/**
 * Just enough SMTP to ask a mail server about itself.
 *
 * Three checks share this: what a server announces (STARTTLS, SIZE, SMTPUTF8),
 * what certificate it presents once the session is encrypted, and whether it
 * will relay for a stranger. All three are read-only — the open-relay probe in
 * particular stops at `RCPT TO` and sends `RSET` and `QUIT`. **No `DATA` command
 * is ever issued, so no message can be sent, even accidentally.**
 *
 * The one thing to know about port 25: most hosting providers block outbound
 * connections to it by default, to keep their address space off blocklists.
 * When that is the case here, this returns `blocked` rather than `closed`, and
 * the report says the check could not be made from our network. Reporting
 * "STARTTLS unavailable" because *we* could not reach the port would be the
 * same class of mistake as scoring a server that was rate-limiting us.
 */

import net from 'node:net';
import tls from 'node:tls';

import { pace } from '@sharapov/service-kit';

const CONNECT_TIMEOUT = Number(process.env.SMTP_CONNECT_TIMEOUT_MS || 8000);
const COMMAND_TIMEOUT = Number(process.env.SMTP_COMMAND_TIMEOUT_MS || 8000);

/** The name we introduce ourselves with. */
const EHLO_NAME = process.env.SMTP_EHLO_NAME || 'mymx.sharapov.biz';

/**
 * A line-oriented reader over a socket, with SMTP's multi-line replies handled:
 * `250-EXTENSION` continues, `250 EXTENSION` is the last one.
 */
function createReader(socket) {
  let buffer = '';
  const waiters = [];

  const feed = chunk => {
    buffer += chunk.toString('binary');
    flush();
  };

  function flush() {
    while (waiters.length) {
      const match = /^(?:\d{3}-[^\r\n]*\r?\n)*\d{3}(?: [^\r\n]*)?\r?\n/.exec(buffer);
      if (!match) return;
      const raw = match[0];
      buffer = buffer.slice(raw.length);
      const lines = raw.split(/\r?\n/).filter(Boolean);
      const waiter = waiters.shift();
      clearTimeout(waiter.timer);
      waiter.resolve({
        code: Number(lines[lines.length - 1].slice(0, 3)),
        lines: lines.map(line => line.slice(4)),
        raw,
      });
    }
  }

  socket.on('data', feed);

  return {
    read() {
      return new Promise((resolve, reject) => {
        const waiter = { resolve, reject };
        waiter.timer = setTimeout(() => {
          const index = waiters.indexOf(waiter);
          if (index >= 0) waiters.splice(index, 1);
          reject(Object.assign(new Error('smtp-timeout'), { code: 'smtp-timeout' }));
        }, COMMAND_TIMEOUT);
        waiters.push(waiter);
        flush();
      });
    },
    /** Re-attach after the socket is replaced by its TLS wrapper. */
    attach(next) {
      socket.off('data', feed);
      buffer = '';
      socket = next;
      socket.on('data', feed);
    },
  };
}

function connect(host, port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(Object.assign(new Error('smtp-timeout'), { code: 'smtp-timeout' }));
    }, CONNECT_TIMEOUT);

    socket.once('connect', () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once('error', err => {
      clearTimeout(timer);
      // ECONNREFUSED means something answered "no"; a timeout on 25 with no
      // response at all is what an outbound block looks like from in here.
      reject(Object.assign(new Error(err.code || 'smtp-network'), {
        code: err.code === 'ECONNREFUSED' ? 'smtp-refused' : 'smtp-network',
        detail: err.message,
      }));
    });
  });
}

/** Everything after `250-` on the EHLO reply, as a keyword → argument map. */
function parseExtensions(lines) {
  const extensions = {};
  for (const line of lines.slice(1)) {
    const [keyword, ...rest] = line.trim().split(/\s+/);
    if (!keyword) continue;
    extensions[keyword.toUpperCase()] = rest.join(' ') || true;
  }
  return extensions;
}

/**
 * Opens a session, says EHLO, optionally upgrades with STARTTLS, and hands the
 * result back. The socket is closed before returning unless `keep` is set.
 *
 * @param {object} options
 * @param {string} options.host       the MX host name, used for SNI and EHLO
 * @param {string} options.address    the address to connect to
 * @param {number} options.port
 * @param {boolean} options.implicitTls  port 465 speaks TLS from the first byte
 * @param {boolean} options.startTls     upgrade in-band on 25 and 587
 */
export async function probeSmtp({
  host, address, port, implicitTls = false, startTls = true, probeRelay = false,
}) {
  await pace('smtp');

  const result = {
    host,
    address,
    port,
    reachable: false,
    banner: null,
    ehlo: null,
    extensions: {},
    starttls: { offered: false, established: false },
    tls: null,
    certificate: null,
    relay: null,
    error: null,
  };

  let socket;
  try {
    socket = implicitTls
      ? await connectTls({ host, address, port })
      : await connect(address, port);
  } catch (err) {
    result.error = err.code || 'smtp-network';
    return result;
  }

  const reader = createReader(socket);
  const say = async line => {
    socket.write(line + '\r\n');
    return reader.read();
  };

  try {
    socket.setNoDelay(true);
    const greeting = await reader.read();
    result.reachable = true;
    result.banner = greeting.lines[0] || null;
    result.bannerCode = greeting.code;

    /* A banner that names the software and its version is a small gift to
       somebody scanning for a known bug in it. */
    result.bannerRevealsSoftware = /\b(postfix|exim|sendmail|microsoft|zimbra|opensmtpd)\b/i
      .test(result.banner || '') && /\d+\.\d+/.test(result.banner || '');

    const ehlo = await say(`EHLO ${EHLO_NAME}`);
    result.ehlo = ehlo.code;
    result.extensions = parseExtensions(ehlo.lines);
    result.starttls.offered = 'STARTTLS' in result.extensions;

    if (implicitTls) {
      result.starttls.established = true;
      readTlsDetails(socket, result);
    } else if (startTls && result.starttls.offered) {
      const ready = await say('STARTTLS');
      if (ready.code === 220) {
        const secure = await upgrade(socket, host);
        reader.attach(secure);
        socket = secure;
        result.starttls.established = true;
        readTlsDetails(secure, result);
        // After the upgrade the session restarts: everything announced before
        // is discarded, and a server may offer more once it trusts the channel.
        const second = await say(`EHLO ${EHLO_NAME}`);
        result.extensionsAfterTls = parseExtensions(second.lines);
      } else {
        result.starttls.error = `STARTTLS refused with ${ready.code}`;
      }
    }

    if (probeRelay) {
      result.relay = await checkRelay(say);
    }

    try { await say('QUIT'); } catch { /* the server may just close */ }
  } catch (err) {
    result.error = err.code || 'smtp-error';
  } finally {
    socket.destroy();
  }

  return result;
}

function connectTls({ host, address, port }) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: address,
      port,
      servername: net.isIP(host) ? undefined : host,
      // The certificate is the thing being examined, so a bad one must not
      // abort the connection — it is read and judged afterwards.
      rejectUnauthorized: false,
    });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(Object.assign(new Error('smtp-timeout'), { code: 'smtp-timeout' }));
    }, CONNECT_TIMEOUT);
    socket.once('secureConnect', () => { clearTimeout(timer); resolve(socket); });
    socket.once('error', err => {
      clearTimeout(timer);
      reject(Object.assign(new Error(err.code || 'tls-error'), { code: 'tls-failed', detail: err.message }));
    });
  });
}

/** Wraps an established plaintext socket, which is what STARTTLS is. */
function upgrade(socket, host) {
  return new Promise((resolve, reject) => {
    const secure = tls.connect({
      socket,
      servername: net.isIP(host) ? undefined : host,
      rejectUnauthorized: false,
    });
    const timer = setTimeout(() => reject(Object.assign(new Error('tls-timeout'), { code: 'tls-timeout' })), CONNECT_TIMEOUT);
    secure.once('secureConnect', () => { clearTimeout(timer); resolve(secure); });
    secure.once('error', err => {
      clearTimeout(timer);
      reject(Object.assign(new Error(err.code || 'tls-error'), { code: 'tls-failed', detail: err.message }));
    });
  });
}

/**
 * What the encrypted session turned out to be, and the certificate on it.
 *
 * Node's X509Certificate hands over the SPKI in DER, which is exactly what a
 * DANE selector of 1 hashes — so no ASN.1 parsing is needed here at all.
 */
function readTlsDetails(socket, result) {
  const cipher = socket.getCipher?.() || {};
  result.tls = {
    protocol: socket.getProtocol?.() || null,
    cipher: cipher.standardName || cipher.name || null,
    authorized: socket.authorized,
    authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
  };

  const certificate = socket.getPeerX509Certificate?.();
  if (!certificate) return;

  let publicKeyDer = null;
  try {
    publicKeyDer = certificate.publicKey.export({ type: 'spki', format: 'der' });
  } catch { /* an unusual key type; the full-certificate selector still works */ }

  result.certificate = {
    subject: certificate.subject,
    issuer: certificate.issuer,
    subjectAltName: certificate.subjectAltName || null,
    validFrom: certificate.validFrom,
    validTo: certificate.validTo,
    fingerprint256: certificate.fingerprint256,
    // Kept as buffers for the DANE comparison, stripped before the report.
    raw: certificate.raw,
    spki: publicKeyDer,
  };
}

/**
 * The open-relay probe.
 *
 * A relay test that sends a message is not a test, it is spam. This stops at
 * `RCPT TO` — the point at which the server has already decided whether it
 * would accept mail from a stranger for a stranger — and then resets. There is
 * no `DATA`, so nothing can be delivered.
 */
async function checkRelay(say) {
  const from = `probe@${EHLO_NAME}`;
  const to = 'relay-test@example.com';

  const mailFrom = await say(`MAIL FROM:<${from}>`);
  if (mailFrom.code >= 400) {
    return { open: false, stoppedAt: 'MAIL FROM', code: mailFrom.code, message: mailFrom.lines[0] };
  }

  const rcptTo = await say(`RCPT TO:<${to}>`);
  await say('RSET');

  return {
    open: rcptTo.code >= 200 && rcptTo.code < 300,
    stoppedAt: 'RCPT TO',
    code: rcptTo.code,
    message: rcptTo.lines[0],
  };
}

/**
 * Is outbound port 25 usable from here at all?
 *
 * Answered once per process against a server that is certainly up, and cached,
 * because the answer is a property of our network rather than of any domain
 * being checked. A refusal is a different thing from a timeout: providers block
 * 25 by dropping packets, so a timeout is the signature of a block.
 */
let port25 = null;

export async function outboundPort25({ probe = 'gmail-smtp-in.l.google.com' } = {}) {
  if (port25) return port25;
  if (process.env.SMTP_PORT_25 === 'blocked') {
    port25 = { usable: false, reason: 'configured-blocked' };
    return port25;
  }
  if (process.env.SMTP_PORT_25 === 'open') {
    port25 = { usable: true, reason: 'configured-open' };
    return port25;
  }

  try {
    const socket = await connect(probe, 25);
    socket.destroy();
    port25 = { usable: true, reason: 'reachable' };
  } catch (err) {
    port25 = {
      usable: false,
      reason: err.code === 'smtp-refused' ? 'refused' : 'blocked',
      detail: err.detail,
    };
  }
  return port25;
}

/** Tests need to forget what the network looked like last time. */
export function resetPort25Cache() {
  port25 = null;
}
