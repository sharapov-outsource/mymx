/**
 * What each mail server offers, and on which ports.
 *
 * Port 25 is the one that matters — it is where mail between servers is
 * delivered, and the only place STARTTLS, DANE and relaying can be observed as
 * a sender sees them. It is also the one most hosting providers block outbound
 * by default, so it may be unreachable from here for reasons that have nothing
 * to do with the domain being checked.
 *
 * That case is handled explicitly and loudly. When 25 is blocked from our
 * network, the report says so, the affected checks are marked as not made, and
 * the grade is withheld rather than computed from what we happened to be able
 * to reach. Silently reporting "no STARTTLS" because *we* could not connect
 * would be the same mistake as scoring a server that was rate-limiting the
 * scanner — and that one has been made before, at a bank's expense.
 *
 * 465 (implicit TLS) and 587 (submission) are checked too. They are for clients
 * rather than for server-to-server delivery, so what they say about the
 * domain's transport security is suggestive rather than conclusive.
 */

import { flag } from '@sharapov/service-kit';

import { probeSmtp, outboundPort25 } from './smtp.js';

/** 25 first: everything else is a consolation prize. */
const PORTS = [
  { port: 25, role: 'relay', implicitTls: false },
  { port: 465, role: 'submission-implicit', implicitTls: true },
  { port: 587, role: 'submission', implicitTls: false },
];

const enabled = name => process.env[name] !== 'false';

export async function inspectStartTls(session, hosts, { checkRelay = true } = {}) {
  const flags = [];
  const incomplete = [];

  if (!hosts.length) {
    return { sessions: [], port25: null, flags, incomplete };
  }

  const port25 = await outboundPort25();
  if (!port25.usable) {
    /* Named as ours, not theirs. */
    flags.push(flag('port-25-blocked-from-here', 'info', 'unknown', { reason: port25.reason }));
    incomplete.push('port-25-unreachable-from-this-network');
  }

  /* Only the highest-priority hosts are probed: a large provider may list eight
     MX records that all lead to the same infrastructure, and opening a
     connection to each of them is noise for them and time for the visitor. */
  const probeLimit = Number(process.env.SMTP_MAX_HOSTS || 3);
  const chosen = hosts.filter(host => host.addresses.length).slice(0, probeLimit);
  if (chosen.length < hosts.filter(host => host.addresses.length).length) {
    incomplete.push('not-every-mx-was-probed');
  }

  const sessions = [];
  for (const host of chosen) {
    const address = host.addresses.find(entry => entry.family === 4)?.address
      || host.addresses[0].address;

    for (const spec of PORTS) {
      if (spec.port === 25 && !port25.usable) {
        sessions.push({
          host: host.host, address, port: 25, role: spec.role,
          skipped: 'port-blocked-from-here',
        });
        continue;
      }
      if (!enabled(`SMTP_CHECK_${spec.port}`)) continue;

      const result = await probeSmtp({
        host: host.host,
        address,
        port: spec.port,
        implicitTls: spec.implicitTls,
        // The relay probe belongs on 25 only: 465 and 587 are for authenticated
        // clients, where a refusal proves nothing about relaying.
        probeRelay: checkRelay && spec.port === 25,
      });
      sessions.push({ ...result, role: spec.role });
    }
  }

  /* ---------------- findings ---------------- */
  const relaySessions = sessions.filter(entry => entry.port === 25 && !entry.skipped);
  const reachable = relaySessions.filter(entry => entry.reachable);

  if (port25.usable && relaySessions.length && !reachable.length) {
    flags.push(flag('mx-not-reachable-on-25', 'critical', 'failed', {}));
  }

  for (const entry of reachable) {
    if (!entry.starttls.offered) {
      // Mail to this server travels in the clear, every time.
      flags.push(flag('no-starttls', 'critical', 'failed', { host: entry.host }));
    } else if (!entry.starttls.established) {
      flags.push(flag('starttls-fails', 'critical', 'failed',
        { host: entry.host, detail: entry.starttls.error }));
    } else {
      if (entry.tls?.protocol && /TLSv1(\.[01])?$/.test(entry.tls.protocol)) {
        flags.push(flag('starttls-legacy-protocol', 'high', 'weak',
          { host: entry.host, protocol: entry.tls.protocol }));
      }
      if (entry.tls && entry.tls.authorized === false) {
        /* Worth stating, and worth stating carefully: a self-signed certificate
           on port 25 is normal and does not stop delivery, because opportunistic
           TLS does not verify. It stops mattering the moment MTA-STS or DANE is
           in play, and then it stops delivery completely. */
        flags.push(flag('mx-certificate-not-trusted', 'medium', 'warning', {
          host: entry.host, reason: entry.tls.authorizationError,
        }));
      }
    }

    if (entry.bannerRevealsSoftware) {
      flags.push(flag('banner-reveals-version', 'low', 'warning', { host: entry.host }));
    }
    if (entry.relay?.open) {
      // The one finding here that is unambiguously somebody else's emergency.
      flags.push(flag('open-relay', 'critical', 'failed', { host: entry.host }));
    }
    if (entry.extensions && !('SIZE' in entry.extensions)) {
      flags.push(flag('no-size-extension', 'info', 'info', { host: entry.host }));
    }
  }

  const submission = sessions.filter(entry => entry.port !== 25 && entry.reachable);
  for (const entry of submission) {
    if (entry.port === 587 && entry.reachable && !entry.starttls.offered) {
      flags.push(flag('submission-without-starttls', 'high', 'failed', { host: entry.host }));
    }
  }

  return {
    /* Two views of the same thing. `sessions` is what goes into the report;
       `live` still carries the certificate buffers, because DANE has to hash
       them and a hex string in a JSON document is no use for that. The scan
       hands `live` to the DANE check and never puts it in the report. */
    sessions: sessions.map(forReport),
    live: sessions,
    port25,
    tlsEverywhere: reachable.length > 0 && reachable.every(entry => entry.starttls.established),
    flags,
    incomplete,
  };
}

/** The same session without the DER buffers, which nobody wants to read. */
function forReport(session) {
  if (!session.certificate) return session;
  const { raw, spki, ...rest } = session.certificate;
  return { ...session, certificate: rest };
}

export { PORTS };
