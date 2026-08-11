/**
 * MTA-STS and TLS-RPT.
 *
 * SMTP's transport security has an awkward hole in it: STARTTLS is opportunistic,
 * so a sender that is stripped of the STARTTLS offer simply carries on in the
 * clear. MTA-STS closes it by publishing, over HTTPS, a policy that says "this
 * domain's mail servers are these, and they always speak TLS" — and HTTPS is
 * what makes the policy hard to strip, because tampering with it means
 * defeating the web PKI rather than editing one line of a plaintext session.
 *
 * The policy has two halves that must agree: a TXT record carrying an id, and
 * the document itself at a well-known URL. The id is what tells a sender its
 * cached copy is stale; a policy edited without bumping the id will not be
 * picked up until the cache expires, which `max_age` may put weeks away.
 *
 * The check that earns its keep is comparing the `mx:` patterns in the policy
 * with the domain's actual MX set. A host that is in the DNS and not in the
 * policy will have its mail refused by every sender enforcing the policy.
 */

import { TYPE } from '@sharapov/dns-wire';
import { flag, isPrivateAddress, allowPrivate } from '@sharapov/service-kit';

import { parseTagList } from './dkim.js';

const strip = value => String(value || '').toLowerCase().replace(/\.$/, '');
const POLICY_TIMEOUT = Number(process.env.MTASTS_TIMEOUT_MS || 8000);
const MAX_POLICY_BYTES = 64 * 1024;

/** `mx: *.example.com` matches one label, and only the leftmost one. */
export function matchesPattern(pattern, host) {
  const clean = strip(pattern);
  const target = strip(host);
  if (!clean.startsWith('*.')) return clean === target;
  const suffix = clean.slice(1);                       // ".example.com"
  if (!target.endsWith(suffix)) return false;
  const label = target.slice(0, target.length - suffix.length);
  return label.length > 0 && !label.includes('.');
}

/** The policy document: `key: value` per line, `mx` repeatable. */
export function parsePolicy(text) {
  const policy = { mx: [] };
  for (const line of String(text).split(/\r?\n/)) {
    const match = /^\s*([A-Za-z_]+)\s*:\s*(.+?)\s*$/.exec(line);
    if (!match) continue;
    const key = match[1].toLowerCase();
    if (key === 'mx') policy.mx.push(match[2].toLowerCase());
    else policy[key] = match[2];
  }
  return policy;
}

export async function inspectMtaSts(session, domain, mxHosts = []) {
  const flags = [];
  const name = `_mta-sts.${domain}`;

  const response = await session.ask({ name, type: 'TXT' });
  const records = (response?.message?.answers || [])
    .filter(record => record.type === TYPE.TXT)
    .map(record => record.data.text)
    .filter(text => /^v\s*=\s*STSv1/i.test(text.trim()));

  if (!records.length) {
    flags.push(flag('mtasts-missing', 'medium', 'missing', {}));
    return { present: false, flags };
  }
  if (records.length > 1) {
    flags.push(flag('mtasts-multiple-records', 'medium', 'failed', { count: records.length }));
  }

  const tags = parseTagList(records[0]);
  const result = {
    present: true,
    record: records[0],
    id: tags.id || null,
    policyUrl: `https://mta-sts.${domain}/.well-known/mta-sts.txt`,
    policy: null,
    fetched: false,
  };

  if (!tags.id) {
    flags.push(flag('mtasts-no-id', 'medium', 'failed', {}));
  }

  /* The policy host is derived from the domain being checked, so before
     fetching it, make sure it does not resolve into private space — otherwise
     this service becomes a way to make requests inside its own network. */
  const policyHost = `mta-sts.${domain}`;
  const addresses = await session.ask({ name: policyHost, type: 'A' });
  const address = (addresses?.message?.answers || [])
    .find(record => record.type === TYPE.A)?.data.address;

  if (!address) {
    flags.push(flag('mtasts-policy-host-missing', 'high', 'failed', { host: policyHost }));
    return { ...result, flags };
  }
  if (!allowPrivate() && isPrivateAddress(address)) {
    flags.push(flag('mtasts-policy-host-private', 'high', 'failed', { host: policyHost }));
    return { ...result, flags };
  }

  let text = null;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), POLICY_TIMEOUT);
    const fetched = await fetch(result.policyUrl, {
      signal: controller.signal,
      redirect: 'error',                               // RFC 8461 §3.3: no redirects
      headers: { 'user-agent': 'mymx.sharapov.biz (+https://mymx.sharapov.biz)' },
    });
    clearTimeout(timer);

    result.status = fetched.status;
    result.contentType = fetched.headers.get('content-type');

    if (!fetched.ok) {
      flags.push(flag('mtasts-policy-unreachable', 'high', 'failed', { status: fetched.status }));
      return { ...result, flags };
    }
    if (!/text\/plain/i.test(result.contentType || '')) {
      flags.push(flag('mtasts-policy-wrong-content-type', 'low', 'warning',
        { contentType: result.contentType }));
    }
    text = (await fetched.text()).slice(0, MAX_POLICY_BYTES);
    result.fetched = true;
  } catch (err) {
    /* A failure here may be the policy host's certificate — which is itself the
       finding, since the whole mechanism rests on that certificate being
       valid — or our own network. Both are reported, neither is guessed at. */
    flags.push(flag('mtasts-policy-unreachable', 'high', 'failed',
      { reason: err.name === 'AbortError' ? 'timeout' : err.message }));
    return { ...result, flags };
  }

  const policy = parsePolicy(text);
  result.policy = policy;

  if (!/^STSv1$/i.test(policy.version || '')) {
    flags.push(flag('mtasts-policy-bad-version', 'high', 'failed', { version: policy.version }));
  }

  const mode = String(policy.mode || '').toLowerCase();
  result.mode = mode;
  if (!['enforce', 'testing', 'none'].includes(mode)) {
    flags.push(flag('mtasts-policy-bad-mode', 'high', 'failed', { mode: policy.mode }));
  } else if (mode === 'testing') {
    // Testing mode reports failures and delivers anyway: a staging post, not a
    // destination.
    flags.push(flag('mtasts-mode-testing', 'medium', 'warning', {}));
  } else if (mode === 'none') {
    flags.push(flag('mtasts-mode-none', 'medium', 'warning', {}));
  }

  const maxAge = Number(policy.max_age);
  result.maxAge = Number.isFinite(maxAge) ? maxAge : null;
  if (!Number.isFinite(maxAge)) {
    flags.push(flag('mtasts-no-max-age', 'high', 'failed', {}));
  } else if (maxAge < 86400) {
    flags.push(flag('mtasts-max-age-short', 'low', 'warning', { maxAge }));
  }

  /* The comparison that matters. */
  if (mxHosts.length && policy.mx.length) {
    const unlisted = mxHosts
      .map(entry => entry.host)
      .filter(host => !policy.mx.some(pattern => matchesPattern(pattern, host)));
    const unused = policy.mx
      .filter(pattern => !mxHosts.some(entry => matchesPattern(pattern, entry.host)));

    result.mxCoverage = { unlisted, unused, patterns: policy.mx };

    if (unlisted.length) {
      flags.push(flag('mtasts-mx-not-in-policy', 'critical', 'failed', { hosts: unlisted }));
    }
    if (unused.length) {
      flags.push(flag('mtasts-policy-lists-unknown-mx', 'low', 'warning', { patterns: unused }));
    }
  } else if (!policy.mx.length) {
    flags.push(flag('mtasts-policy-no-mx', 'high', 'failed', {}));
  }

  return { ...result, flags };
}

/**
 * TLS-RPT: where a sender should send a report when a TLS connection to this
 * domain fails. Cheap to publish and the only way to learn that anything is
 * going wrong at all — without it, a downgrade or an expired certificate on an
 * MX is invisible from the receiving end.
 */
export async function inspectTlsRpt(session, domain) {
  const flags = [];
  const response = await session.ask({ name: `_smtp._tls.${domain}`, type: 'TXT' });
  const records = (response?.message?.answers || [])
    .filter(record => record.type === TYPE.TXT)
    .map(record => record.data.text)
    .filter(text => /^v\s*=\s*TLSRPTv1/i.test(text.trim()));

  if (!records.length) {
    flags.push(flag('tlsrpt-missing', 'low', 'missing', {}));
    return { present: false, flags };
  }

  const tags = parseTagList(records[0]);
  const rua = (tags.rua || '').split(',').map(entry => entry.trim()).filter(Boolean);
  if (!rua.length) flags.push(flag('tlsrpt-no-rua', 'medium', 'failed', {}));

  return { present: true, record: records[0], rua, flags };
}
