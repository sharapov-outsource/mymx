/**
 * Where mail for this domain goes.
 *
 * The MX set is simple enough. What is worth checking around it:
 *
 *   · a null MX — a single `.` at priority 0 — which is RFC 7505 for "this
 *     domain sends no mail and accepts none". Deliberate and useful, and
 *     completely different from having no MX at all, which means senders fall
 *     back to the A record;
 *   · an MX pointing at a CNAME, which RFC 2181 §10.3 forbids and some senders
 *     simply refuse;
 *   · MX hosts that do not resolve, which cost every sender a delay before it
 *     moves on to the next priority.
 */

import { TYPE } from '@sharapov/dns-wire';
import { flag } from '@sharapov/service-kit';

const strip = value => String(value || '').toLowerCase().replace(/\.$/, '');

export async function inspectMx(session, domain) {
  const flags = [];
  const response = await session.ask({ name: domain, type: 'MX', dnssec: true });

  if (!response?.message) {
    return { hosts: [], nullMx: false, incomplete: ['mx-lookup-failed'], flags };
  }

  const records = response.message.answers
    .filter(record => record.type === TYPE.MX)
    .map(record => ({ preference: record.data.preference, exchange: strip(record.data.exchange) }))
    .sort((a, b) => a.preference - b.preference || a.exchange.localeCompare(b.exchange));

  /* RFC 7505: exactly one MX, priority 0, target the root. */
  const nullMx = records.length === 1 && records[0].exchange === '';
  if (nullMx) {
    return {
      hosts: [],
      nullMx: true,
      records,
      flags: [flag('null-mx', 'info', 'info', {})],
    };
  }

  if (!records.length) {
    // Senders fall back to the A record (RFC 5321 §5.1), so mail may still be
    // delivered — to whatever is answering on port 25 at the web server.
    const a = await session.ask({ name: domain, type: 'A' });
    const hasAddress = (a?.message?.answers || []).some(record => record.type === TYPE.A);
    flags.push(flag(hasAddress ? 'no-mx-falls-back-to-a' : 'no-mx', hasAddress ? 'medium' : 'high',
      hasAddress ? 'warning' : 'missing', {}));
    return { hosts: [], nullMx: false, records: [], flags };
  }

  /* Deduplicated, because a set that names the same host twice at different
     priorities is a configuration error rather than redundancy. */
  const seen = new Set();
  const duplicates = [];
  for (const record of records) {
    if (seen.has(record.exchange)) duplicates.push(record.exchange);
    seen.add(record.exchange);
  }
  if (duplicates.length) {
    flags.push(flag('duplicate-mx-host', 'low', 'warning', { hosts: [...new Set(duplicates)] }));
  }

  const hosts = await Promise.all([...seen].map(async name => {
    const preference = records.find(record => record.exchange === name).preference;
    const [v4, v6, cname] = await Promise.all([
      session.ask({ name, type: 'A' }),
      session.ask({ name, type: 'AAAA' }),
      session.ask({ name, type: 'CNAME' }),
    ]);

    const addresses = [
      ...(v4?.message?.answers || []).filter(record => record.type === TYPE.A)
        .map(record => ({ address: record.data.address, family: 4 })),
      ...(v6?.message?.answers || []).filter(record => record.type === TYPE.AAAA)
        .map(record => ({ address: record.data.address, family: 6 })),
    ];

    const alias = (cname?.message?.answers || []).some(record => record.type === TYPE.CNAME);

    return { host: name, preference, addresses, alias, ipv6: addresses.some(a => a.family === 6) };
  }));

  hosts.sort((a, b) => a.preference - b.preference || a.host.localeCompare(b.host));

  for (const host of hosts) {
    if (!host.addresses.length) {
      flags.push(flag('mx-does-not-resolve', 'high', 'failed', { host: host.host }));
    }
    if (host.alias) {
      flags.push(flag('mx-points-at-cname', 'medium', 'warning', { host: host.host }));
    }
  }

  if (hosts.length === 1) {
    flags.push(flag('single-mx', 'low', 'warning', {}));
  }
  if (hosts.length && !hosts.some(host => host.ipv6)) {
    flags.push(flag('no-ipv6-mx', 'low', 'warning', {}));
  }

  return { hosts, nullMx: false, records, flags };
}
