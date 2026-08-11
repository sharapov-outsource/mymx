/**
 * Reverse DNS for the mail servers, and the round trip back.
 *
 * A PTR record on its own proves nothing — the owner of an address block can
 * put any name there. What receivers actually check is forward-confirmed
 * reverse DNS: the address has a PTR, and the name that PTR gives resolves back
 * to the same address. Both halves have to be arranged by people who control
 * different things, which is exactly why it is used as a signal that a sender
 * is run by somebody paying attention.
 *
 * Its absence is one of the most common reasons mail from a new server is
 * quietly deferred or filed as junk, and one of the least often mentioned by
 * the receiving side.
 */

import { TYPE } from '@sharapov/dns-wire';
import { flag } from '@sharapov/service-kit';

const strip = value => String(value || '').toLowerCase().replace(/\.$/, '');

/** 203.0.113.5 → 5.113.0.203.in-addr.arpa */
export function reverseName(address) {
  if (address.includes(':')) {
    const groups = expandIpv6(address);
    if (!groups) return null;
    return groups.split('').reverse().join('.') + '.ip6.arpa';
  }
  const octets = address.split('.');
  if (octets.length !== 4) return null;
  return octets.slice().reverse().join('.') + '.in-addr.arpa';
}

/** The full 32 hex digits of an IPv6 address, `::` expanded. */
function expandIpv6(address) {
  const [head, tail] = address.split('::');
  const left = head ? head.split(':') : [];
  const right = tail !== undefined ? (tail ? tail.split(':') : []) : null;
  let groups;
  if (right === null) {
    groups = left;
  } else {
    const missing = 8 - left.length - right.length;
    if (missing < 0) return null;
    groups = [...left, ...Array(missing).fill('0'), ...right];
  }
  if (groups.length !== 8) return null;
  return groups.map(group => group.padStart(4, '0')).join('').toLowerCase();
}

export async function inspectRdns(session, hosts) {
  const flags = [];
  const entries = [];

  for (const host of hosts) {
    for (const { address, family } of host.addresses) {
      const name = reverseName(address);
      if (!name) continue;

      const response = await session.ask({ name, type: 'PTR' });
      const ptr = (response?.message?.answers || [])
        .filter(record => record.type === TYPE.PTR)
        .map(record => strip(record.data.ptr));

      const entry = { host: host.host, address, family, ptr, confirmed: null };

      if (!ptr.length) {
        entry.status = response?.message ? 'missing' : 'unknown';
        entries.push(entry);
        if (entry.status === 'missing') {
          flags.push(flag('rdns-missing', 'high', 'missing', { address, host: host.host }));
        }
        continue;
      }

      /* The confirming half: does the name the PTR gave resolve back here? */
      const forward = await session.ask({ name: ptr[0], type: family === 6 ? 'AAAA' : 'A' });
      const addresses = (forward?.message?.answers || [])
        .filter(record => record.type === (family === 6 ? TYPE.AAAA : TYPE.A))
        .map(record => record.data.address.toLowerCase());

      entry.forward = addresses;
      entry.confirmed = addresses.includes(address.toLowerCase());
      entry.status = entry.confirmed ? 'confirmed' : 'unconfirmed';

      if (!entry.confirmed) {
        flags.push(flag('rdns-not-confirmed', 'medium', 'warning',
          { address, ptr: ptr[0], host: host.host }));
      }
      /* A PTR that matches the MX name is tidy and slightly more convincing to
         a receiver than one that merely resolves back. */
      entry.matchesMx = ptr.includes(strip(host.host));

      entries.push(entry);
    }
  }

  const checked = entries.filter(entry => entry.status !== 'unknown');
  const confirmed = entries.filter(entry => entry.confirmed);

  if (checked.length && !confirmed.length) {
    flags.push(flag('rdns-none-confirmed', 'high', 'failed', {}));
  }

  return {
    entries,
    checked: checked.length,
    confirmed: confirmed.length,
    allConfirmed: checked.length > 0 && confirmed.length === checked.length,
    flags,
  };
}
