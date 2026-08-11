/**
 * DANE: the certificate the DNS says to expect, checked against the one on the
 * wire.
 *
 * A TLSA record at `_25._tcp.<mx>` pins what an MX must present. It only means
 * anything when the zone is signed — an unsigned TLSA record can be replaced by
 * whoever could replace the MX record, so it protects nothing. That is the
 * first thing checked here, and a TLSA record in an unsigned zone is reported
 * as the false comfort it is.
 *
 * The comparison itself is arithmetic:
 *
 *   selector 0 = the whole certificate, 1 = the public key (SPKI)
 *   matching  0 = the bytes, 1 = SHA-256 of them, 2 = SHA-512
 *
 * Node's X509Certificate hands over both the DER certificate and the SPKI, so
 * no ASN.1 parsing is needed — which is the only reason this is thirty lines
 * rather than three hundred.
 */

import { createHash } from 'node:crypto';

import { TYPE } from '@sharapov/dns-wire';
import { flag } from '@sharapov/service-kit';

const USAGE = {
  0: 'PKIX-TA', 1: 'PKIX-EE', 2: 'DANE-TA', 3: 'DANE-EE',
};

/** The bytes a TLSA record claims to describe, hashed the way it says. */
function association(certificate, selector, matchingType) {
  const source = selector === 1 ? certificate.spki : certificate.raw;
  if (!source) return null;
  if (matchingType === 0) return Buffer.from(source).toString('hex');
  if (matchingType === 1) return createHash('sha256').update(source).digest('hex');
  if (matchingType === 2) return createHash('sha512').update(source).digest('hex');
  return null;
}

export async function inspectDane(session, hosts, { zoneSigned = null, sessions = [] } = {}) {
  const flags = [];
  const perHost = [];

  for (const entry of hosts) {
    const name = `_25._tcp.${entry.host}`;
    const response = await session.ask({ name, type: 'TLSA', dnssec: true });

    const records = (response?.message?.answers || [])
      .filter(record => record.type === TYPE.TLSA)
      .map(record => ({
        usage: record.data.usage,
        usageName: USAGE[record.data.usage] || `usage${record.data.usage}`,
        selector: record.data.selector,
        matchingType: record.data.matchingType,
        certificateAssociation: record.data.certificateAssociation,
      }));

    /* The DO bit was set, so a signed zone returns the signature alongside.
       Its absence here means the records are not protected. */
    const signed = zoneSigned ?? (response?.message?.answers || [])
      .some(record => record.type === TYPE.RRSIG && record.data.typeCovered === TYPE.TLSA);

    if (!records.length) {
      perHost.push({ host: entry.host, present: false, signed, records: [] });
      continue;
    }

    const live = sessions.find(item => item.host === entry.host && item.certificate);
    const matches = [];
    let verified = null;

    if (live) {
      verified = false;
      for (const record of records) {
        const computed = association(live.certificate, record.selector, record.matchingType);
        const matched = Boolean(computed) &&
          computed.toLowerCase() === String(record.certificateAssociation).toLowerCase();
        matches.push({ ...record, matched, computed: computed ? computed.slice(0, 16) + '…' : null });
        if (matched) verified = true;
      }
    }

    perHost.push({
      host: entry.host,
      present: true,
      signed,
      verified,
      records: matches.length ? matches : records,
      // Stated so a reader does not read "not verified" as "does not match".
      comparedAgainstLiveCertificate: Boolean(live),
    });

    if (!signed) {
      flags.push(flag('dane-without-dnssec', 'high', 'failed', { host: entry.host }));
    }
    if (live && verified === false) {
      flags.push(flag('dane-mismatch', 'critical', 'failed', { host: entry.host }));
    }
    for (const record of records) {
      if (record.usage === 0 || record.usage === 1) {
        // Usages 0 and 1 require the certificate to validate through the public
        // PKI as well, and RFC 7672 §3.1 forbids them for SMTP outright.
        flags.push(flag('dane-pkix-usage', 'medium', 'warning',
          { host: entry.host, usage: record.usageName }));
      }
      if (record.matchingType === 0) {
        flags.push(flag('dane-full-certificate', 'low', 'warning', { host: entry.host }));
      }
    }
  }

  const withRecords = perHost.filter(entry => entry.present);
  if (hosts.length && !withRecords.length) {
    flags.push(flag('dane-missing', 'low', 'missing', {}));
  } else if (withRecords.length && withRecords.length < hosts.length) {
    // Senders pick an MX by priority, so a set where only some hosts are
    // protected is protected only some of the time.
    flags.push(flag('dane-partial', 'medium', 'warning', {
      covered: withRecords.length, total: hosts.length,
    }));
  }

  return {
    hosts: perHost,
    present: withRecords.length > 0,
    covered: withRecords.length,
    total: hosts.length,
    flags,
  };
}
