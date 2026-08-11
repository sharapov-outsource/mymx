/**
 * DMARC: the policy, and the one thing about it nobody checks.
 *
 * The policy itself is easy to read. `p=none` is the interesting value — it
 * asks receivers to enforce nothing and merely send reports, which is the right
 * place to start and the wrong place to stay. A great many domains have been
 * sitting at `p=none` since the day it was added, under the impression that
 * having a DMARC record is the same as being protected. It is not: with
 * `p=none`, a message that fails both SPF and DKIM alignment is delivered
 * exactly as before.
 *
 * The unchecked thing is external reporting. If `rua` points at an address
 * outside the domain — which it does whenever a third-party service handles
 * reports — that other domain must publish
 *
 *     <your-domain>._report._dmarc.<their-domain>   TXT   "v=DMARC1"
 *
 * to say it agrees to receive them (RFC 7489 §7.1). Without it, conforming
 * receivers send nothing. The record looks perfect, the dashboard stays empty,
 * and it is nearly always put down to "reports take a while to arrive".
 */

import { TYPE, ancestors } from '@sharapov/dns-wire';
import { flag } from '@sharapov/service-kit';

import { parseTagList } from './dkim.js';

const strip = value => String(value || '').toLowerCase().replace(/\.$/, '');

const POLICIES = ['none', 'quarantine', 'reject'];

/** `mailto:reports@example.com!10m` → the address and the size limit. */
function parseUri(raw) {
  const [uri, limit] = String(raw).trim().split('!');
  const match = /^mailto:(.+)$/i.exec(uri.trim());
  if (!match) return { uri: uri.trim(), scheme: 'other', address: null, domain: null, limit };
  const address = match[1].trim();
  return {
    uri: uri.trim(),
    scheme: 'mailto',
    address,
    domain: strip(address.split('@')[1] || ''),
    limit: limit || null,
  };
}

/** Is `candidate` the domain itself or one of its subdomains? */
function sameOrganisation(candidate, domain) {
  return candidate === domain || candidate.endsWith(`.${domain}`) || domain.endsWith(`.${candidate}`);
}

export async function inspectDmarc(session, domain) {
  const flags = [];
  const name = `_dmarc.${domain}`;

  const response = await session.ask({ name, type: 'TXT', dnssec: true });
  if (!response?.message) {
    return { present: null, incomplete: ['dmarc-lookup-failed'], flags };
  }

  const records = (response.message.answers || [])
    .filter(record => record.type === TYPE.TXT)
    .map(record => record.data.text)
    .filter(text => /^v\s*=\s*DMARC1\s*;/i.test(text.trim()));

  if (!records.length) {
    /* A subdomain inherits the organisational domain's policy, so before
       calling it missing, look up the tree. */
    const inherited = await findInherited(session, domain);
    if (inherited) {
      flags.push(flag('dmarc-inherited', 'info', 'info', { from: inherited.domain }));
      return { ...inherited.result, present: true, inheritedFrom: inherited.domain, flags: [...flags, ...inherited.result.flags] };
    }
    flags.push(flag('dmarc-missing', 'high', 'missing', {}));
    return { present: false, flags };
  }

  if (records.length > 1) {
    // RFC 7489 §6.6.3: more than one record and the policy is discarded.
    flags.push(flag('dmarc-multiple-records', 'critical', 'failed', { count: records.length }));
  }

  const record = records[0];
  const tags = parseTagList(record);
  const policy = (tags.p || '').toLowerCase();
  const subdomainPolicy = (tags.sp || '').toLowerCase() || null;
  const percent = tags.pct === undefined ? 100 : Number(tags.pct);

  const rua = (tags.rua || '').split(',').map(entry => entry.trim()).filter(Boolean).map(parseUri);
  const ruf = (tags.ruf || '').split(',').map(entry => entry.trim()).filter(Boolean).map(parseUri);

  if (!policy) {
    flags.push(flag('dmarc-no-policy', 'critical', 'failed', {}));
  } else if (!POLICIES.includes(policy)) {
    flags.push(flag('dmarc-invalid-policy', 'high', 'failed', { policy }));
  } else if (policy === 'none') {
    flags.push(flag('dmarc-policy-none', 'medium', 'warning', {}));
  } else if (policy === 'quarantine') {
    flags.push(flag('dmarc-policy-quarantine', 'info', 'info', {}));
  }

  if (subdomainPolicy === 'none' && policy !== 'none') {
    // A strict policy on the domain and none on its subdomains leaves every
    // unused subdomain available for spoofing.
    flags.push(flag('dmarc-subdomain-policy-none', 'medium', 'warning', {}));
  }

  if (Number.isFinite(percent) && percent < 100) {
    flags.push(flag('dmarc-partial-percentage', 'medium', 'warning', { percent }));
  }

  if (!rua.length) {
    flags.push(flag('dmarc-no-reporting', 'medium', 'warning', {}));
  }

  /* ---------------- external reporting authorisation ---------------- */
  const external = [...rua, ...ruf]
    .filter(entry => entry.domain && !sameOrganisation(entry.domain, domain));

  const authorisations = await Promise.all([...new Set(external.map(entry => entry.domain))]
    .map(async target => {
      const authName = `${domain}._report._dmarc.${target}`;
      const authResponse = await session.ask({ name: authName, type: 'TXT' });
      const authorised = (authResponse?.message?.answers || [])
        .filter(record => record.type === TYPE.TXT)
        .some(record => /v\s*=\s*DMARC1/i.test(record.data.text));
      return {
        domain: target,
        record: authName,
        authorised,
        checked: Boolean(authResponse?.message),
      };
    }));

  for (const entry of authorisations) {
    if (!entry.checked) continue;
    if (!entry.authorised) {
      flags.push(flag('dmarc-external-reporting-unauthorised', 'high', 'failed', {
        target: entry.domain, record: entry.record,
      }));
    }
  }

  return {
    present: true,
    record,
    policy,
    subdomainPolicy,
    percent,
    alignment: {
      dkim: (tags.adkim || 'r').toLowerCase(),
      spf: (tags.aspf || 'r').toLowerCase(),
    },
    failureOptions: tags.fo || '0',
    reportInterval: tags.ri ? Number(tags.ri) : 86400,
    rua,
    ruf,
    externalAuthorisation: authorisations,
    enforcing: policy === 'quarantine' || policy === 'reject',
    flags,
  };
}

/** The organisational domain's policy, which a subdomain inherits. */
async function findInherited(session, domain) {
  for (const parent of ancestors(domain).slice(1)) {
    if (!parent || parent.split('.').length < 2) break;
    const response = await session.ask({ name: `_dmarc.${parent}`, type: 'TXT' });
    const records = (response?.message?.answers || [])
      .filter(record => record.type === TYPE.TXT)
      .map(record => record.data.text)
      .filter(text => /^v\s*=\s*DMARC1\s*;/i.test(text.trim()));
    if (!records.length) continue;

    const tags = parseTagList(records[0]);
    // `sp` is what actually applies to the subdomain, when it is set.
    const effective = (tags.sp || tags.p || '').toLowerCase();
    return {
      domain: parent,
      result: {
        record: records[0],
        policy: effective,
        subdomainPolicy: (tags.sp || '').toLowerCase() || null,
        percent: tags.pct === undefined ? 100 : Number(tags.pct),
        alignment: {
          dkim: (tags.adkim || 'r').toLowerCase(),
          spf: (tags.aspf || 'r').toLowerCase(),
        },
        rua: [], ruf: [], externalAuthorisation: [],
        enforcing: effective === 'quarantine' || effective === 'reject',
        flags: effective === 'none'
          ? [flag('dmarc-policy-none', 'medium', 'warning', {})]
          : [],
      },
    };
  }
  return null;
}
