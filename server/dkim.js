/**
 * DKIM, which can only ever be checked halfway from the outside.
 *
 * A DKIM key lives at `<selector>._domainkey.<domain>`, and the selector is
 * chosen by whoever signs — it is written into the header of each message and
 * is not published anywhere else. From outside, with no message in hand, there
 * is no way to enumerate them. So this tries the selectors the large providers
 * and mail platforms actually use, and takes a custom one when the caller knows
 * theirs.
 *
 * That means "no key found" here is never proof that DKIM is missing, and the
 * report has to say so rather than implying otherwise. What it *can* say with
 * certainty is what is wrong with the keys it did find: a modulus under 1024
 * bits, a record left in test mode, or a key revoked by publishing an empty
 * `p=` and then forgotten about.
 */

import { createPublicKey } from 'node:crypto';

import { TYPE } from '@sharapov/dns-wire';
import { flag } from '@sharapov/service-kit';

/**
 * Selectors worth trying: the defaults of the platforms that sign the most
 * mail, plus the conventional ones.
 */
export const KNOWN_SELECTORS = [
  'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'mail', 'dkim',
  's1', 's2', 'smtp', 'mandrill', 'sendgrid', 'zoho', 'mailru', 'yandex',
  'protonmail', 'protonmail2', 'fm1', 'mailjet', 'postmark', 'sparkpost',
  'amazonses', 'everlytickey1', 'mailchimp', 'hs1-', 'ctct1',
];

/** `k=rsa; p=MIGf...; t=y` — a tag list, same shape as DMARC's. */
export function parseTagList(text) {
  const tags = {};
  for (const part of String(text).split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    const key = part.slice(0, index).trim().toLowerCase();
    if (key) tags[key] = part.slice(index + 1).trim();
  }
  return tags;
}

/** Key size, read from the DER the record carries rather than guessed. */
function keyStrength(tags) {
  const material = String(tags.p || '').replace(/\s+/g, '');
  if (!material) return { revoked: true, bits: null, type: null };

  const type = (tags.k || 'rsa').toLowerCase();
  if (type === 'ed25519') return { revoked: false, bits: 256, type };

  try {
    const key = createPublicKey({
      key: Buffer.from(material, 'base64'),
      format: 'der',
      type: 'spki',
    });
    return {
      revoked: false,
      type: key.asymmetricKeyType || type,
      bits: key.asymmetricKeyDetails?.modulusLength ?? null,
    };
  } catch {
    return { revoked: false, bits: null, type, malformed: true };
  }
}

export async function inspectDkim(session, domain, { selectors = [] } = {}) {
  const flags = [];
  const candidates = [...new Set([...selectors, ...KNOWN_SELECTORS])];

  const found = [];
  await Promise.all(candidates.map(async selector => {
    const name = `${selector}._domainkey.${domain}`;
    const response = await session.ask({ name, type: 'TXT' });
    const texts = (response?.message?.answers || [])
      .filter(record => record.type === TYPE.TXT)
      .map(record => record.data.text)
      .filter(text => /(^|;)\s*(v\s*=\s*DKIM1|k\s*=|p\s*=)/i.test(text));
    if (!texts.length) return;

    for (const text of texts) {
      const tags = parseTagList(text);
      const strength = keyStrength(tags);
      found.push({
        selector,
        name,
        version: tags.v || null,
        keyType: strength.type,
        bits: strength.bits,
        revoked: strength.revoked,
        malformed: Boolean(strength.malformed),
        testing: /(^|:)y(:|$)/i.test(tags.t || ''),
        strictSubdomains: /(^|:)s(:|$)/i.test(tags.t || ''),
        serviceType: tags.s || null,
        notes: tags.n || null,
      });
    }
  }));

  found.sort((a, b) => a.selector.localeCompare(b.selector));

  if (!found.length) {
    /* Deliberately not "DKIM is missing". We cannot enumerate selectors, so the
       most that can honestly be said is that none of the ones we know about
       are published. */
    flags.push(flag('dkim-no-known-selector', 'medium', 'unknown',
      { tried: candidates.length }));
    return { keys: [], triedSelectors: candidates.length, conclusive: false, flags };
  }

  for (const key of found) {
    if (key.revoked) {
      flags.push(flag('dkim-key-revoked', 'medium', 'warning', { selector: key.selector }));
      continue;
    }
    if (key.malformed) {
      flags.push(flag('dkim-key-malformed', 'high', 'failed', { selector: key.selector }));
      continue;
    }
    if (key.testing) {
      // t=y tells receivers to treat a failure as if DKIM were not in use. It
      // belongs in a rollout and nowhere else.
      flags.push(flag('dkim-in-test-mode', 'medium', 'warning', { selector: key.selector }));
    }
    if (key.bits && key.bits < 1024) {
      flags.push(flag('dkim-key-too-short', 'high', 'weak',
        { selector: key.selector, bits: key.bits }));
    } else if (key.bits && key.bits < 2048 && key.keyType === 'rsa') {
      flags.push(flag('dkim-key-1024-bit', 'low', 'warning',
        { selector: key.selector, bits: key.bits }));
    }
  }

  return {
    keys: found,
    triedSelectors: candidates.length,
    conclusive: true,
    flags,
  };
}
