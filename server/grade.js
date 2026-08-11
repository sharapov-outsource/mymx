/**
 * The letter.
 *
 * Three components, weighted:
 *
 *   authentication  45%  — SPF, DKIM, DMARC, and whether DMARC is enforcing
 *   transport       35%  — STARTTLS, MTA-STS, DANE, TLS-RPT
 *   hygiene         20%  — MX sanity, reverse DNS, no open relay
 *
 * Authentication carries the most weight because it is the half that stops
 * somebody sending as you, and because it is the half that is entirely within
 * the domain owner's control. Transport protects mail in flight and depends on
 * the other end cooperating.
 *
 * Two rules are absolute. An open relay is an F, whatever else is right: it is
 * an active hazard to everybody, not a weakness in the domain's own defences.
 * And if a check could not be made — most often because outbound port 25 is
 * blocked from wherever this is running — there is no letter at all, only a
 * list of what could not be established.
 */

import { letterFor, worstGrade, weighted, sortFlags } from '@sharapov/service-kit';

export const CAPS = [
  ['open-relay', 'F', 'open-relay'],
  ['spf-plus-all', 'F', 'spf-authorises-everyone'],
  ['no-mx', 'F', 'no-mail-servers'],
  ['mx-not-reachable-on-25', 'F', 'mail-servers-unreachable'],
  ['dane-mismatch', 'F', 'dane-mismatch'],
  ['mtasts-mx-not-in-policy', 'F', 'mtasts-policy-contradicts-dns'],
  ['spf-too-many-lookups', 'D', 'spf-over-the-lookup-limit'],
  ['spf-multiple-records', 'D', 'spf-permerror'],
  ['dmarc-multiple-records', 'D', 'dmarc-permerror'],
  ['no-starttls', 'D', 'mail-in-the-clear'],
  ['spf-missing', 'C', 'no-spf'],
  ['dmarc-missing', 'C', 'no-dmarc'],
  ['starttls-fails', 'C', 'starttls-broken'],
  ['dmarc-policy-none', 'B', 'dmarc-not-enforcing'],
  ['rdns-none-confirmed', 'B', 'no-reverse-dns'],
  ['spf-no-all', 'B', 'spf-without-a-default'],
  ['dkim-key-too-short', 'B', 'weak-dkim-key'],
  ['dmarc-external-reporting-unauthorised', 'B', 'dmarc-reports-go-nowhere'],
  ['mx-does-not-resolve', 'C', 'mail-server-does-not-resolve'],
];

const WARNINGS = [
  'spf-lookups-near-limit', 'spf-uses-ptr', 'spf-softfail-all', 'spf-neutral-all',
  'dkim-no-known-selector', 'dkim-in-test-mode', 'dkim-key-1024-bit',
  'dmarc-partial-percentage', 'dmarc-no-reporting', 'dmarc-subdomain-policy-none',
  'mtasts-missing', 'mtasts-mode-testing', 'tlsrpt-missing', 'dane-missing',
  'dane-partial', 'rdns-not-confirmed', 'single-mx', 'no-ipv6-mx',
  'mx-certificate-not-trusted', 'banner-reveals-version', 'mx-points-at-cname',
];

function authenticationScore({ spf, dkim, dmarc }) {
  let score = 0;

  /* SPF: 35 of the component. A record that a receiver would reject as a
     permerror is worth nothing, because permerror means SPF does not apply. */
  if (spf.present) {
    /* A record a receiver would reject as a permerror is worth nothing, because
       permerror means SPF does not apply. The budget is checked directly rather
       than only through the findings, so this holds however the report was
       assembled. */
    const permerror = spf.budget?.withinLimit === false ||
      (spf.flags || []).some(entry =>
        ['spf-too-many-lookups', 'spf-multiple-records', 'spf-unknown-mechanism'].includes(entry.id));
    if (!permerror) {
      score += 20;
      if (spf.policy === 'fail') score += 15;
      else if (spf.policy === 'softfail') score += 12;
      else if (spf.policy === 'neutral') score += 4;
    }
  }

  /* DKIM: 25. Not finding a key is not proof there is none, so an inconclusive
     result costs less than a key that is present and weak. */
  const usable = dkim.keys.filter(key => !key.revoked && !key.malformed && !key.testing);
  if (usable.length) {
    score += 18;
    if (usable.some(key => (key.bits ?? 0) >= 2048 || key.keyType === 'ed25519')) score += 7;
    else if (usable.some(key => (key.bits ?? 0) >= 1024)) score += 4;
  } else if (!dkim.conclusive) {
    // Unknown, not absent.
    score += 8;
  }

  /* DMARC: 40, because it is what makes the other two mean anything. */
  if (dmarc.present) {
    score += 12;
    if (dmarc.policy === 'reject') score += 20;
    else if (dmarc.policy === 'quarantine') score += 14;
    if (dmarc.percent === 100) score += 4;
    if (dmarc.rua?.length) score += 4;
    if (dmarc.alignment?.dkim === 's' || dmarc.alignment?.spf === 's') score += 0;
  }

  return Math.max(0, Math.min(100, score));
}

function transportScore({ starttls, mtasts, dane, tlsrpt }) {
  const reachable = (starttls.sessions || [])
    .filter(entry => entry.port === 25 && entry.reachable);

  let score = 0;

  if (reachable.length) {
    const withTls = reachable.filter(entry => entry.starttls?.established);
    score += Math.round(45 * (withTls.length / reachable.length));
    if (withTls.length && withTls.every(entry => /TLSv1\.[23]/.test(entry.tls?.protocol || ''))) {
      score += 10;
    }
  } else if (!starttls.port25?.usable) {
    /* Unknown rather than absent. The grade is withheld anyway when this
       happens, but the component still has to hold a defensible number. */
    score += 30;
  }

  if (mtasts.present) {
    score += mtasts.mode === 'enforce' ? 25 : 10;
  }
  if (dane.present) {
    score += dane.covered === dane.total ? 15 : 8;
  }
  if (tlsrpt.present) score += 5;

  return Math.max(0, Math.min(100, score));
}

function hygieneScore({ mx, rdns, starttls }) {
  let score = 100;

  if (mx.nullMx) return 100;                           // says nothing, correctly

  if (!mx.hosts.length) score -= 50;
  if (mx.hosts.length === 1) score -= 8;
  if (mx.hosts.some(host => !host.addresses.length)) score -= 25;
  if (mx.hosts.some(host => host.alias)) score -= 10;
  if (mx.hosts.length && !mx.hosts.some(host => host.ipv6)) score -= 5;

  if (rdns.checked) {
    score -= Math.round(30 * (1 - rdns.confirmed / rdns.checked));
  }

  const relaying = (starttls.sessions || []).some(entry => entry.relay?.open);
  if (relaying) score = 0;

  return Math.max(0, Math.min(100, score));
}

export function grade(report) {
  const flags = sortFlags(report.flags || []);
  const present = new Set(flags.map(entry => entry.id));

  const components = {
    authentication: {
      key: 'authentication',
      score: authenticationScore(report),
      weight: 0.45,
    },
    transport: { key: 'transport', score: transportScore(report), weight: 0.35 },
    hygiene: { key: 'hygiene', score: hygieneScore(report), weight: 0.2 },
  };

  const score = weighted(Object.values(components));
  let letter = letterFor(score);

  const caps = [];
  const warnings = WARNINGS.filter(id => present.has(id));

  /* An open relay is reported even from an incomplete check, because it is the
     one finding that is urgent regardless of what else could not be measured. */
  if (present.has('open-relay')) {
    caps.push({ grade: 'F', reason: 'open-relay' });
    return finish('F');
  }

  if (report.incomplete?.length) {
    return finish('?', 'scan-incomplete');
  }

  for (const [id, cap, reason] of CAPS) {
    if (!present.has(id)) continue;
    caps.push({ grade: cap, reason });
    letter = worstGrade(letter, cap);
  }

  /* The bonus: authentication enforced, transport protected by policy rather
     than by hope, and nothing outstanding. */
  if (letter === 'A' && !warnings.length &&
      report.dmarc.policy === 'reject' &&
      (report.mtasts.mode === 'enforce' || report.dane.present)) {
    letter = 'A+';
  }

  return finish(letter);

  function finish(finalGrade, reason) {
    return {
      grade: finalGrade,
      score,
      reason,
      components,
      caps,
      warnings,
      methodology: 'mymx/1.0 — authentication 45%, transport 35%, hygiene 20%',
    };
  }
}
