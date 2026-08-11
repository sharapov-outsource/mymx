/**
 * The mail check, in the order the dependencies allow.
 *
 * MX comes first because everything about transport needs to know which hosts
 * to talk to. SPF, DKIM, DMARC and TLS-RPT are pure DNS and independent of each
 * other, so they run together. MTA-STS needs the MX set to compare its policy
 * against. STARTTLS opens actual connections and therefore goes last but one,
 * and DANE goes last because it compares the TLSA records with the certificate
 * those connections produced.
 */

import { withDeadline, incomplete as collectIncomplete, sortFlags } from '@sharapov/service-kit';

import { createSession } from './session.js';
import { inspectMx } from './mx.js';
import { inspectSpf } from './spf.js';
import { inspectDkim } from './dkim.js';
import { inspectDmarc } from './dmarc.js';
import { inspectMtaSts, inspectTlsRpt } from './mtasts.js';
import { inspectStartTls } from './starttls.js';
import { inspectDane } from './dane.js';
import { inspectRdns } from './rdns.js';
import { grade } from './grade.js';

export const STAGES = [
  'resolve', 'mx', 'spf', 'dkim', 'dmarc', 'mtasts', 'dane', 'starttls', 'grade',
];

const SCAN_TIMEOUT = Number(process.env.SCAN_TIMEOUT_MS || 60000);

export async function scan(target, options = {}) {
  return withDeadline(run(target, options), SCAN_TIMEOUT);
}

async function run(target, { onProgress = () => {}, query = {} } = {}) {
  const domain = target.host;
  const started = Date.now();
  const session = createSession();
  const progress = (stage, extra = {}) =>
    onProgress({ stage, elapsedMs: Date.now() - started, ...extra });

  /* A caller who knows their DKIM selector can say so; without it we can only
     try the ones the large platforms use. */
  const selectors = String(query.selector || '')
    .split(',').map(entry => entry.trim().toLowerCase())
    .filter(entry => /^[a-z0-9_-]{1,63}$/.test(entry))
    .slice(0, 5);

  /* ---------------- mx ---------------- */
  progress('resolve');
  const mx = await inspectMx(session, domain);
  progress('mx', { done: true, hosts: mx.hosts.length, nullMx: mx.nullMx });

  /* ---------------- the DNS-only checks, together ---------------- */
  progress('spf');
  const [spf, dkim, dmarc, tlsrpt] = await Promise.all([
    inspectSpf(session, domain),
    inspectDkim(session, domain, { selectors }),
    inspectDmarc(session, domain),
    inspectTlsRpt(session, domain),
  ]);
  progress('spf', { done: true, lookups: spf.budget?.lookups });
  progress('dkim', { done: true, keys: dkim.keys?.length ?? 0 });
  progress('dmarc', { done: true, policy: dmarc.policy });

  /* ---------------- mta-sts ---------------- */
  progress('mtasts');
  const mtasts = await inspectMtaSts(session, domain, mx.hosts);
  progress('mtasts', { done: true, present: mtasts.present });

  /* ---------------- the connections ---------------- */
  progress('starttls');
  const starttls = mx.nullMx || !mx.hosts.length
    ? { sessions: [], live: [], port25: null, flags: [], incomplete: [] }
    : await inspectStartTls(session, mx.hosts);
  progress('starttls', { done: true, sessions: starttls.sessions.length });

  progress('dane');
  const dane = mx.hosts.length
    ? await inspectDane(session, mx.hosts, { sessions: starttls.live })
    : { hosts: [], present: false, covered: 0, total: 0, flags: [] };
  progress('dane', { done: true, covered: dane.covered });

  const rdns = mx.hosts.length
    ? await inspectRdns(session, mx.hosts)
    : { entries: [], checked: 0, confirmed: 0, allConfirmed: false, flags: [] };

  /* ---------------- assemble ---------------- */
  const flags = sortFlags([
    ...mx.flags, ...spf.flags, ...dkim.flags, ...dmarc.flags,
    ...mtasts.flags, ...tlsrpt.flags, ...starttls.flags, ...dane.flags, ...rdns.flags,
  ]);

  const incomplete = collectIncomplete([
    ...(mx.incomplete || []),
    ...(spf.incomplete || []),
    ...(dmarc.incomplete || []),
    ...(starttls.incomplete || []),
  ]);

  const partial = {
    domain,
    mx,
    spf,
    dkim,
    dmarc,
    mtasts,
    tlsrpt,
    starttls: { sessions: starttls.sessions, port25: starttls.port25, tlsEverywhere: starttls.tlsEverywhere },
    dane,
    rdns,
    flags,
    incomplete,
  };

  const report = {
    ...partial,
    grade: grade({ ...partial, starttls }),
    meta: {
      elapsedMs: Date.now() - started,
      queries: session.stats.queries,
      unanswered: session.failures,
      cached: false,
      generatedAt: new Date().toISOString(),
      engine: 'mymx/1.0',
    },
  };

  progress('grade', { grade: report.grade.grade });
  return report;
}
