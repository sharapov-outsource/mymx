/**
 * mymx — the HTTP layer.
 *
 * Everything generic lives in @sharapov/service-kit; what is here is the part
 * that is about mail.
 *
 *   GET /                          the page
 *   GET /<domain>                  page for a domain (JSON for console clients)
 *   GET /api/<domain>              always data
 *   GET /api/<domain>?selector=k1  try a DKIM selector we would not have guessed
 *   GET /api/stream/<domain>       the same check as server-sent events
 *   GET /healthz                   liveness probe
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createService, parseDomain, localizeReport, pace } from '@sharapov/service-kit';
import { setPacer, defaultResolver } from '@sharapov/dns-wire';

import { scan, STAGES } from './scan.js';
import { outboundPort25 } from './smtp.js';
import { KNOWN_SELECTORS } from './dkim.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

setPacer(pace);

const service = await createService({
  slug: 'mymx',
  name: 'Mail Check',
  domain: 'mymx.sharapov.biz',
  port: 3027,
  root: ROOT,
  stages: STAGES,

  parse: raw => parseDomain(raw),
  pathFor: target => target.host,
  cacheKey: target => target.host,
  /* A different DKIM selector is a different report, so it must not be served
     from the cache entry of a check that did not ask for it. */
  cacheSuffix: query => String(query.selector || ''),
  run: (target, options) => scan(target, options),

  errors: ['smtp-timeout', 'smtp-network', 'smtp-refused', 'tls-failed'],

  examples: ['sharapov.biz', 'gmail.com', 'protonmail.com'],

  usage: {
    checks: [
      'MX with priorities, addresses and null-MX handling',
      'SPF expanded through every include, counted against the limit of 10',
      'DKIM keys for the selectors the large platforms use',
      'DMARC policy, alignment, and whether external report addresses authorise you',
      'MTA-STS policy fetched over HTTPS and compared with the real MX set',
      'DANE TLSA records checked against the certificate on the wire',
      'STARTTLS on 25, 465 and 587, plus a read-only open-relay probe',
      'reverse DNS with forward confirmation',
    ],
    parameters: {
      selector: 'a DKIM selector to try in addition to the known ones, comma-separated',
    },
    dkimSelectorsTried: KNOWN_SELECTORS.length,
    note: 'the open-relay probe stops at RCPT TO and sends RSET — no DATA command is ever issued, so no mail can be sent',
  },

  health: async () => ({
    resolver: defaultResolver(),
    outboundPort25: await outboundPort25(),
  }),

  localize: (report, lang) => localizeReport(report, service.i18n, lang, (out, language) => {
    const { tCode } = service.i18n;

    if (Array.isArray(out.incomplete)) {
      out.incompleteLabels = out.incomplete.map(code => tCode(language, 'inc', code));
    }
    if (out.dmarc?.policy) {
      out.dmarc.policyLabel = tCode(language, 'pol', out.dmarc.policy);
    }
    if (out.spf?.policy) {
      out.spf.policyLabel = tCode(language, 'spfp', out.spf.policy);
    }
    if (out.mtasts?.mode) {
      out.mtasts.modeLabel = tCode(language, 'stsmode', out.mtasts.mode);
    }
    for (const entry of out.rdns?.entries || []) {
      entry.statusLabel = tCode(language, 'rdns', entry.status);
    }
  }),
});

await service.start();

export { service };
