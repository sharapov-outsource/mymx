/**
 * The reasoning behind a mail report.
 *
 * The lookup budget is the centre of this file, because it is the check that
 * this service exists for and the one that is easiest to get subtly wrong: the
 * limit is on *terms evaluated across the whole expansion*, not on terms in the
 * top record, and the difference only shows up once includes are nested.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { TYPE } from '@sharapov/dns-wire';

import { parseSpf, inspectSpf } from '../server/spf.js';
import { inspectDmarc } from '../server/dmarc.js';
import { inspectMx } from '../server/mx.js';
import { parseTagList } from '../server/dkim.js';
import { matchesPattern, parsePolicy } from '../server/mtasts.js';
import { reverseName } from '../server/rdns.js';
import { grade } from '../server/grade.js';

/* ------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------ */

function stubSession(table) {
  return {
    ask: async options => {
      const key = `${options.name}|${options.type}`;
      const answer = table[key];
      if (answer === undefined) return txtResponse([]);
      return typeof answer === 'function' ? answer(options) : answer;
    },
    stats: { queries: 0, failures: 0 },
    failures: [],
  };
}

const message = answers => ({
  server: '1.1.1.1',
  elapsedMs: 5,
  message: {
    flags: { aa: false, tc: false, rd: true, ra: true, ad: false, cd: false, qr: true },
    rcodeName: 'NOERROR',
    answers,
    authorities: [],
    additionals: [],
  },
});

const txtResponse = texts => message(texts.map(text => ({
  name: 'x', type: TYPE.TXT, typeName: 'TXT', ttl: 300,
  data: { text, strings: [text], chunks: 1 },
})));

const mxResponse = entries => message(entries.map(([preference, exchange]) => ({
  name: 'x', type: TYPE.MX, typeName: 'MX', ttl: 300,
  data: { preference, exchange },
})));

const aResponse = addresses => message(addresses.map(address => ({
  name: 'x', type: TYPE.A, typeName: 'A', ttl: 300, data: { address },
})));

/* ------------------------------------------------------------------ *
 * Parsing
 * ------------------------------------------------------------------ */

test('an SPF record is split into mechanisms and modifiers in order', () => {
  const { terms } = parseSpf('v=spf1 ip4:203.0.113.0/24 include:_spf.example.net -all');
  assert.equal(terms.length, 3);
  assert.deepEqual(terms.map(term => term.name), ['ip4', 'include', 'all']);
  assert.equal(terms[0].cidr, '/24');
  assert.equal(terms[2].qualifier, '-');
});

test('something that is not an SPF record is refused rather than half-parsed', () => {
  const { terms, problems } = parseSpf('google-site-verification=abc123');
  assert.equal(terms.length, 0);
  assert.deepEqual(problems, ['not-an-spf-record']);
});

test('a tag list survives odd spacing', () => {
  const tags = parseTagList('v=DKIM1 ; k = rsa ;p=AAAA; t=y');
  assert.equal(tags.v, 'DKIM1');
  assert.equal(tags.k, 'rsa');
  assert.equal(tags.t, 'y');
});

/* ------------------------------------------------------------------ *
 * The lookup budget
 * ------------------------------------------------------------------ */

test('ip4 and all cost nothing; include costs one each', async () => {
  const session = stubSession({
    'example.com|TXT': txtResponse(['v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 -all']),
  });
  const result = await inspectSpf(session, 'example.com');
  assert.equal(result.budget.lookups, 0);
  assert.equal(result.budget.withinLimit, true);
  assert.equal(result.policy, 'fail');
});

test('the budget counts terms inside includes, not only the top record', async () => {
  const session = stubSession({
    'example.com|TXT': txtResponse(['v=spf1 include:a.example include:b.example -all']),
    'a.example|TXT': txtResponse(['v=spf1 include:c.example a mx ~all']),
    'a.example|A': aResponse(['203.0.113.7']),
    'a.example|MX': mxResponse([[10, 'mail.a.example']]),
    'b.example|TXT': txtResponse(['v=spf1 ip4:198.51.100.0/24 ~all']),
    'c.example|TXT': txtResponse(['v=spf1 exists:%{i}.c.example ~all']),
  });
  const result = await inspectSpf(session, 'example.com');
  // include:a (1) + include:c (2) + exists (3) + a (4) + mx (5) + include:b (6)
  assert.equal(result.budget.lookups, 6);
  assert.equal(result.budget.withinLimit, true);
  // The exists: target carries a macro, so it costs a lookup and nothing else.
  assert.equal(result.budget.voids, 0);
});

test('a macro target costs a lookup but is never counted as a void one', async () => {
  const session = stubSession({
    'example.com|TXT': txtResponse(['v=spf1 exists:%{i}._spf.example.com -all']),
  });
  const result = await inspectSpf(session, 'example.com');
  assert.equal(result.budget.lookups, 1);
  assert.equal(result.budget.voids, 0);
  assert.equal(result.tree.children[0].macro, true);
});

test('going past ten lookups is a critical finding, and the term is named', async () => {
  const table = { 'example.com|TXT': txtResponse([
    'v=spf1 ' + Array.from({ length: 12 }, (_, i) => `include:s${i}.example`).join(' ') + ' -all',
  ]) };
  for (let i = 0; i < 12; i++) {
    table[`s${i}.example|TXT`] = txtResponse(['v=spf1 ip4:203.0.113.0/24 ~all']);
  }
  const result = await inspectSpf(stubSession(table), 'example.com');

  assert.equal(result.budget.lookups, 12);
  assert.equal(result.budget.withinLimit, false);
  const finding = result.flags.find(entry => entry.id === 'spf-too-many-lookups');
  assert.ok(finding);
  assert.equal(finding.limit, 10);
  assert.equal(finding.exceededAt, 'include:s10.example');
});

test('being close to the limit is worth saying before it is exceeded', async () => {
  const table = { 'example.com|TXT': txtResponse([
    'v=spf1 ' + Array.from({ length: 9 }, (_, i) => `include:s${i}.example`).join(' ') + ' -all',
  ]) };
  for (let i = 0; i < 9; i++) {
    table[`s${i}.example|TXT`] = txtResponse(['v=spf1 ip4:203.0.113.0/24 ~all']);
  }
  const result = await inspectSpf(stubSession(table), 'example.com');
  assert.equal(result.budget.withinLimit, true);
  assert.ok(result.flags.some(entry => entry.id === 'spf-lookups-near-limit'));
});

test('an include loop is caught rather than followed forever', async () => {
  const session = stubSession({
    'example.com|TXT': txtResponse(['v=spf1 include:a.example -all']),
    'a.example|TXT': txtResponse(['v=spf1 include:b.example ~all']),
    'b.example|TXT': txtResponse(['v=spf1 include:a.example ~all']),
  });
  const result = await inspectSpf(session, 'example.com');
  assert.ok(result.flags.some(entry => entry.id === 'spf-include-loop'));
});

test('an include pointing at a domain with no SPF record is a permanent error', async () => {
  const session = stubSession({
    'example.com|TXT': txtResponse(['v=spf1 include:gone.example -all']),
    'gone.example|TXT': txtResponse([]),
  });
  const result = await inspectSpf(session, 'example.com');
  assert.ok(result.flags.some(entry => entry.id === 'spf-include-without-record'));
  assert.equal(result.budget.voids, 1);
});

test('two SPF records are a permanent error, not a preference', async () => {
  const session = stubSession({
    'example.com|TXT': txtResponse(['v=spf1 include:a.example -all', 'v=spf1 ip4:203.0.113.1 -all']),
    'a.example|TXT': txtResponse(['v=spf1 ip4:198.51.100.0/24 ~all']),
  });
  const result = await inspectSpf(session, 'example.com');
  const finding = result.flags.find(entry => entry.id === 'spf-multiple-records');
  assert.ok(finding);
  assert.equal(finding.severity, 'critical');
});

test('+all is reported as worse than having no record', async () => {
  const session = stubSession({ 'example.com|TXT': txtResponse(['v=spf1 +all']) });
  const result = await inspectSpf(session, 'example.com');
  const finding = result.flags.find(entry => entry.id === 'spf-plus-all');
  assert.equal(finding.severity, 'critical');
  assert.equal(result.policy, 'pass');
});

test('a missing SPF record is a finding, not an absent section', async () => {
  const result = await inspectSpf(stubSession({}), 'example.com');
  assert.equal(result.present, false);
  assert.ok(result.flags.some(entry => entry.id === 'spf-missing'));
});

test('a TXT record that is not SPF is ignored rather than parsed', async () => {
  const session = stubSession({
    'example.com|TXT': txtResponse(['google-site-verification=abc', 'MS=ms12345']),
  });
  const result = await inspectSpf(session, 'example.com');
  assert.equal(result.present, false);
});

/* ------------------------------------------------------------------ *
 * DMARC
 * ------------------------------------------------------------------ */

test('p=none is reported as monitoring rather than protection', async () => {
  const session = stubSession({
    '_dmarc.example.com|TXT': txtResponse(['v=DMARC1; p=none; rua=mailto:d@example.com']),
  });
  const result = await inspectDmarc(session, 'example.com');
  assert.equal(result.policy, 'none');
  assert.equal(result.enforcing, false);
  assert.ok(result.flags.some(entry => entry.id === 'dmarc-policy-none'));
});

test('an external report address without authorisation is caught', async () => {
  const session = stubSession({
    '_dmarc.example.com|TXT': txtResponse(['v=DMARC1; p=reject; rua=mailto:reports@dmarc-vendor.test']),
    // The vendor publishes nothing, so conforming receivers send no reports.
    'example.com._report._dmarc.dmarc-vendor.test|TXT': txtResponse([]),
  });
  const result = await inspectDmarc(session, 'example.com');
  const finding = result.flags.find(entry => entry.id === 'dmarc-external-reporting-unauthorised');
  assert.ok(finding);
  assert.equal(finding.target, 'dmarc-vendor.test');
  assert.equal(finding.record, 'example.com._report._dmarc.dmarc-vendor.test');
});

test('an authorised external report address produces no finding', async () => {
  const session = stubSession({
    '_dmarc.example.com|TXT': txtResponse(['v=DMARC1; p=reject; rua=mailto:reports@dmarc-vendor.test']),
    'example.com._report._dmarc.dmarc-vendor.test|TXT': txtResponse(['v=DMARC1']),
  });
  const result = await inspectDmarc(session, 'example.com');
  assert.equal(result.flags.filter(f => f.id === 'dmarc-external-reporting-unauthorised').length, 0);
  assert.equal(result.externalAuthorisation[0].authorised, true);
});

test('an address inside the domain needs no authorisation record', async () => {
  const session = stubSession({
    '_dmarc.example.com|TXT': txtResponse(['v=DMARC1; p=reject; rua=mailto:dmarc@mail.example.com']),
  });
  const result = await inspectDmarc(session, 'example.com');
  assert.deepEqual(result.externalAuthorisation, []);
});

test('a subdomain inherits the organisational policy', async () => {
  const session = stubSession({
    '_dmarc.mail.example.com|TXT': txtResponse([]),
    '_dmarc.example.com|TXT': txtResponse(['v=DMARC1; p=reject; sp=quarantine']),
  });
  const result = await inspectDmarc(session, 'mail.example.com');
  assert.equal(result.present, true);
  assert.equal(result.inheritedFrom, 'example.com');
  // sp is what actually applies to the subdomain.
  assert.equal(result.policy, 'quarantine');
});

test('pct below 100 leaves a gap and is reported', async () => {
  const session = stubSession({
    '_dmarc.example.com|TXT': txtResponse(['v=DMARC1; p=reject; pct=20; rua=mailto:d@example.com']),
  });
  const result = await inspectDmarc(session, 'example.com');
  assert.equal(result.percent, 20);
  assert.ok(result.flags.some(entry => entry.id === 'dmarc-partial-percentage'));
});

/* ------------------------------------------------------------------ *
 * MX
 * ------------------------------------------------------------------ */

test('a null MX is read as a deliberate statement, not as an absence', async () => {
  const session = stubSession({ 'example.com|MX': mxResponse([[0, '.']]) });
  const result = await inspectMx(session, 'example.com');
  assert.equal(result.nullMx, true);
  assert.equal(result.hosts.length, 0);
  assert.ok(result.flags.some(entry => entry.id === 'null-mx'));
});

test('no MX with an A record means senders fall back to the web server', async () => {
  const session = stubSession({
    'example.com|MX': mxResponse([]),
    'example.com|A': aResponse(['203.0.113.10']),
  });
  const result = await inspectMx(session, 'example.com');
  assert.ok(result.flags.some(entry => entry.id === 'no-mx-falls-back-to-a'));
});

test('an MX that does not resolve is a failure, not a warning', async () => {
  const session = stubSession({
    'example.com|MX': mxResponse([[10, 'mail.example.com']]),
    'mail.example.com|A': aResponse([]),
    'mail.example.com|AAAA': message([]),
    'mail.example.com|CNAME': message([]),
  });
  const result = await inspectMx(session, 'example.com');
  const finding = result.flags.find(entry => entry.id === 'mx-does-not-resolve');
  assert.equal(finding.severity, 'high');
});

/* ------------------------------------------------------------------ *
 * MTA-STS
 * ------------------------------------------------------------------ */

test('an mx pattern matches one label and only the leftmost', () => {
  assert.equal(matchesPattern('*.example.com', 'mail.example.com'), true);
  assert.equal(matchesPattern('*.example.com', 'a.b.example.com'), false);
  assert.equal(matchesPattern('*.example.com', 'example.com'), false);
  assert.equal(matchesPattern('mail.example.com', 'mail.example.com'), true);
  assert.equal(matchesPattern('MAIL.Example.COM', 'mail.example.com'), true);
});

test('a policy document is parsed with mx repeated', () => {
  const policy = parsePolicy([
    'version: STSv1', 'mode: enforce',
    'mx: mail1.example.com', 'mx: mail2.example.com', 'max_age: 604800',
  ].join('\n'));
  assert.equal(policy.version, 'STSv1');
  assert.equal(policy.mode, 'enforce');
  assert.deepEqual(policy.mx, ['mail1.example.com', 'mail2.example.com']);
  assert.equal(policy.max_age, '604800');
});

/* ------------------------------------------------------------------ *
 * Reverse DNS
 * ------------------------------------------------------------------ */

test('a reverse name is built for both address families', () => {
  assert.equal(reverseName('203.0.113.5'), '5.113.0.203.in-addr.arpa');
  assert.equal(reverseName('2001:db8::1'),
    '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa');
});

/* ------------------------------------------------------------------ *
 * The grade
 * ------------------------------------------------------------------ */

function baseReport(overrides = {}) {
  return {
    flags: [],
    mx: { hosts: [{ host: 'mail.example.com', addresses: [{ address: '203.0.113.1', family: 4 }], ipv6: true, alias: false }], nullMx: false, flags: [] },
    spf: { present: true, policy: 'fail', budget: { lookups: 4, limit: 10, withinLimit: true }, flags: [] },
    dkim: { keys: [{ selector: 'default', bits: 2048, keyType: 'rsa' }], conclusive: true, flags: [] },
    dmarc: { present: true, policy: 'reject', percent: 100, rua: [{ address: 'd@example.com' }], alignment: { dkim: 's', spf: 's' }, enforcing: true, flags: [] },
    mtasts: { present: true, mode: 'enforce', flags: [] },
    tlsrpt: { present: true, flags: [] },
    dane: { present: true, covered: 1, total: 1, flags: [] },
    rdns: { checked: 1, confirmed: 1, allConfirmed: true, flags: [] },
    starttls: {
      sessions: [{ host: 'mail.example.com', port: 25, reachable: true, starttls: { established: true }, tls: { protocol: 'TLSv1.3' } }],
      port25: { usable: true },
      flags: [],
    },
    ...overrides,
  };
}

test('a domain doing everything right reaches the top of the scale', () => {
  const result = grade(baseReport());
  assert.ok(['A', 'A+'].includes(result.grade), `${result.grade} (${result.score})`);
});

test('an open relay is an F even when everything else is perfect', () => {
  const report = baseReport();
  report.flags = [{ id: 'open-relay', severity: 'critical', status: 'failed' }];
  report.starttls.sessions[0].relay = { open: true };
  const result = grade(report);
  assert.equal(result.grade, 'F');
});

test('an open relay is reported even when the check was otherwise incomplete', () => {
  const report = baseReport({ incomplete: ['port-25-unreachable-from-this-network'] });
  report.flags = [{ id: 'open-relay', severity: 'critical', status: 'failed' }];
  // The one finding urgent enough to outrank "we could not measure everything".
  assert.equal(grade(report).grade, 'F');
});

test('port 25 blocked from our side withholds the grade rather than guessing', () => {
  const report = baseReport({ incomplete: ['port-25-unreachable-from-this-network'] });
  const result = grade(report);
  assert.equal(result.grade, '?');
  assert.equal(result.reason, 'scan-incomplete');
});

test('p=none caps the grade however good the transport is', () => {
  const report = baseReport();
  report.dmarc = { ...report.dmarc, policy: 'none', enforcing: false };
  report.flags = [{ id: 'dmarc-policy-none', severity: 'medium', status: 'warning' }];
  const result = grade(report);
  assert.ok(['B', 'C', 'D'].includes(result.grade), result.grade);
  assert.ok(result.caps.some(cap => cap.reason === 'dmarc-not-enforcing'));
});

test('an SPF record over the lookup limit scores nothing for SPF', () => {
  const report = baseReport();
  report.spf = {
    present: true, policy: 'fail',
    budget: { lookups: 14, limit: 10, withinLimit: false },
    flags: [{ id: 'spf-too-many-lookups', severity: 'critical', status: 'failed' }],
  };
  report.flags = [{ id: 'spf-too-many-lookups', severity: 'critical', status: 'failed' }];
  const result = grade(report);
  // A permerror means SPF does not apply, so it must not be scored as present.
  assert.ok(result.components.authentication.score < grade(baseReport()).components.authentication.score);
  assert.ok(result.caps.some(cap => cap.reason === 'spf-over-the-lookup-limit'));
});

test('not finding a DKIM selector costs less than finding a broken key', () => {
  const unknown = baseReport();
  unknown.dkim = { keys: [], conclusive: false, flags: [] };

  const broken = baseReport();
  broken.dkim = { keys: [{ selector: 'default', revoked: true }], conclusive: true, flags: [] };

  assert.ok(grade(unknown).components.authentication.score >
    grade(broken).components.authentication.score);
});
