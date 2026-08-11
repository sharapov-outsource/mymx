/**
 * Every code this service can put in a report. The flag identifiers are read
 * out of the source, because a list maintained by hand goes stale the first
 * time somebody adds a finding in a hurry — and the symptom, a raw identifier
 * showing up in the interface, is invisible until a user sends a screenshot.
 */

import path from 'node:path';
import { codesFrom } from '@sharapov/service-kit/check-i18n';

import { CAPS } from './server/grade.js';

export default function codes(root) {
  const server = file => path.join(root, 'server', file);

  const flags = [
    'mx.js', 'spf.js', 'dkim.js', 'dmarc.js', 'mtasts.js', 'dane.js', 'starttls.js', 'rdns.js',
  ].flatMap(file => codesFrom(server(file), /flag\('([a-z0-9-]+)'/g));

  return {
    flag: flags,
    fd: flags,
    stage: ['resolve', 'mx', 'spf', 'dkim', 'dmarc', 'mtasts', 'dane', 'starttls', 'grade'],
    comp: ['authentication', 'transport', 'hygiene'],
    cap: [...CAPS.map(([, , reason]) => reason), 'scan-incomplete'],
    inc: [
      'mx-lookup-failed', 'spf-lookup-failed', 'dmarc-lookup-failed',
      'port-25-unreachable-from-this-network', 'not-every-mx-was-probed',
    ],
    pol: ['none', 'quarantine', 'reject'],
    spfp: ['pass', 'fail', 'softfail', 'neutral', 'redirect'],
    spfterm: ['no-target', 'loop', 'lookup-failed', 'no-spf-record'],
    stsmode: ['enforce', 'testing', 'none'],
    rdns: ['confirmed', 'unconfirmed', 'missing', 'unknown'],
    err: [
      'invalid-host', 'domain-expected', 'invalid-port', 'port-not-allowed', 'dns-failed',
      'private-address', 'unreachable', 'scan-timeout', 'stage-timeout', 'scan-failed',
      'busy', 'bad-output', 'network', 'bad-response', 'timeout',
      'smtp-timeout', 'smtp-network', 'smtp-refused', 'tls-failed',
    ],
    sev: ['critical', 'high', 'medium', 'low', 'info'],
    st: ['ok', 'safe', 'warning', 'weak', 'missing', 'unknown', 'partial', 'failed', 'info', 'vulnerable'],
  };
}
