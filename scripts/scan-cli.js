#!/usr/bin/env node
/**
 * The checker without the web server, for when a terminal is enough:
 *
 *   npm run scan -- example.com
 *   npm run scan -- example.com --json
 */

import { scan } from '../server/scan.js';

const args = process.argv.slice(2);
const domain = args.find(argument => !argument.startsWith('-'));
const asJson = args.includes('--json');

if (!domain) {
  console.error('usage: npm run scan -- <domain> [--json]');
  process.exit(2);
}

const report = await scan({ host: domain }, {
  onProgress: event => {
    if (asJson) return;
    process.stderr.write(`  ${event.stage}${event.done ? ' ✓' : '…'}\n`);
  },
});

if (asJson) {
  console.log(JSON.stringify(report, null, 2));
  process.exit(0);
}

const line = (label, value) => console.log(`  ${String(label).padEnd(22)} ${value}`);

console.log(`\n${report.domain} — grade ${report.grade.grade} (${report.grade.score})\n`);
line('mx', report.mx.nullMx ? 'null MX (no mail)' :
  report.mx.hosts.map(host => `${host.preference} ${host.host}`).join(', ') || '—');
for (const [name, component] of Object.entries(report.grade.components)) {
  line(name, `${component.score} × ${component.weight}`);
}
line('spf', report.spf.present
  ? `${report.spf.budget.lookups}/${report.spf.budget.limit} lookups · ${report.spf.policy}`
  : 'none');
line('dkim', report.dkim.keys.length
  ? report.dkim.keys.map(key => `${key.selector}:${key.bits ?? '?'}`).join(', ')
  : `none of ${report.dkim.triedSelectors} known selectors`);
line('dmarc', report.dmarc.present ? `p=${report.dmarc.policy} pct=${report.dmarc.percent}` : 'none');
line('mta-sts', report.mtasts.present ? report.mtasts.mode || 'no policy fetched' : 'none');
line('dane', report.dane.total ? `${report.dane.covered}/${report.dane.total} servers` : '—');
line('rdns', report.rdns.checked ? `${report.rdns.confirmed}/${report.rdns.checked} confirmed` : '—');
line('port 25', report.starttls.port25
  ? (report.starttls.port25.usable ? 'reachable' : `${report.starttls.port25.reason} from here`)
  : '—');

if (report.incomplete?.length) {
  console.log(`\n  incomplete: ${report.incomplete.join(', ')}`);
}

console.log('\nfindings:');
if (!report.flags.length) console.log('  none');
for (const finding of report.flags) {
  console.log(`  ${finding.severity.padEnd(8)} ${finding.id}`);
}
console.log(`\n${report.meta.queries} queries in ${report.meta.elapsedMs} ms\n`);
