/**
 * mymx client.
 *
 * A check makes several dozen DNS queries and opens SMTP sessions to the mail
 * servers, so the page follows an event stream and fills the progress bar as the
 * stages go by. Switching language repaints from the report already in memory —
 * no second check, and no second round of connections to somebody's mail server.
 */
'use strict';

const byId = id => document.getElementById(id);
const DASH = '—';

/* ================================================================== *
 * Language
 * ================================================================== */

const I18N = window.I18N;
const RTL = new Set(window.RTL_LANGS || []);
const STORAGE_KEY = 'mymx-lang';

function detectLang() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved && I18N[saved]) return saved;
  } catch { /* localStorage may be unavailable */ }

  const candidates = navigator.languages?.length ? navigator.languages : [navigator.language || 'en'];
  for (const raw of candidates) {
    const tag = String(raw).toLowerCase();
    if (I18N[tag]) return tag;
    const base = tag.split('-')[0];
    if (I18N[base]) return base;
  }
  return 'en';
}

let LANG = detectLang();
const locale = () => (window.LANG_LOCALES?.[LANG]) || LANG;

function t(key, vars) {
  const dict = I18N[LANG] || I18N.en;
  let value = dict[key] ?? I18N.en[key] ?? key;
  if (vars) for (const [name, replacement] of Object.entries(vars)) {
    value = value.split('{' + name + '}').join(replacement);
  }
  return value;
}

/** Translation for a dashed code such as "lame-delegation", or the code itself. */
function tCode(prefix, code) {
  if (!code && code !== 0) return undefined;
  const key = prefix + '_' + String(code).replace(/[-.]/g, '_');
  const dict = I18N[LANG] || I18N.en;
  return dict[key] ?? I18N.en[key] ?? String(code).replace(/-/g, ' ');
}

/* ================================================================== *
 * Rendering helpers
 * ================================================================== */

function set(id, value, state) {
  const node = byId(id);
  if (!node) return;
  const empty = value === undefined || value === null || value === '' ||
    (Array.isArray(value) && !value.length) ||
    (typeof value === 'number' && Number.isNaN(value));
  node.className = 'v' + (empty ? ' muted' : state ? ' ' + state : '');
  node.textContent = empty ? DASH : (Array.isArray(value) ? value.join(', ') : String(value));
}

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** Yes/no with the colour that matches which answer is the good one. */
function flagRow(id, value, { goodIfTrue = true } = {}) {
  if (value === undefined || value === null) { set(id, t('v_unknown'), 'muted'); return; }
  set(id, value ? t('v_yes') : t('v_no'), value === goodIfTrue ? 'ok' : 'bad');
}

function tag(text, kind) {
  const element = document.createElement('span');
  element.className = 'tag' + (kind ? ' ' + kind : '');
  element.textContent = text;
  return element;
}

function skeletons() {
  document.querySelectorAll('#report .v').forEach(node => {
    node.className = 'v skeleton';
    node.textContent = '';
  });
  ['grade-caps', 'grade-warnings', 'mx-body', 'dkim-body', 'session-body', 'rdns-body',
    'spf-tree', 'spf-record', 'flag-list'].forEach(id => {
    const node = byId(id);
    if (node) node.innerHTML = '';
  });
  ['bar-authentication', 'bar-transport', 'bar-hygiene'].forEach(id => {
    const node = byId(id);
    if (node) node.style.width = '0';
  });
}

function toast(message) {
  const element = byId('toast');
  element.textContent = message;
  element.classList.add('show');
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => element.classList.remove('show'), 1900);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast(t('toast_copied'));
  } catch {
    const area = document.createElement('textarea');
    area.value = text;
    area.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(area);
    area.select();
    try { document.execCommand('copy'); toast(t('toast_copied')); }
    catch { toast(t('toast_copy_fail')); }
    area.remove();
  }
}

/* ================================================================== *
 * State
 * ================================================================== */

let REPORT = null;
let LAST_ERROR = null;
let TARGET = null;
let STREAM = null;

const STAGES = ['resolve', 'mx', 'spf', 'dkim', 'dmarc', 'mtasts', 'dane', 'starttls', 'grade'];

/* ================================================================== *
 * Running a check
 * ================================================================== */

function setProgress(stage) {
  const box = byId('progress');
  box.hidden = false;
  const index = Math.max(0, STAGES.indexOf(stage));
  byId('progress-fill').style.width = Math.round(((index + 1) / STAGES.length) * 100) + '%';
  byId('progress-label').textContent = tCode('stage', stage);
}

function checking(on) {
  byId('btn-scan').disabled = on;
  byId('btn-rescan').disabled = on;
  if (!on) byId('progress').hidden = true;
}

function startCheck(domain, { refresh = false } = {}) {
  if (!domain) return;
  TARGET = domain;
  REPORT = null;
  LAST_ERROR = null;

  if (STREAM) { STREAM.close(); STREAM = null; }

  byId('empty').hidden = true;
  byId('report').hidden = false;
  byId('alerts').innerHTML = '';
  byId('search-host').value = domain;
  byId('hero-host').textContent = domain;
  byId('hero-meta').innerHTML = '';
  byId('grade-badge').className = 'grade-badge pending';
  byId('grade-badge').textContent = '·';
  skeletons();
  checking(true);
  setProgress('resolve');
  updateSeoMeta();

  const url = `/api/stream/${encodeURIComponent(domain)}?lang=${encodeURIComponent(LANG)}${
    refresh ? '&refresh=1' : ''}`;
  const stream = new EventSource(url);
  STREAM = stream;

  stream.addEventListener('progress', event => {
    try { setProgress(JSON.parse(event.data).stage); }
    catch { /* a malformed frame is not worth breaking the check over */ }
  });

  stream.addEventListener('report', event => {
    try { REPORT = JSON.parse(event.data); }
    catch { LAST_ERROR = { error: 'bad-response' }; }
    stream.close();
    STREAM = null;
    checking(false);
    render();
  });

  stream.addEventListener('failed', event => {
    try { LAST_ERROR = JSON.parse(event.data); }
    catch { LAST_ERROR = { error: 'scan-failed' }; }
    stream.close();
    STREAM = null;
    checking(false);
    render();
  });

  stream.onerror = () => {
    if (REPORT || LAST_ERROR) return;
    stream.close();
    STREAM = null;
    LAST_ERROR = { error: 'network' };
    checking(false);
    render();
  };
}

/* ================================================================== *
 * Rendering the report
 * ================================================================== */

const GRADE_CLASS = grade => {
  if (!grade || grade === '?') return 'g-unknown';
  return 'g-' + grade[0].toLowerCase();
};

function renderGrade(report) {
  const badge = byId('grade-badge');
  badge.className = 'grade-badge ' + GRADE_CLASS(report.grade.grade);
  badge.textContent = report.grade.grade;

  for (const key of ['authentication', 'transport', 'hygiene']) {
    const component = report.grade.components?.[key];
    byId('bar-' + key).style.width = (component?.score ?? 0) + '%';
    set('score-' + key, component ? component.score : undefined);
  }
  set('score-total', report.grade.score);
  set('meta-queries', report.meta?.queries);
  set('meta-elapsed', report.meta?.elapsedMs ? report.meta.elapsedMs + ' ms' : undefined);

  const caps = byId('grade-caps');
  caps.innerHTML = '';
  for (const cap of report.grade.caps || []) {
    caps.appendChild(tag(`${cap.grade} · ${cap.label || tCode('cap', cap.reason)}`, 'bad'));
  }
  if (report.grade.reason) {
    caps.appendChild(tag(report.grade.reasonLabel || tCode('cap', report.grade.reason), 'warn'));
  }

  const warnings = byId('grade-warnings');
  warnings.innerHTML = '';
  (report.grade.warningLabels || report.grade.warnings || []).forEach(label =>
    warnings.appendChild(tag(label, 'warn')));
}

function renderMx(report) {
  const mx = report.mx || {};
  set('mx-count', mx.nullMx ? t('v_none') : mx.hosts?.length,
    mx.nullMx ? 'muted' : mx.hosts?.length ? 'ok' : 'bad');
  flagRow('mx-null', Boolean(mx.nullMx), { goodIfTrue: false });
  const ipv6 = (mx.hosts || []).filter(host => host.ipv6).length;
  set('mx-ipv6', mx.hosts?.length ? `${ipv6} / ${mx.hosts.length}` : undefined,
    ipv6 ? 'ok' : 'warn');

  const body = byId('mx-body');
  body.innerHTML = '';
  for (const host of mx.hosts || []) {
    const row = document.createElement('tr');
    row.innerHTML =
      `<td class="num">${host.preference}</td>` +
      `<td class="mono${host.addresses.length ? '' : ' weak'}">${esc(host.host)}` +
      `${host.alias ? ' <span class="legacy">(CNAME)</span>' : ''}</td>` +
      `<td class="mono">${esc(host.addresses.map(entry => entry.address).join(', ') || DASH)}</td>`;
    body.appendChild(row);
  }
}

function renderSpf(report) {
  const spf = report.spf || {};
  if (!spf.present) {
    set('spf-lookups', t('v_absent'), 'bad');
    set('spf-voids', undefined);
    set('spf-policy', undefined);
    byId('spf-record').innerHTML = '';
    byId('spf-tree').innerHTML = '';
    return;
  }

  const budget = spf.budget || {};
  set('spf-lookups', t('v_of_limit', { used: budget.lookups, limit: budget.limit }),
    budget.lookups > budget.limit ? 'bad' : budget.lookups >= budget.limit - 2 ? 'warn' : 'ok');
  set('spf-voids', t('v_of_limit', { used: budget.voids, limit: budget.voidLimit }),
    budget.voids > budget.voidLimit ? 'bad' : 'ok');
  set('spf-policy', spf.policyLabel || tCode('spfp', spf.policy),
    spf.policy === 'fail' ? 'ok' : spf.policy === 'pass' ? 'bad' : 'warn');

  const record = byId('spf-record');
  record.innerHTML = '';
  for (const text of spf.records || []) {
    const row = document.createElement('div');
    row.className = 'kv';
    row.innerHTML = `<span class="val">${esc(text)}</span>`;
    record.appendChild(row);
  }

  /* The expansion, as the tree a receiver walks. Terms past the tenth lookup
     are marked, because those are the ones that make the record a permerror. */
  const tree = byId('spf-tree');
  tree.innerHTML = '';
  const build = (node, into) => {
    for (const child of node.children || []) {
      const item = document.createElement('li');
      if (child.overLimit) item.className = 'bad';
      else if (child.problem || child.void) item.className = 'warn';
      const detail = [
        `#${child.lookupAt}`,
        child.problem ? tCode('spfterm', child.problem) : null,
        child.void ? t('v_none') : null,
      ].filter(Boolean).join(' · ');
      item.innerHTML =
        `<span class="label">${esc(child.term)}</span>` +
        `<div class="meta">${esc(detail)}</div>`;
      if (child.expanded?.children?.length) {
        const nested = document.createElement('ul');
        build(child.expanded, nested);
        item.appendChild(nested);
      }
      into.appendChild(item);
    }
  };
  if (spf.tree) build(spf.tree, tree);
}

function renderDkim(report) {
  const dkim = report.dkim || {};
  const keys = dkim.keys || [];
  set('dkim-count', keys.length || t('v_no_selector_found', { n: dkim.triedSelectors }),
    keys.length ? 'ok' : 'warn');
  set('dkim-tried', dkim.triedSelectors);

  const usable = keys.filter(key => !key.revoked && !key.malformed);
  const strongest = usable.reduce((best, key) => (!best || (key.bits ?? 0) > (best.bits ?? 0) ? key : best), null);
  set('dkim-strongest', strongest ? `${strongest.selector} · ${strongest.bits ?? DASH}` : undefined,
    (strongest?.bits ?? 0) >= 2048 ? 'ok' : strongest ? 'warn' : undefined);

  const body = byId('dkim-body');
  body.innerHTML = '';
  for (const key of keys) {
    const state = key.revoked ? t('v_absent') : key.malformed ? t('v_invalid')
      : key.testing ? 'testing' : t('v_ok');
    const kind = key.revoked || key.malformed ? 'weak' : key.testing ? 'legacy' : 'good';
    const row = document.createElement('tr');
    row.innerHTML =
      `<td class="mono">${esc(key.selector)}</td>` +
      `<td class="mono">${esc(key.keyType || DASH)}</td>` +
      `<td class="num${(key.bits ?? 0) < 1024 ? ' weak' : ''}">${key.bits ?? DASH}</td>` +
      `<td class="${kind}">${esc(state)}</td>`;
    body.appendChild(row);
  }
}

function renderDmarc(report) {
  const dmarc = report.dmarc || {};
  if (!dmarc.present) {
    set('dmarc-policy', t('v_absent'), 'bad');
    ['dmarc-sp', 'dmarc-pct', 'dmarc-align', 'dmarc-rua', 'dmarc-ruf', 'dmarc-external']
      .forEach(id => set(id, undefined));
    return;
  }

  set('dmarc-policy', dmarc.policyLabel || tCode('pol', dmarc.policy),
    dmarc.policy === 'reject' ? 'ok' : dmarc.policy === 'quarantine' ? 'warn' : 'bad');
  set('dmarc-sp', dmarc.subdomainPolicy ? tCode('pol', dmarc.subdomainPolicy) : undefined,
    dmarc.subdomainPolicy === 'none' ? 'warn' : undefined);
  set('dmarc-pct', t('v_percent', { n: dmarc.percent }), dmarc.percent === 100 ? 'ok' : 'warn');
  set('dmarc-align', `${dmarc.alignment?.dkim ?? '?'} / ${dmarc.alignment?.spf ?? '?'}`);
  set('dmarc-rua', (dmarc.rua || []).map(entry => entry.address || entry.uri));
  set('dmarc-ruf', (dmarc.ruf || []).map(entry => entry.address || entry.uri));

  const external = dmarc.externalAuthorisation || [];
  if (!external.length) {
    set('dmarc-external', t('v_not_checked'), 'muted');
  } else {
    const ok = external.filter(entry => entry.authorised).length;
    set('dmarc-external', `${ok} / ${external.length}`, ok === external.length ? 'ok' : 'bad');
  }
}

function renderTransport(report) {
  const starttls = report.starttls || {};
  const relay = (starttls.sessions || []).filter(entry => entry.port === 25 && entry.reachable);
  const withTls = relay.filter(entry => entry.starttls?.established);

  if (starttls.port25 && !starttls.port25.usable) {
    set('t-starttls', t('v_not_checked'), 'muted');
    set('t-port25', t('v_blocked_here'), 'warn');
  } else {
    set('t-starttls', relay.length ? `${withTls.length} / ${relay.length}` : t('v_unknown'),
      relay.length && withTls.length === relay.length ? 'ok' : relay.length ? 'bad' : 'muted');
    set('t-port25', t('v_ok'), 'ok');
  }

  const mtasts = report.mtasts || {};
  set('t-mtasts', mtasts.present ? t('v_present') : t('v_absent'), mtasts.present ? 'ok' : 'warn');
  set('t-mtasts-mode', mtasts.mode ? (mtasts.modeLabel || tCode('stsmode', mtasts.mode)) : undefined,
    mtasts.mode === 'enforce' ? 'ok' : mtasts.mode ? 'warn' : undefined);
  set('t-mtasts-id', mtasts.id);
  set('t-mtasts-maxage', mtasts.maxAge ? t('v_days_short', { n: Math.round(mtasts.maxAge / 86400) }) : undefined);

  const dane = report.dane || {};
  set('t-dane', dane.present ? t('v_present') : t('v_absent'), dane.present ? 'ok' : 'warn');
  set('t-dane-covered', dane.total ? `${dane.covered} / ${dane.total}` : undefined,
    dane.total && dane.covered === dane.total ? 'ok' : dane.covered ? 'warn' : undefined);

  set('t-tlsrpt', report.tlsrpt?.present ? t('v_present') : t('v_absent'),
    report.tlsrpt?.present ? 'ok' : 'warn');

  const relayOpen = (starttls.sessions || []).some(entry => entry.relay?.open);
  const relayChecked = (starttls.sessions || []).some(entry => entry.relay);
  set('t-relay', relayChecked ? (relayOpen ? t('v_yes') : t('v_no')) : t('v_not_checked'),
    relayChecked ? (relayOpen ? 'bad' : 'ok') : 'muted');
}

function renderSessions(report) {
  const body = byId('session-body');
  body.innerHTML = '';
  for (const session of report.starttls?.sessions || []) {
    const state = session.skipped ? t('v_blocked_here')
      : !session.reachable ? (session.error || t('v_no'))
      : session.starttls?.established ? (session.tls?.protocol || t('v_yes'))
      : session.starttls?.offered ? t('v_no') : t('v_absent');
    const kind = session.skipped ? 'legacy'
      : session.starttls?.established ? 'good'
      : session.reachable ? 'weak' : '';
    const announced = Object.keys(session.extensionsAfterTls || session.extensions || {});
    const row = document.createElement('tr');
    row.innerHTML =
      `<td class="mono">${esc(session.host)}</td>` +
      `<td class="num">${session.port}</td>` +
      `<td class="${kind}">${esc(state)}</td>` +
      `<td class="mono">${esc((session.banner || DASH).slice(0, 60))}</td>` +
      `<td class="mono">${esc(announced.slice(0, 8).join(' ') || DASH)}</td>`;
    body.appendChild(row);
  }
}

function renderRdns(report) {
  const body = byId('rdns-body');
  body.innerHTML = '';
  for (const entry of report.rdns?.entries || []) {
    const row = document.createElement('tr');
    row.innerHTML =
      `<td class="mono">${esc(entry.host)}</td>` +
      `<td class="mono">${esc(entry.address)}</td>` +
      `<td class="mono">${esc(entry.ptr?.[0] || DASH)}</td>` +
      `<td class="${entry.confirmed ? 'good' : 'weak'}">${
        esc(entry.statusLabel || tCode('rdns', entry.status))}</td>`;
    body.appendChild(row);
  }
}

function renderFlags(report) {
  const list = byId('flag-list');
  list.innerHTML = '';
  const flags = report.flags || [];
  if (!flags.length) {
    list.innerHTML = `<div class="empty-note">${esc(t('v_none'))}</div>`;
    return;
  }
  for (const finding of flags) {
    const where = finding.host || finding.selector || finding.target || finding.address || null;
    const item = document.createElement('div');
    item.className = 'finding';
    item.innerHTML =
      `<span class="sev sev-${esc(finding.severity)}">${
        esc(finding.severityLabel || tCode('sev', finding.severity))}</span>` +
      '<div class="body">' +
      `<div class="title">${esc(finding.name || tCode('flag', finding.id))}` +
      `${where ? ` <span class="where">${esc(where)}</span>` : ''}</div>` +
      `<div class="desc">${esc(finding.description || tCode('fd', finding.id))}</div>` +
      '</div>' +
      `<span class="state">${esc(finding.statusLabel || tCode('st', finding.status))}</span>`;
    list.appendChild(item);
  }
}

function renderAlerts(report) {
  const alerts = byId('alerts');
  alerts.innerHTML = '';
  if (!report?.incomplete?.length) return;

  const box = document.createElement('div');
  box.className = 'alert warn';
  const reasons = report.incompleteLabels || report.incomplete.map(code => tCode('inc', code));
  box.innerHTML =
    '<div class="alert-body">' +
    `<div class="alert-title">${esc(t('incomplete_title'))}</div>` +
    `<div>${esc(t('incomplete_body'))}</div>` +
    `<ul>${reasons.map(reason => `<li>${esc(reason)}</li>`).join('')}</ul>` +
    '</div>';
  alerts.appendChild(box);
}

function renderError() {
  const alerts = byId('alerts');
  alerts.innerHTML = '';
  const box = document.createElement('div');
  box.className = 'alert bad';
  const code = LAST_ERROR?.error || 'scan-failed';
  box.innerHTML = `<div class="alert-body"><div class="alert-title">${
    esc(LAST_ERROR?.message || tCode('err', code))}</div></div>`;
  alerts.appendChild(box);
  byId('grade-badge').className = 'grade-badge pending';
  byId('grade-badge').textContent = '·';
}

function render() {
  applyStaticText();
  if (LAST_ERROR) {
    renderError();
    return;
  }
  if (!REPORT) return;

  renderAlerts(REPORT);
  renderGrade(REPORT);
  renderMx(REPORT);
  renderSpf(REPORT);
  renderDkim(REPORT);
  renderDmarc(REPORT);
  renderTransport(REPORT);
  renderSessions(REPORT);
  renderRdns(REPORT);
  renderFlags(REPORT);

  const meta = byId('hero-meta');
  meta.innerHTML = '';
  const chips = [
    [REPORT.dmarc?.policy ? `DMARC ${REPORT.dmarc.policy}` : null,
      REPORT.dmarc?.enforcing ? 'ok' : 'warn'],
    [REPORT.spf?.present ? `SPF ${REPORT.spf.budget?.lookups}/${REPORT.spf.budget?.limit}` : null,
      REPORT.spf?.budget?.withinLimit ? 'ok' : 'bad'],
    [REPORT.mtasts?.present ? 'MTA-STS' : null, REPORT.mtasts?.mode === 'enforce' ? 'ok' : 'warn'],
    [REPORT.dane?.present ? 'DANE' : null, 'ok'],
  ];
  for (const [text, kind] of chips) {
    if (!text) continue;
    const chip = document.createElement('span');
    chip.className = 'chip' + (kind ? ' ' + kind : '');
    chip.textContent = text;
    meta.appendChild(chip);
  }

  byId('raw-json').textContent = JSON.stringify(REPORT, null, 2);
}

/* ================================================================== *
 * Static text, language switching, SEO
 * ================================================================== */

function applyStaticText() {
  document.documentElement.lang = LANG;
  document.documentElement.dir = RTL.has(LANG) ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-i18n]').forEach(node => {
    node.textContent = t(node.dataset.i18n);
  });
  byId('search-host').placeholder = t('ph_host');
  byId('search-host').setAttribute('aria-label', t('hero_label'));
  byId('lang').setAttribute('aria-label', t('lang_aria'));
  byId('api-hint').innerHTML = t('api_hint', {
    origin: location.origin, example: 'example.com',
  });
  if (!TARGET) byId('hero-host').textContent = t('no_target');
  if (!REPORT && !LAST_ERROR) {
    byId('grade-badge').textContent = '·';
  }
}

function updateSeoMeta() {
  const title = TARGET ? `${TARGET} — ${t('title_short')}` : t('title');
  document.title = title;
  for (const [id, value] of [
    ['meta-description', t('subtitle')], ['og-title', title], ['twitter-title', title],
    ['og-description', t('subtitle')], ['twitter-description', t('subtitle')],
  ]) {
    const node = byId(id);
    if (node) node.setAttribute('content', value);
  }
  const canonical = byId('link-canonical');
  if (canonical) canonical.href = location.origin + (TARGET ? '/' + encodeURIComponent(TARGET) : '/');
}

function buildLanguageSelect() {
  const select = byId('lang');
  select.innerHTML = '';
  for (const code of Object.keys(I18N)) {
    const option = document.createElement('option');
    option.value = code;
    option.textContent = window.LANG_NAMES?.[code] || code;
    if (code === LANG) option.selected = true;
    select.appendChild(option);
  }
  select.addEventListener('change', () => {
    LANG = select.value;
    try { localStorage.setItem(STORAGE_KEY, LANG); } catch { /* private mode */ }
    render();
    updateSeoMeta();
  });
}

function buildExamples() {
  const box = byId('examples');
  box.innerHTML = '';
  for (const domain of ['sharapov.biz', 'gmail.com', 'protonmail.com']) {
    const button = document.createElement('button');
    button.textContent = domain;
    button.addEventListener('click', () => go(domain));
    box.appendChild(button);
  }
}

/* ================================================================== *
 * Wiring
 * ================================================================== */

function go(domain) {
  const clean = String(domain || '').trim().toLowerCase();
  if (!clean) return;
  history.pushState({ domain: clean }, '', '/' + encodeURIComponent(clean));
  startCheck(clean);
}

byId('search-form').addEventListener('submit', event => {
  event.preventDefault();
  go(byId('search-host').value);
});

byId('btn-rescan').addEventListener('click', () => {
  if (TARGET) startCheck(TARGET, { refresh: true });
});

byId('btn-copy-json').addEventListener('click', () => {
  if (REPORT) copyText(JSON.stringify(REPORT, null, 2));
});

byId('btn-save-json').addEventListener('click', () => {
  if (!REPORT) return;
  const blob = new Blob([JSON.stringify(REPORT, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `mymx-${REPORT.domain}.json`;
  link.click();
  URL.revokeObjectURL(url);
});

window.addEventListener('popstate', () => {
  const path = decodeURIComponent(location.pathname.replace(/^\//, ''));
  if (path) startCheck(path);
});

buildLanguageSelect();
buildExamples();
applyStaticText();
updateSeoMeta();

const initial = decodeURIComponent(location.pathname.replace(/^\//, ''));
if (initial) startCheck(initial);
