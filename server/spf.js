/**
 * SPF, expanded the way a receiving server expands it.
 *
 * The check that matters, and that almost nothing shows properly, is the
 * lookup budget. RFC 7208 §4.6.4 allows a record ten DNS-querying terms —
 * `include`, `a`, `mx`, `ptr`, `exists` and the `redirect` modifier — counted
 * across the *whole* evaluation, following every include into every include.
 * Past ten, a receiver must return `permerror`, and a permerror means SPF
 * simply does not apply: the mail is judged as if there were no record at all.
 *
 * This is easy to exceed and invisible from the record itself. `include:_spf.
 * google.com` looks like one lookup and is four. Add a CRM, a newsletter tool,
 * a helpdesk and a payment provider and a domain is over the limit without
 * anybody having written anything obviously wrong — and the failure is silent,
 * because everything keeps arriving until the day a receiver starts enforcing.
 *
 * So the expansion is shown as a tree with the running count, and the terms
 * that pushed it over are marked.
 */

import { TYPE } from '@sharapov/dns-wire';
import { flag } from '@sharapov/service-kit';

/** RFC 7208 §4.6.4. */
const LOOKUP_LIMIT = 10;
const VOID_LIMIT = 2;

const QUALIFIERS = { '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' };
const QUERYING = new Set(['include', 'a', 'mx', 'ptr', 'exists']);

const strip = value => String(value || '').toLowerCase().replace(/\.$/, '');

/** Splits a record into mechanisms and modifiers, keeping the order. */
export function parseSpf(text) {
  const terms = [];
  const problems = [];
  const words = String(text).trim().split(/\s+/);

  if (!/^v=spf1$/i.test(words[0] || '')) {
    return { terms, problems: ['not-an-spf-record'] };
  }

  for (const word of words.slice(1)) {
    const modifier = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(word);
    if (modifier) {
      terms.push({ kind: 'modifier', name: modifier[1].toLowerCase(), value: modifier[2] });
      continue;
    }

    const mechanism = /^([+\-~?]?)([a-z0-9]+)(?::([^/]*))?(\/\d{1,3}(?:\/\/\d{1,3})?)?$/i.exec(word);
    if (!mechanism) {
      problems.push(`unparsable term: ${word}`);
      continue;
    }
    terms.push({
      kind: 'mechanism',
      qualifier: mechanism[1] || '+',
      name: mechanism[2].toLowerCase(),
      value: mechanism[3] || null,
      cidr: mechanism[4] || null,
      raw: word,
    });
  }

  return { terms, problems };
}

/** Every `v=spf1` TXT record published at a name. */
async function spfRecordsAt(session, name) {
  const response = await session.ask({ name, type: 'TXT', dnssec: true });
  if (!response?.message) return { failed: true, records: [] };
  const records = response.message.answers
    .filter(record => record.type === TYPE.TXT)
    // `text` is the concatenation of the character-strings, which is what the
    // record actually says; joining them any other way corrupts long records.
    .map(record => record.data.text)
    .filter(text => /^v=spf1(\s|$)/i.test(text.trim()));
  return { failed: false, records, empty: !response.message.answers.length };
}

/**
 * Walks the record, following includes and redirects, counting as it goes.
 *
 * @returns {object} the tree, the totals, and everything worth saying about it
 */
export async function inspectSpf(session, domain) {
  const flags = [];
  const budget = { lookups: 0, voids: 0, overLimitAt: null };
  const visited = new Set();

  const top = await spfRecordsAt(session, domain);
  if (top.failed) {
    return { present: null, incomplete: ['spf-lookup-failed'], flags, budget, tree: null };
  }

  if (!top.records.length) {
    flags.push(flag('spf-missing', 'high', 'missing', {}));
    return { present: false, records: [], budget, tree: null, flags };
  }

  if (top.records.length > 1) {
    /* Two records is not "one wins". RFC 7208 §4.5 makes it a permerror, and
       a permerror means no SPF result at all — usually the exact opposite of
       what whoever added the second record intended. */
    flags.push(flag('spf-multiple-records', 'critical', 'failed', { count: top.records.length }));
  }

  const record = top.records[0];
  const tree = await expand(session, domain, record, { budget, visited, depth: 0, flags });

  /* ---------------- the budget ---------------- */
  if (budget.lookups > LOOKUP_LIMIT) {
    flags.push(flag('spf-too-many-lookups', 'critical', 'failed', {
      lookups: budget.lookups, limit: LOOKUP_LIMIT, exceededAt: budget.overLimitAt,
    }));
  } else if (budget.lookups >= LOOKUP_LIMIT - 2) {
    flags.push(flag('spf-lookups-near-limit', 'medium', 'warning', {
      lookups: budget.lookups, limit: LOOKUP_LIMIT,
    }));
  }
  if (budget.voids > VOID_LIMIT) {
    flags.push(flag('spf-too-many-void-lookups', 'high', 'failed', {
      voids: budget.voids, limit: VOID_LIMIT,
    }));
  }

  /* ---------------- the policy itself ---------------- */
  const { terms } = parseSpf(record);
  const all = [...terms].reverse().find(term => term.kind === 'mechanism' && term.name === 'all');
  const redirect = terms.find(term => term.kind === 'modifier' && term.name === 'redirect');

  if (!all && !redirect) {
    flags.push(flag('spf-no-all', 'high', 'warning', {}));
  } else if (all) {
    if (all.qualifier === '+') {
      // "+all" authorises the entire internet to send as this domain. It is
      // almost always a misunderstanding of what the qualifier means.
      flags.push(flag('spf-plus-all', 'critical', 'failed', {}));
    } else if (all.qualifier === '?') {
      flags.push(flag('spf-neutral-all', 'medium', 'warning', {}));
    } else if (all.qualifier === '~') {
      flags.push(flag('spf-softfail-all', 'info', 'info', {}));
    }
  }

  if (terms.some(term => term.kind === 'mechanism' && term.name === 'ptr')) {
    // RFC 7208 §5.5 deprecates it outright: slow, unreliable, and a burden on
    // whoever runs the reverse zone.
    flags.push(flag('spf-uses-ptr', 'medium', 'warning', {}));
  }

  const unknown = terms.filter(term => term.kind === 'mechanism' &&
    !['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists'].includes(term.name));
  if (unknown.length) {
    flags.push(flag('spf-unknown-mechanism', 'high', 'failed',
      { terms: unknown.map(term => term.raw) }));
  }

  const modifiers = terms.filter(term => term.kind === 'modifier');
  if (modifiers.filter(term => term.name === 'redirect').length > 1) {
    flags.push(flag('spf-duplicate-redirect', 'high', 'failed', {}));
  }
  if (redirect && all) {
    // A `redirect` after an `all` is never reached — `all` always matches.
    flags.push(flag('spf-redirect-after-all', 'medium', 'warning', {}));
  }

  if (record.length > 450) {
    flags.push(flag('spf-record-long', 'info', 'info', { bytes: record.length }));
  }

  return {
    present: true,
    record,
    records: top.records,
    terms,
    tree,
    budget: {
      lookups: budget.lookups,
      limit: LOOKUP_LIMIT,
      voids: budget.voids,
      voidLimit: VOID_LIMIT,
      withinLimit: budget.lookups <= LOOKUP_LIMIT && budget.voids <= VOID_LIMIT,
    },
    policy: all ? QUALIFIERS[all.qualifier] : redirect ? 'redirect' : null,
    flags,
  };
}

/**
 * One record, expanded. Recursion is bounded by the lookup budget itself and by
 * a visited set, because `include` loops exist in the wild and a receiver that
 * followed one would never finish.
 */
async function expand(session, name, record, context, mechanismLabel = null) {
  const { budget, visited, depth, flags } = context;
  const { terms, problems } = parseSpf(record);
  const node = {
    name,
    via: mechanismLabel,
    record,
    lookupsBefore: budget.lookups,
    children: [],
    problems,
  };

  if (depth > 12) {
    node.problems.push('nesting-too-deep');
    return node;
  }

  for (const term of terms) {
    const isRedirect = term.kind === 'modifier' && term.name === 'redirect';
    if (term.kind === 'mechanism' && !QUERYING.has(term.name)) continue;
    if (term.kind === 'modifier' && !isRedirect) continue;

    budget.lookups++;
    if (budget.lookups > 10 && budget.overLimitAt === null) {
      budget.overLimitAt = term.raw || `${term.name}=${term.value}`;
    }

    const target = isRedirect
      ? strip(term.value)
      : strip(term.value || (term.name === 'include' ? '' : name));

    const child = {
      term: term.raw || `${term.name}=${term.value}`,
      mechanism: term.name,
      target: target || name,
      lookupAt: budget.lookups,
      overLimit: budget.lookups > 10,
    };

    if (term.name === 'include' || isRedirect) {
      if (!target) {
        child.problem = 'no-target';
        node.children.push(child);
        continue;
      }
      if (visited.has(target)) {
        child.problem = 'loop';
        flags.push(flag('spf-include-loop', 'high', 'failed', { target }));
        node.children.push(child);
        continue;
      }
      visited.add(target);

      const nested = await spfRecordsAt(session, target);
      if (nested.failed || !nested.records.length) {
        budget.voids++;
        child.problem = nested.failed ? 'lookup-failed' : 'no-spf-record';
        // An include that resolves to nothing is a permerror in its own right
        // (RFC 7208 §5.2), not merely a wasted lookup.
        if (!nested.failed) {
          flags.push(flag('spf-include-without-record', 'high', 'failed', { target }));
        }
        node.children.push(child);
        continue;
      }
      if (nested.records.length > 1) {
        flags.push(flag('spf-multiple-records', 'critical', 'failed',
          { domain: target, count: nested.records.length }));
      }

      const subtree = await expand(session, target, nested.records[0],
        { ...context, depth: depth + 1 }, child.term);
      child.expanded = subtree;
      node.children.push(child);
      continue;
    }

    /* `a`, `mx`, `ptr` and `exists` cost a lookup each; the void limit counts
       the ones that come back with nothing.

       A target containing a macro — `exists:%{i}._spf.example.com` is the
       common one — expands per connection, using the sending address. It
       cannot be evaluated here at all, so it costs its lookup and is left at
       that. Querying the literal name with `%{i}` still in it would always come
       back empty and would push perfectly healthy records over the void
       limit. */
    if (/%\{/.test(target)) {
      child.macro = true;
      node.children.push(child);
      continue;
    }

    const type = term.name === 'mx' ? 'MX' : term.name === 'ptr' ? 'PTR' : 'A';
    const response = await session.ask({ name: target || name, type });
    const found = (response?.message?.answers || []).length;
    if (!found) {
      budget.voids++;
      child.void = true;
    }
    child.answers = found;
    node.children.push(child);
  }

  node.lookupsAfter = budget.lookups;
  return node;
}
