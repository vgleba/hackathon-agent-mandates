// Everything is put on the page as text (textContent), never as HTML.
'use strict';

const SIDES = ['before', 'after'];
const $ = (id) => document.getElementById(id);
let info;

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'onclick') el.addEventListener('click', v);
    else if (v === true) el.setAttribute(k, '');
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  el.append(...children.filter((c) => c != null && c !== false));
  return el;
}

async function api(path, body) {
  const res = await fetch(`/api/${path}`, body === undefined ? {} : {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`The lab answered ${res.status}. ${res.status === 422 ? 'Check the values you entered.' : 'Is it still running?'}`);
  return res.json();
}

async function busy(button, work) {
  $('error').hidden = true;
  if (button) button.disabled = true;
  try { return await work(); } catch (e) {
    $('error').textContent = e instanceof TypeError ? 'Could not reach the lab. Is “python -m lab” still running?' : e.message;
    $('error').hidden = false;
  } finally { if (button) button.disabled = false; }
}

// ---------------------------------------------------------------- what a reply means

const CHECKS = ['Genuine mandate', 'In date', 'Not taken back', 'Signed by its agent', 'Inside scope', 'Not too much', 'Person, purpose, sensitivity'];
const STOPS_AT = {
  WRONG_TOKEN_TYPE: 0, ISSUER_NOT_ACCREDITED: 0, SIG_INVALID: 0, MALFORMED_REQUEST: 0,
  NOT_YET_VALID: 1, EXPIRED: 1, REVOKED: 2, STATUS_UNAVAILABLE: 2, POP_FAILED: 3,
  DENIED_BY_RULE: 4, OUT_OF_SCOPE: 4, CONSTRAINT_MISSING: 4, CONSTRAINT_VIOLATED: 4,
  LIMIT_NOT_ALLOWED: 5, QUERY_TOO_BROAD: 5, BUDGET_EXCEEDED: 5, TOO_MANY_WAITING: 5, PATH_NOT_ALLOWED: 4,
  CHILD_WIDER: 0, CHILD_SIG_INVALID: 0, DELEGATION_NOT_ALLOWED: 0,
  PERSON_UNKNOWN: 6, PERSON_PAUSED: 6, PERSON_LOST_ACCESS: 6, PURPOSE_MISMATCH: 6, CLEARANCE_TOO_LOW: 6,
  CLAIM_NOT_UNDERSTOOD: 6, UNSAFE_GROUPING: 6, LABELS_UNAVAILABLE: 6,
};
const PLAIN = {
  IN_SCOPE: 'Every check passed.',
  WRONG_TOKEN_TYPE: 'That is not a mandate.',
  MALFORMED_REQUEST: 'The checks could not make sense of it, so the answer is no.',
  ISSUER_NOT_ACCREDITED: 'Signed by someone this gateway does not trust.',
  SIG_INVALID: 'The mandate has been altered.',
  NOT_YET_VALID: 'The mandate has not started yet.',
  EXPIRED: 'The mandate is out of date.',
  REVOKED: 'The person took this access back.',
  STATUS_UNAVAILABLE: 'Could not confirm it has not been taken back, so the answer is no.',
  POP_FAILED: 'Not freshly signed by the agent the mandate names.',
  DENIED_BY_RULE: 'The mandate says never to do this.',
  OUT_OF_SCOPE: 'The mandate does not include this tool.',
  CONSTRAINT_MISSING: 'The call left out something the mandate limits.',
  CONSTRAINT_VIOLATED: 'The mandate does not cover this school or file.',
  LIMIT_NOT_ALLOWED: 'Asked for too many records, or the limit was not a whole number.',
  QUERY_TOO_BROAD: 'The search does not narrow anything down.',
  PATH_NOT_ALLOWED: 'The file is written in a way that could mean another file.',
  CHILD_WIDER: 'The helper asks for more than its parent has.',
  CHILD_SIG_INVALID: 'Not made by the parent’s own key.',
  DELEGATION_NOT_ALLOWED: 'This access may not be handed on.',
  PERSON_PAUSED: 'The person who granted it has left or is away.',
  PERSON_LOST_ACCESS: 'The person who granted it does not cover that school.',
  PERSON_UNKNOWN: 'Nobody by that name may grant access.',
  PURPOSE_MISMATCH: 'That is not what the access was given for.',
  CLEARANCE_TOO_LOW: 'The data is too sensitive for this access.',
  UNSAFE_GROUPING: 'The count could single someone out.',
  BUDGET_EXCEEDED: 'It has seen as many pupils as the job needs.',
  SENSITIVE_TOOL: 'A person must approve it first.',
};

function outcome(r) {
  if (r.status >= 500) return r.upstream_error ? 'Data server refused it' : 'Crashed';
  if (r.decision === 'ALLOW') return 'Allowed';
  if (r.decision === 'DENY') return 'Refused';
  return r.decision ? 'Held for a person' : `HTTP ${r.status}`;
}

function checks(which, r) {
  const crashed = r.status >= 500 && !r.upstream_error;
  const stop = crashed ? 0 : STOPS_AT[r.reason];
  return h('ol', { class: 'steps', 'aria-label': 'Checks, in order' }, ...CHECKS.map((name, i) => {
    const missing = which === 'before' && i >= 5;  // the original gateway has none of these
    const state = missing ? 'none' : stop === undefined ? 'ok' : i < stop ? 'ok' : i === stop ? 'stop' : '';
    const label = missing ? `${name}: no check` : state === 'stop' ? `✕ ${crashed ? 'Crashed here' : name}` : state === 'ok' ? `✓ ${name}` : name;
    return h('li', { class: state }, label);
  }));
}

function pupilSquares(released, total) {
  const box = h('div', { class: 'dots', role: 'img', 'aria-label': `${released} of ${total} pupils released` });
  for (let i = 0; i < total; i++) box.append(h('i', { class: i < released ? 'on' : false }));
  return box;
}

function side(which, r, { total, verdict, showChecks = true } = {}) {
  const facts = [];
  if (r.pupils && r.sensitive.length) facts.push(`Sensitive columns released: ${r.sensitive.join(', ')}${r.named ? ', with the pupil’s name' : ''}`);
  if (r.volume?.trimmed) facts.push(`Cut short at ${r.volume.returned_rows} rows, and the reply says so`);
  if (r.reason) facts.push(`${r.reason}, HTTP ${r.status}`);
  else if (r.status) facts.push(`HTTP ${r.status}`);
  if (r.policy) facts.push(`Answered by policy ${r.policy}`);
  return h('article', { class: `side ${which}` },
    h('header', {}, h('span', {}, h('i', { 'aria-hidden': 'true' }), which === 'before' ? 'Before' : 'After'),
      verdict === undefined ? null : h('span', { class: `verdict ${verdict ? 'good' : 'bad'}` }, verdict ? '✓ Right answer' : '✕ Wrong answer')),
    h('p', { class: 'outcome' }, r.outcome ?? outcome(r)),
    h('p', { class: 'why' }, r.text ? r.text : r.status >= 500 && !r.upstream_error ? 'The check broke instead of answering.' : PLAIN[r.reason] ?? ''),
    total ? h('div', { class: 'figure' }, h('b', {}, String(r.pupils)), h('span', {}, `of ${total} pupils released`)) : null,
    total ? pupilSquares(r.pupils, total) : null,
    showChecks ? checks(which, r) : null,
    h('ul', { class: 'facts' }, ...facts.map((f) => h('li', {}, f))));
}

const pair = (make) => h('div', { class: 'pair' }, ...SIDES.map(make));

// ---------------------------------------------------------------- overview

async function drawHero() {
  const r = await api('search', { urn: 'SCH02', query: '', limit: 1000 });
  $('hero').replaceChildren(...SIDES.map((s) => side(s, r[s], { total: r.school.pupils, verdict: s === 'after' ? r.after.pupils === 0 : r.before.pupils === 0 })));
}

async function drawScore() {
  const score = await api('scoreboard', {});
  const cell = (s) => {
    const full = s.passed === s.total;
    return h('td', { class: 'num' }, h('span', { class: `mark ${full ? 'good' : 'bad'}`, 'aria-hidden': 'true' }, full ? '✓' : '✕'), `${s.passed} of ${s.total}`);
  };
  const rows = Object.entries(info.questions).map(([q, ask]) => {
    return h('tr', {}, h('td', {}, `${q}`), h('td', {}, ask),
      cell(score.before[q]), cell(score.after[q]));
  });
  const sum = (s) => Object.values(s).reduce((a, x) => ({ passed: a.passed + x.passed, total: a.total + x.total }), { passed: 0, total: 0 });
  rows.push(h('tr', {}, h('td', {}), h('td', {}, h('strong', {}, 'All cases')), cell(sum(score.before)), cell(sum(score.after))));
  $('score').replaceChildren(
    h('thead', {}, h('tr', {}, ...['No.', 'What the administrator asks', 'Before', 'After'].map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', {}, ...rows));
}

// ---------------------------------------------------------------- the eval's cases

function caseCard(c) {
  const out = h('div', { 'aria-live': 'polite' });
  const run = async () => {
    const r = await api(`cases/${c.id}`, {});
    const urn = c.tool === 'search' && c.arguments.urn;
    const total = urn && info.schools[urn] ? info.schools[urn].pupils : null;
    const days = Math.round((r.claims.exp - r.claims.iat) / 8640) / 10;
    out.replaceChildren(
      pair((s) => side(s, r[s], { total, verdict: r[s].passed })),
      h('details', {}, h('summary', {}, 'The mandate it used'),
        h('p', { class: 'note' }, r.claims.exp * 1000 < Date.now()
          ? `Expired ${new Date(r.claims.exp * 1000).toLocaleString()}.`
          : `Valid for ${days} days, until ${new Date(r.claims.exp * 1000).toLocaleString()}. Revocation index ${r.claims.status_idx}.`),
        h('pre', { class: 'diff' }, ...JSON.stringify({ scope: r.claims.scope, deny: r.claims.deny }, null, 2).split('\n').map((l) => h('span', {}, l)))));
  };
  const button = h('button', { class: 'quiet', onclick: () => busy(button, run) }, 'Run');
  const card = h('div', { class: 'case' }, h('div', { class: 'row' },
    h('div', {}, h('strong', {}, c.name), h('code', {}, `${c.tool} ${JSON.stringify(c.arguments)}`)),
    h('span', { class: 'note' }, `should be ${c.expected === 'ALLOW' ? 'allowed' : 'refused'}`), button), out);
  return { card, run, button };
}

function drawCases() {
  for (const box of document.querySelectorAll('.cases')) {
    const cards = info.cases.filter((c) => c.question === Number(box.dataset.question)).map(caseCard);
    const all = h('button', { onclick: () => busy(all, async () => { for (const c of cards) await c.run(); }) }, `Run all ${cards.length}`);
    box.replaceChildren(h('div', {}, all), ...cards.map((c) => c.card));
  }
  for (const el of document.querySelectorAll('[data-ask]')) el.textContent = `“${info.questions[el.dataset.ask]}”`;
}

// ---------------------------------------------------------------- question 1: take it back

async function takeBack() {
  const r = await api('take-back', {});
  $('takeback-out').replaceChildren(
    h('p', { class: 'spaced' }, `1. Granted: search at Ashfield for 10 minutes (revocation index ${r.idx}).`),
    h('p', {}, '2. Used:'), pair((s) => side(s, r.used[s], { verdict: r.used[s].decision === 'ALLOW' })),
    h('p', {}, '3. Taken back. 4. Tried again with the same mandate and the same key:'),
    pair((s) => side(s, r.retried[s], { verdict: r.retried[s].reason === 'REVOKED' })));
}

// ---------------------------------------------------------------- question 3: the playground

const PRESETS = [
  ['Blank', '', '1000', 'number'], ['A comma', ',', '100', 'number'], ['The letter P', 'P', '100', 'number'],
  ['The school’s own code', 'sch01', '', 'number'], ['A hidden value', 'ASIA', '', 'number'], ['Limit sent as text', 'SPR', '1000', 'text'],
  ['Summer census', 'SUM', '', 'number'], ['Spring census', 'SPR', '', 'number'], ['One pupil', 'P0004', '', 'number'],
];

async function play() {
  const limit = $('play-limit').value.trim();
  const body = { urn: $('play-urn').value, query: $('play-query').value };
  if (limit !== '') {
    body.limit = $('play-kind').value === 'text' ? limit : Number(limit);
    if ($('play-kind').value === 'number' && !Number.isInteger(body.limit)) throw new Error('To send a number, the limit must be a whole number. Or send it as text.');
  }
  const r = await api('search', body);
  $('play-out').replaceChildren(
    h('p', { class: 'note' }, h('code', {}, `search ${JSON.stringify(r.arguments)}`)),
    pair((s) => side(s, r[s], { total: r.school.pupils })));
}

// ---------------------------------------------------------------- the open questions, 6 to 16

function drawOpen() {
  $('open-list').replaceChildren(...Object.entries(info.open).map(([q, [ask, core]]) => {
    const out = h('div', { 'aria-live': 'polite' });
    const run = async () => {
      const d = await api(`demos/${q}`, {});
      out.replaceChildren(
        h('details', {}, h('summary', {}, 'The mandate'),
          h('pre', { class: 'diff' }, ...JSON.stringify(d.mandate, null, 2).split('\n').map((l) => h('span', {}, l)))),
        ...d.steps.map((s) => h('div', {}, h('h4', {}, s.label), pair((w) => side(w, s[w], { verdict: s[w].good, showChecks: !!s[w].reason })))),
        h('p', { class: 'note' }, h('strong', {}, 'Still unresolved. '), d.unresolved));
    };
    const button = h('button', { class: 'quiet', id: `demo-${q}`, onclick: () => busy(button, run) }, 'Show it');
    return h('div', { class: 'case', id: `open-${q}` }, h('div', { class: 'row' },
      h('div', {}, h('strong', {}, `${q}. “${ask}”`), h('span', { class: 'note' }, core)), button), out);
  }));
}

function drawPlayground() {
  $('play-urn').replaceChildren(...Object.entries(info.schools).map(([urn, s]) => h('option', { value: urn }, `${s.name} (${urn})`)));
  $('presets').replaceChildren(...PRESETS.map(([label, query, limit, kind]) => h('button', {
    class: 'quiet', type: 'button', onclick: (e) => {
      $('play-urn').value = 'SCH01'; $('play-query').value = query; $('play-limit').value = limit; $('play-kind').value = kind;
      busy(e.currentTarget, play);
    },
  }, label)));
  $('play').addEventListener('submit', (e) => { e.preventDefault(); busy(e.submitter, play); });
  const { pupils, rows, blanket_percent: share } = info.limits;
  $('layers').replaceChildren(
    ...[['Ask for something', `No blank searches. A limit must be a whole number from 1 to ${rows}. Decided before any data is read.`],
      ['Narrow something down', `A search matching ${share}% of the records it could see is refused, however it is worded.`],
      ['Never more than a few', `At most ${pupils} pupils leave in one call, whatever the query. Anything cut short says so.`],
    ].map(([a, b]) => h('li', {}, h('strong', {}, a), h('span', {}, b))));
}

// ---------------------------------------------------------------- attacks

async function attack(name) {
  const r = await api(`attacks/${name}`, {});
  $(`attack-${name}`).replaceChildren(pair((s) => {
    if (name === 'junk') return side(s, r[s], { verdict: r[s].status === 403 });
    if (r[s].minted) return side(s, r[s], { verdict: r[s].pupils === 0, showChecks: false });
    return h('article', { class: `side ${s}` },
      h('header', {}, h('span', {}, h('i', { 'aria-hidden': 'true' }), s === 'before' ? 'Before' : 'After'),
        h('span', { class: 'verdict good' }, '✓ Right answer')),
      h('p', { class: 'outcome' }, 'No such route'),
      h('p', { class: 'why' }, 'No mandate was made and nothing was released.'),
      h('ul', { class: 'facts' }, h('li', {}, `HTTP ${r[s].status}`)));
  }));
}

// ---------------------------------------------------------------- what changed

function drawChanges() {
  $('baseline').textContent = info.baseline;
  $('change-list').replaceChildren(...info.changes.map((c) => h('div', { class: 'panel' },
    h('h3', {}, c.title), h('p', { class: 'note' }, `Question ${c.question}`), h('p', {}, c.why),
    ...Object.entries(c.diffs).map(([file, diff]) => h('details', {}, h('summary', {}, h('code', {}, file)),
      h('pre', { class: 'diff' }, ...diff.split('\n').map((line) => h('span', {
        class: line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++') ? 'at' : line.startsWith('+') ? 'add' : line.startsWith('-') ? 'del' : false,
      }, line || ' '))))))));
}

// ---------------------------------------------------------------- tabs and start-up

const tabs = [...document.querySelectorAll('[role=tab]')];
function show(id) {
  const tab = tabs.find((t) => t.getAttribute('aria-controls') === id) ?? tabs[0];
  for (const t of tabs) {
    const on = t === tab;
    t.setAttribute('aria-selected', String(on));
    t.tabIndex = on ? 0 : -1;
    $(t.getAttribute('aria-controls')).hidden = !on;
  }
  $('error').hidden = true;
}
for (const [i, t] of tabs.entries()) {
  t.addEventListener('click', () => { location.hash = t.getAttribute('aria-controls'); });
  t.addEventListener('keydown', (e) => {
    const step = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
    if (!step) return;
    const next = tabs[(i + step + tabs.length) % tabs.length];
    next.focus();
    next.click();
  });
}
window.addEventListener('hashchange', () => show(location.hash.slice(1)));

async function drawHealth() {
  const names = { before: 'gateway before', after: 'gateway after', 'data server': 'data server' };
  let up = {};
  try { up = await api('health'); } catch { /* shown as stopped */ }
  $('health').replaceChildren(...Object.entries(names).map(([k, label]) => h('li', {},
    h('span', { class: `mark ${up[k] ? 'good' : 'bad'}`, 'aria-hidden': 'true' }, up[k] ? '✓' : '✕'), `${label} ${up[k] ? 'running' : 'stopped'}`)));
}

show(location.hash.slice(1));
busy(null, async () => {
  info = await api('info');
  drawCases(); drawPlayground(); drawOpen(); drawChanges();
  $('takeback').addEventListener('click', (e) => busy(e.currentTarget, takeBack));
  for (const b of document.querySelectorAll('[data-attack]')) b.addEventListener('click', () => busy(b, () => attack(b.dataset.attack)));
  $('rescore').addEventListener('click', (e) => busy(e.currentTarget, drawScore));
  await Promise.all([drawHealth(), drawHero(), drawScore()]);
  setInterval(drawHealth, 10000);
});
