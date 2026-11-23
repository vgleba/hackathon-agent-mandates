// Everything is put on the page as text, never as HTML.
'use strict';

const $ = (id) => document.getElementById(id);
let me;
let job = null;       // the job being set up
let choice = {};      // its blanks so far
let draft = null;     // what is being checked, kept on the server
let classList = {};   // names for the school and year chosen

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'checked' || k === 'value') el[k] = v;
    else if (v === true) el.setAttribute(k, '');
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  el.append(...children.flat().filter((c) => c != null && c !== false));
  return el;
}

async function api(path, body) {
  let res;
  try {
    res = await fetch(`/api/${path}`, body === undefined ? {} : {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    });
  } catch { throw new Error('Desk cannot be reached just now. Please try again in a moment.'); }
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) { signedOut(); throw new Error(''); }
  if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'That did not work. Please check it and try again.');
  return data;
}

function say(text) {
  $('message').textContent = text;
  $('message').hidden = !text;
  if (text) $('message').scrollIntoView({ block: 'nearest' });
}

async function busy(button, work) {
  say('');
  if (button) button.disabled = true;
  try { return await work(); } catch (e) { say(e.message); } finally { if (button) button.disabled = false; }
}

function signedOut() {
  $('desk').hidden = true;
  $('signout').hidden = true;
  $('hello').textContent = '';
  $('signed-out').hidden = false;
}

function step(name) {
  for (const s of ['ask', 'form', 'review']) $(`step-${s}`).hidden = s !== name;
  const heading = $(`step-${name}`).querySelector('h2');
  heading.focus({ preventScroll: true });
  heading.scrollIntoView({ block: 'start' });
}

// ---------------------------------------------------------------- 1. say it

function drawTiles() {
  $('tiles').replaceChildren(...Object.entries(me.jobs).map(([id, j]) => h('li', {},
    h('button', { type: 'button', onclick: () => open(id, {}) }, j.title, h('span', {}, j.about)))));
}

async function understand() {
  const got = await api('understand', { text: $('text').value });
  const ignored = got.ignored.length ? `I cannot give access to “${got.ignored.join('”, “')}”, so I have left that out. ` : '';
  if (!got.job) { $('say-note').textContent = ignored + got.ask; return; }
  $('say-note').textContent = '';
  open(got.job, got.choice, ignored + 'Please check what I have filled in, and fill in the rest.');
}

// ---------------------------------------------------------------- 2. fill the gaps

function open(id, known, note = '') {
  job = id;
  choice = { ...known };
  draft = null;
  $('form-title').textContent = me.jobs[id].title;
  $('form-about').textContent = me.jobs[id].about;
  $('form-note').textContent = note;
  $('form-note').hidden = !note;
  drawBlanks();
  step('form');
  if (!me.jobs[id].blanks.length) busy(null, check);
}

function radios(field, options, legend) {
  const set = h('fieldset', { id: `blank-${field}` }, h('legend', {}, legend));
  set.append(h('div', { class: 'options' }, Object.entries(options).map(([value, label]) => h('label', {},
    h('input', {
      type: 'radio', name: field, value, checked: String(choice[field]) === value,
      onchange: () => { choice[field] = field === 'year' ? Number(value) : value; changed(field); },
    }), label))));
  return set;
}

function select(field, options, label) {
  const box = h('select', { id: `input-${field}`, onchange: (e) => { choice[field] = e.target.value || undefined; changed(field); } },
    h('option', { value: '' }, 'Choose'), Object.entries(options).map(([value, text]) => h('option', { value }, text)));
  box.value = choice[field] ?? '';
  return h('div', { class: 'blank', id: `blank-${field}` }, h('label', { for: `input-${field}` }, label), box);
}

function tick(field, legend, label) {
  return h('fieldset', { id: `blank-${field}` }, h('legend', {}, legend), h('div', { class: 'options' }, h('label', {},
    h('input', { type: 'checkbox', checked: choice[field] === true, onchange: (e) => { choice[field] = e.target.checked; } }), label)));
}

function changed(field) {
  if (field === 'school' || field === 'year') { choice.pupils = undefined; loadClass(); }
  if (field === 'field') { choice.value = undefined; drawBlanks(); }
  if (field === 'split') { if (choice.split === 'school') choice.school = 'all'; drawBlanks(); }
}

async function loadClass() {
  classList = {};
  const wanted = `${choice.school}/${choice.year}`;
  if (me.jobs[job].blanks.includes('pupils') && choice.school && choice.year) {
    await busy(null, async () => {
      const got = await api('class', { school: choice.school, year: choice.year });
      if (wanted === `${choice.school}/${choice.year}`) classList = got.pupils;
    });
  }
  const old = $('blank-pupils');
  if (old) old.replaceWith(pupils());
}

function pupils() {
  const most = me.jobs[job].most;
  const set = h('fieldset', { id: 'blank-pupils' }, h('legend', {}, most > 1 ? 'Which pupils?' : 'Which pupil?'));
  const names = Object.entries(classList).sort((a, b) => a[1].localeCompare(b[1]));
  if (!choice.school || !choice.year) { set.append(h('p', { class: 'note' }, 'Choose the school and year group first.')); return set; }
  if (!names.length) { set.append(h('p', { class: 'note' }, 'There are no pupils in that year group this term.')); return set; }
  const picked = new Set(choice.pupils ?? []);
  const count = h('p', { class: 'note', 'aria-live': 'polite' });
  const list = h('div', { class: 'options names' });
  const update = () => {
    choice.pupils = [...picked];
    count.textContent = most > 1 ? `${picked.size} of ${names.length} chosen${most < names.length ? `, up to ${most}` : ''}` : '';
  };
  const boxes = names.map(([id, name]) => {
    const input = h('input', {
      type: most > 1 ? 'checkbox' : 'radio', name: 'pupil', checked: picked.has(id),
      onchange: () => { if (most === 1) picked.clear(); if (input.checked) picked.add(id); else picked.delete(id); update(); },
    });
    const label = h('label', {}, input, name);
    return { id, name, input, label };
  });
  list.append(...boxes.map((b) => b.label));
  const find = h('input', { type: 'search', id: 'find-name', placeholder: 'Type a name', oninput: () => {
    for (const b of boxes) b.label.hidden = !b.name.toLowerCase().includes(find.value.toLowerCase());
  } });
  set.append(h('label', { for: 'find-name' }, 'Find a name'), find, list, count);
  if (most >= names.length && most > 1) {
    set.append(h('button', { type: 'button', class: 'quiet', onclick: () => {
      const all = picked.size < boxes.length;
      for (const b of boxes) { b.input.checked = all; if (all) picked.add(b.id); else picked.delete(b.id); }
      update();
    } }, 'Choose all, or none'));
  }
  update();
  return set;
}

function drawBlanks() {
  const { options, questions, schools } = me;
  const make = {
    school: () => job === 'count' && choice.split === 'school' ? null
      : select('school', job === 'count' && me.every_school ? { all: 'All schools', ...schools } : schools, questions.school),
    year: () => radios('year', { 11: 'Year 11', 10: 'Year 10' }, questions.year),
    pupils,
    helper: () => tick('helper', questions.helper, 'Yes. A helper writes half, and can do nothing else'),
    value: () => choice.field ? radios('value', options.value[choice.field], questions.value) : null,
    reason: () => h('div', { class: 'blank', id: 'blank-reason' }, h('label', { for: 'input-reason' }, questions.reason),
      h('input', { type: 'text', id: 'input-reason', maxlength: 120, value: choice.reason ?? '', oninput: (e) => { choice.reason = e.target.value; } })),
    confirm: () => tick('confirm', questions.confirm, 'Yes, I need to see ethnicity and care status for the pupils I have named'),
    split: () => radios('split', me.every_school ? options.split : Object.fromEntries(Object.entries(options.split).filter(([k]) => k !== 'school')), questions.split),
  };
  const form = me.jobs[job].blanks.map((b) => (make[b] ?? (() => radios(b, options[b], questions[b])))()).filter(Boolean);
  $('blanks').replaceChildren(...form);
  if (choice.school && choice.year && !Object.keys(classList).length) loadClass();
}

async function check() {
  for (const old of document.querySelectorAll('.missing')) old.remove();
  const filled = Object.fromEntries(Object.entries(choice).filter(([, v]) => v !== undefined));
  const got = await api('check', { job, choice: filled });
  if (got.ask) {
    const where = $(`blank-${got.ask.field}`);
    if (!where) { say(got.ask.question); return; }
    where.prepend(h('p', { class: 'missing', role: 'alert' }, `Please answer this: ${got.ask.question}`));
    where.scrollIntoView({ block: 'center' });
    where.querySelector('input, select, button')?.focus({ preventScroll: true });
    return;
  }
  draft = got.draft;
  $('review-title').textContent = got.title;
  $('review').replaceChildren(...said(got.said));
  step('review');
}

function said(s) {
  const part = (kind, title, lines) => lines.length
    ? h('div', { class: `said ${kind}` }, h('h3', {}, title), h('ul', {}, lines.map((l) => h('li', {}, l)))) : null;
  return [part('can', 'It can', s.can), part('asks', 'It will ask you', s.asks), part('cannot', 'It cannot', s.cannot), part('limits', 'Limits', s.limits)].filter(Boolean);
}

async function start() {
  await api('start', { draft });
  draft = null;
  $('text').value = '';
  step('ask');
  await refresh();
  $('work').scrollIntoView({ block: 'start' });
}

// ---------------------------------------------------------------- waiting for you

let shownWaiting = '';
async function drawWaiting() {
  const { waiting } = await api('waiting');
  $('waiting').hidden = !waiting.length;
  document.title = waiting.length ? `(${waiting.length}) Desk` : 'Desk';
  const key = waiting.map((w) => w.id).join();
  if (key === shownWaiting) return;  // do not redraw under someone who is reading
  shownWaiting = key;
  $('waiting-list').replaceChildren(...waiting.map((w) => {
    const answer = (said) => (e) => busy(e.currentTarget, async () => { await api(`waiting/${w.id}`, { answer: said }); shownWaiting = ''; await refresh(); });
    return h('div', { class: 'card' },
      h('h3', {}, w.question), h('p', { class: 'note' }, `${w.job}. If you do nothing, it lapses at ${w.until} and nothing happens.`),
      w.problem ? h('p', { class: 'missing' }, w.problem) : null,
      w.change ? h('dl', { class: 'change' }, h('dt', {}, 'What'), h('dd', {}, w.change.what), h('dt', {}, 'Now'), h('dd', {}, w.change.now),
        h('dt', {}, 'It would become'), h('dd', {}, w.change.new), h('dt', {}, 'Reason given'), h('dd', {}, w.change.reason ?? '')) : null,
      w.letters ? letters(w.letters) : null,
      h('div', { class: 'row' }, h('button', { onclick: answer('approve') }, w.yes ?? 'Yes'), h('button', { class: 'quiet', onclick: answer('refuse') }, w.no ?? 'No')));
  }));
}

const letters = (list) => h('div', { class: 'letters', tabindex: 0, role: 'group', 'aria-label': 'Letters' },
  list.map((l) => h('div', { class: 'letter' }, h('strong', {}, l.name), l.letter)));

// ---------------------------------------------------------------- your assistants

const STATES = { working: 'Working', waiting: 'Waiting for you', done: 'Finished', stopped: 'Stopped', 'taken back': 'Taken back' };
const cards = new Map();

function drawResult(r) {
  if (!r) return null;
  const note = r.note ? h('p', { class: 'note' }, r.note) : null;
  if (r.kind === 'letters') {
    return h('div', {}, note, letters(r.letters), h('button', { class: 'quiet', onclick: (e) => busy(e.currentTarget, async () => {
      await navigator.clipboard.writeText(r.letters.map((l) => l.letter).join('\n\n---\n\n'));
      say('The letters are copied. You can paste them into a document.');
    }) }, 'Copy the letters'));
  }
  return h('div', {}, note, h('div', { class: 'scroll', tabindex: 0, role: 'group', 'aria-label': 'Results' }, h('table', {},
    h('thead', {}, h('tr', {}, r.columns.map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', {}, r.rows.map((row) => h('tr', {}, row.map((c) => h('td', {}, c))))))));
}

function workCard(j) {
  const seen = h('div', {});
  const act = (path) => (e) => busy(e.currentTarget, async () => { await api(`work/${j.id}/${path}`, {}); await refresh(); });
  return h('div', { class: 'card' },
    h('div', { class: 'row between' }, h('h3', {}, j.title), h('span', { class: `state ${j.state.replace(' ', '')}` }, STATES[j.state])),
    h('p', {}, j.note, j.ends ? `. Its access stops by ${j.ends}` : ''), j.helper ? h('p', { class: 'note' }, j.helper) : null,
    drawResult(j.result),
    h('details', {}, h('summary', {}, 'What it was allowed to do'), ...said(j.said)),
    h('div', { class: 'row' },
      j.running ? h('button', { class: 'stop', onclick: act('take-back') }, 'Take back access') : null,
      j.can_stop_helper ? h('button', { class: 'stop', onclick: act('stop-helper') }, 'Stop the helper') : null,
      h('button', { class: 'quiet', onclick: (e) => busy(e.currentTarget, async () => seen.replaceChildren(drawSeen(await api(`work/${j.id}/seen`)))) }, 'What did it see?')),
    seen);
}

function drawSeen(s) {
  const n = s.pupils.length;
  return h('div', { class: 'card' },
    h('p', {}, n ? `It saw information about ${n} pupil${n > 1 ? 's' : ''}.` : 'It saw no pupil’s information.'),
    h('p', {}, s.special.length ? `Special category information: ${s.special.join(', ')}.` : 'Special category information: none.'),
    s.kinds.length ? h('p', {}, `Kinds of information: ${s.kinds.join(', ')}.`) : null,
    s.refused ? h('p', {}, `It was refused ${s.refused} time${s.refused > 1 ? 's' : ''}.`) : null,
    n ? h('details', {}, h('summary', {}, 'Which pupils?'), h('ul', {}, s.pupils.map((p) => h('li', {}, p)))) : null,
    checked(s.complete));
}

const checked = (ok) => h('p', { class: ok ? 'checked' : 'checked no' }, ok
  ? '✓ Record checked: complete and unchanged' : '✕ The record does not match. Tell your data protection lead');

async function drawWork() {
  const { jobs, paused } = await api('work');
  $('work').hidden = !jobs.length;
  $('stop-all').hidden = !jobs.some((j) => j.running);
  if (paused) say('Your own access is paused, so your assistants are too.');
  const list = jobs.map((j) => {
    const key = JSON.stringify([j.state, j.note, j.helper, j.can_stop_helper]);
    const known = cards.get(j.id);
    if (known?.key === key) return known.card;
    const card = workCard(j);
    cards.set(j.id, { key, card });
    return card;
  });
  const now = [...$('work-list').children];
  if (list.length !== now.length || list.some((c, i) => c !== now[i])) $('work-list').replaceChildren(...list);
}

// ---------------------------------------------------------------- activity, alarms and handover

async function drawActivity() {
  const a = await api('activity');
  $('alarm').hidden = !a.alarms;
  return a;
}

async function showActivity() {
  const a = await drawActivity();
  $('activity-list').replaceChildren(checked(a.complete), h('ul', { class: 'lines' }, a.lines.length ? a.lines.map((l) => h('li', { class: l.alarm ? 'alarmed' : false },
    l.text, h('small', {}, `${l.when}. ${l.job}. From ${l.from}`))) : h('li', {}, 'Nothing yet.')));
  $('show-activity').textContent = 'Show the latest';
}

async function drawHandover() {
  const { jobs } = await api('handover');
  $('handover').hidden = !jobs.length;
  $('handover-list').replaceChildren(...jobs.map((j) => h('div', { class: 'card' },
    h('h3', {}, j.title), h('p', {}, `${j.from} has left, so this has stopped. Nothing was passed to you. You can start it afresh under your own access.`),
    h('button', { onclick: () => open(j.job, j.choice, 'This is filled in from the earlier job. Please check every answer.') }, 'Look at it'))));
}

async function refresh() { await Promise.all([drawWaiting(), drawWork()]); }

// ---------------------------------------------------------------- start

$('say').addEventListener('submit', (e) => { e.preventDefault(); busy(e.submitter, understand); });
$('blanks').addEventListener('submit', (e) => e.preventDefault());
$('form-next').addEventListener('click', (e) => busy(e.currentTarget, check));
$('start').addEventListener('click', (e) => busy(e.currentTarget, start));
$('stop-all').addEventListener('click', (e) => busy(e.currentTarget, async () => { await api('stop-everything', {}); await refresh(); }));
$('show-activity').addEventListener('click', (e) => busy(e.currentTarget, showActivity));
$('signout').addEventListener('click', (e) => busy(e.currentTarget, async () => { await api('signout', {}); signedOut(); }));
for (const b of document.querySelectorAll('[data-back]')) b.addEventListener('click', () => { say(''); step(b.dataset.back); });
for (const b of document.querySelectorAll('[data-go]')) b.addEventListener('click', () => busy(b, async () => { await showActivity(); $(b.dataset.go).scrollIntoView(); }));

busy(null, async () => {
  me = await api('me');
  $('hello').textContent = `Hello, ${me.name}`;
  $('desk').hidden = false;
  $('signout').hidden = false;
  drawTiles();
  await Promise.all([refresh(), drawActivity(), drawHandover()]);
  const quietly = (work) => async () => { if (!$('desk').hidden) try { await work(); } catch { /* the next one may work */ } };
  setInterval(quietly(refresh), 2500);
  setInterval(quietly(async () => { await drawActivity(); await drawHandover(); }), 15000);
});
