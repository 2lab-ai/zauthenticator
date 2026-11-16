// The account list: rows, live codes, copy on click, search, and delete in edit mode.
import * as totp from '../lib/totp.js';
import * as session from './session.js';
import { t } from './i18n.js';
import { $, announce, setText, reason } from './ui.js';
import { groupCode, matchesQuery, displayName, text } from './format.js';

const COPIED_MS = 1500;
const CONFIRM_MS = 4000;
const NOTICE_MS = 5000;
const EXPIRING_SECONDS = 5;

export function createListView() {
  const listEl = $('#accounts');
  const template = $('#account-template');
  const searchEl = $('#search');
  const emptyEl = $('#empty');
  const noMatchesEl = $('#no-matches');
  const noticeEl = $('#list-notice');
  const editBtn = $('#edit-btn');

  let rows = new Map(); // account id → row
  let timer = null;
  let renderToken = 0;
  let noticeTimer = 0;

  listEl.addEventListener('click', (event) => {
    const rowEl = event.target.closest('.account');
    const row = rowEl && rows.get(rowEl.dataset.id);
    if (!row) return;
    if (event.target.closest('.delete')) {
      deleteClicked(row);
    } else {
      copy(row);
    }
  });

  listEl.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && listEl.querySelector('.account.confirming')) {
      event.stopPropagation();
      disarmAll();
    }
  });

  searchEl.addEventListener('input', applyFilter);
  searchEl.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      const first = [...rows.values()].find((row) => !row.el.hidden);
      if (first) copy(first);
    } else if (event.key === 'Escape' && searchEl.value) {
      event.stopPropagation();
      searchEl.value = '';
      applyFilter();
    }
  });

  editBtn.addEventListener('click', () => setEditing(!document.body.classList.contains('editing')));

  // Builds the rows and computes every code before resolving, so the list never shows
  // a row without its code.
  async function render() {
    const token = ++renderToken;
    const gen = session.generation();
    const accounts = session.accounts();
    const next = new Map();
    const fragment = document.createDocumentFragment();
    for (const account of accounts) {
      const row = buildRow(account);
      next.set(account.id, row);
      fragment.append(row.el);
    }
    const now = Date.now();
    await Promise.all([...next.values()].map((row) => updateCode(row, now)));
    // A later render took over, or the session locked meanwhile (another page's lock can land
    // before this page's clear()): these rows never reach the page.
    if (token !== renderToken || session.generation() !== gen) return;

    for (const row of rows.values()) clearRowTimers(row);
    rows = next;
    listEl.replaceChildren(fragment);
    for (const row of rows.values()) paint(row, now);

    const empty = accounts.length === 0;
    emptyEl.hidden = !empty;
    document.body.classList.toggle('no-accounts', empty);
    if (empty) setEditing(false);
    applyFilter();
  }

  function buildRow(account) {
    const el = template.content.firstElementChild.cloneNode(true);
    el.dataset.id = text(account.id);
    // Issuer and label come from scanned QR codes / pasted links: text only, never markup.
    // text() also turns a non-string field of a hand-edited vault into '' instead of throwing.
    setText(el.querySelector('.issuer'), text(account.issuer));
    setText(el.querySelector('.label'), text(account.label));
    const main = el.querySelector('.account-main');
    main.title = t('copyHint');
    const deleteEl = el.querySelector('.delete');
    deleteEl.setAttribute('aria-label', t('deleteLabel', displayName(account)));
    return {
      account,
      el,
      deleteEl,
      codeEl: el.querySelector('.code'),
      remainingEl: el.querySelector('.remaining'),
      barEl: el.querySelector('.countdown'),
      counter: null,
      copiedTimer: 0,
      confirmTimer: 0,
    };
  }

  function periodOf(account) {
    const period = Number(text(account.period));
    return Number.isInteger(period) && period > 0 ? period : 30;
  }

  // Computes the code at `now` and shows it, unless a later update took over the row or the
  // session locked meanwhile. Resolves to the code at `now` either way ('' for an invalid key).
  async function updateCode(row, now) {
    const gen = session.generation();
    const counter = Math.floor(now / 1000 / periodOf(row.account));
    row.counter = counter;
    let code = '';
    try {
      code = await totp.totp(row.account, now);
    } catch {
      // Invalid stored key: shown as "Invalid key" below.
    }
    if (row.counter !== counter || session.generation() !== gen) return code;
    row.codeEl.dataset.code = code;
    row.codeEl.textContent = code ? groupCode(code) : t('codeUnavailable');
    row.el.classList.toggle('invalid', !code);
    return code;
  }

  function paint(row, now) {
    const period = periodOf(row.account);
    let remaining;
    try {
      remaining = totp.remainingSeconds(period, now);
    } catch {
      row.remainingEl.textContent = '';
      return;
    }
    row.remainingEl.textContent = String(remaining);
    row.barEl.max = period;
    row.barEl.value = remaining;
    row.el.classList.toggle('expiring', remaining <= EXPIRING_SECONDS);
  }

  function tick() {
    // Wake just after the next whole second so countdowns flip in step with the clock.
    timer = setTimeout(tick, 1000 - (Date.now() % 1000) + 15);
    const now = Date.now();
    for (const row of rows.values()) {
      paint(row, now);
      if (Math.floor(now / 1000 / periodOf(row.account)) !== row.counter) updateCode(row, now);
    }
  }

  function start() {
    if (timer === null) tick();
  }

  function stop() {
    clearTimeout(timer);
    timer = null;
  }

  // Copies the code for the moment of the click, never the displayed one: that can be from a
  // period that already ended (a tick is due or still computing, or timers were throttled).
  // The row is refreshed to show what was copied.
  async function copy(row) {
    const gen = session.generation();
    const now = Date.now();
    const code = await updateCode(row, now);
    // Locked or re-rendered while the code was computed: this row is gone.
    if (!code || !stillShown(row, gen)) return;
    paint(row, now);
    try {
      await navigator.clipboard.writeText(code);
    } catch {
      if (stillShown(row, gen)) notice(t('copyFailed'), true);
      return;
    }
    // Locked or re-rendered while the clipboard was written: nothing goes back on the page.
    if (!stillShown(row, gen)) return;
    for (const other of rows.values()) {
      if (other !== row) other.el.classList.remove('copied');
    }
    row.el.classList.add('copied');
    clearTimeout(row.copiedTimer);
    row.copiedTimer = setTimeout(() => row.el.classList.remove('copied'), COPIED_MS);
    announce(t('copiedLive', displayName(row.account)));
  }

  // Inline two-step delete: the first click arms the button ("Delete?"), a second click on
  // the same button within a few seconds deletes. Escape or the timeout disarms it.
  async function deleteClicked(row) {
    if (!row.el.classList.contains('confirming')) {
      disarmAll();
      row.el.classList.add('confirming');
      row.deleteEl.textContent = t('deleteConfirm');
      row.deleteEl.setAttribute('aria-label', t('deleteConfirmLabel', displayName(row.account)));
      row.confirmTimer = setTimeout(() => disarm(row), CONFIRM_MS);
      return;
    }
    clearTimeout(row.confirmTimer);
    row.deleteEl.disabled = true;
    const gen = session.generation();
    try {
      const deleted = await session.deleteAccount(row.account.id);
      // Locked meanwhile (the delete may or may not be stored): the page is already wiped,
      // and no name, list or error goes back on it.
      if (session.generation() !== gen) return;
      // false: the stored list has no entry with this id (another page changed it meanwhile).
      // Nothing was deleted, so nothing is announced; the list shows what is stored now.
      if (deleted) announce(t('deletedLive', displayName(row.account)));
      await render();
      if (session.generation() !== gen) return;
      const first = listEl.querySelector('.account:not([hidden]) .delete');
      if (first && document.body.classList.contains('editing')) first.focus();
      else searchEl.focus();
    } catch (error) {
      if (session.generation() !== gen) return;
      row.deleteEl.disabled = false;
      disarm(row);
      notice(t('deleteFailed', reason(error)), true);
    }
  }

  function disarm(row) {
    clearTimeout(row.confirmTimer);
    row.el.classList.remove('confirming');
    row.deleteEl.textContent = t('deleteBtn');
    row.deleteEl.setAttribute('aria-label', t('deleteLabel', displayName(row.account)));
  }

  function disarmAll() {
    for (const row of rows.values()) {
      if (row.el.classList.contains('confirming')) disarm(row);
    }
  }

  function setEditing(on) {
    document.body.classList.toggle('editing', on);
    editBtn.setAttribute('aria-pressed', String(on));
    if (!on) disarmAll();
  }

  function applyFilter() {
    let visible = 0;
    for (const row of rows.values()) {
      const show = matchesQuery(row.account, searchEl.value);
      row.el.hidden = !show;
      if (show) visible++;
    }
    noMatchesEl.hidden = rows.size === 0 || visible > 0;
  }

  function notice(message, isError = false) {
    clearTimeout(noticeTimer);
    noticeEl.textContent = message;
    noticeEl.classList.toggle('is-error', isError);
    noticeTimer = setTimeout(() => {
      noticeEl.textContent = '';
    }, NOTICE_MS);
  }

  // → true while `row` is still on the page and the session has not locked since `gen`.
  function stillShown(row, gen) {
    return session.generation() === gen && rows.get(row.account.id) === row;
  }

  function clearRowTimers(row) {
    clearTimeout(row.copiedTimer);
    clearTimeout(row.confirmTimer);
  }

  // Removes every code and name from the DOM (on lock).
  function clear() {
    stop();
    renderToken++;
    for (const row of rows.values()) clearRowTimers(row);
    rows = new Map();
    listEl.replaceChildren();
    searchEl.value = '';
    noticeEl.textContent = '';
    setEditing(false);
  }

  function focus() {
    if (rows.size > 0) searchEl.focus();
    else $('#empty-add-btn').focus();
  }

  return { render, start, stop, clear, notice, focus };
}
