// Popup entry point. body[data-state] ∈ setup | locked | list | add | settings selects the
// visible view (popup.css). The same page also runs as a full tab (popup.html#add-file,
// popup.html#settings) for file pickers, which can close a popup on some platforms.
import * as store from '../lib/store.js';
import * as session from './session.js';
import { localize, t, uiLang } from './i18n.js';
import { $, setText, withBusy, reason, clearAnnouncement } from './ui.js';
import { createListView } from './list.js';
import { createAddView, summary } from './add.js';
import { createSettingsView } from './settings.js';

const MIN_PASSPHRASE_LENGTH = 8;
const UNLOCKED_VIEWS = ['list', 'add', 'settings'];
// Idle auto-lock (the limit is session.IDLE_LOCK_MS): how often an open page checks it, and
// the least time between two activity writes from this page.
const IDLE_CHECK_MS = 30 * 1000;
const TOUCH_INTERVAL_MS = 30 * 1000;

let list;
let add;
let settings;
let isTab = false;
let intent = null;     // view to open right after unlocking: 'add' | 'add-file' | 'settings'
let showToken = 0;     // the latest show() call; an earlier one stops after its await
let localOps = 0;      // > 0 while this page starts up, creates, unlocks or locks itself
let recheck = false;   // a storage change arrived meanwhile: re-check once that ends
let reconciling = Promise.resolve();

main().catch((error) => {
  setText($('.loading'), t('errStartup', reason(error)));
});

async function main() {
  document.documentElement.lang = uiLang();
  localize(document);
  localize($('#account-template').content);

  isTab = await detectTab();
  document.documentElement.classList.toggle('tab', isTab);
  intent = takeIntentFromHash();

  list = createListView();
  add = createAddView({ isTab, done: (result) => showList(summary(result)) });
  settings = createSettingsView({
    isTab,
    done: (result) => showList(`${t('importDone')} ${summary(result)}`),
  });

  wireNavigation();
  wireSetup();
  wireUnlock();
  wireIdleLock();
  store.watch(storageChanged);

  await local(async () => route(await session.resume()));
}

async function detectTab() {
  try {
    // undefined inside the toolbar popup, a Tab when opened as a page.
    return Boolean(await chrome.tabs.getCurrent());
  } catch {
    return false;
  }
}

function takeIntentFromHash() {
  const hash = location.hash.slice(1);
  if (hash) history.replaceState(null, '', location.pathname);
  return ['add', 'add-file', 'settings'].includes(hash) ? hash : null;
}

async function route(state) {
  if (state === 'list') await enterUnlocked();
  else await show(state);
}

async function enterUnlocked() {
  // Also when another page did the unlocking: no passphrase stays in a hidden gate field.
  $('#setup-form').reset();
  $('#unlock-form').reset();
  const next = intent;
  intent = null;
  if (next === 'add-file') await show('add', { fileMode: true });
  else if (next === 'add') await show('add');
  else if (next === 'settings') await show('settings');
  else await showList();
}

async function show(state, options = {}) {
  const token = ++showToken;
  // Never an unlocked view without an unlocked session (e.g. a late callback after a lock).
  if (UNLOCKED_VIEWS.includes(state) && !session.isUnlocked()) state = 'locked';
  if (state === 'list') {
    // Rows and codes are ready before the list becomes visible.
    await list.render();
    if (token !== showToken) return;
    if (!session.isUnlocked()) {
      await show('locked');
      return;
    }
    list.start();
  } else {
    list.stop();
  }
  document.body.dataset.state = state;
  $('#main').scrollTop = 0;
  if (state === 'setup') $('#setup-pass').focus();
  else if (state === 'locked') $('#unlock-pass').focus();
  else if (state === 'list') list.focus();
  else if (state === 'add') add.open(options);
  else if (state === 'settings') settings.open();
}

async function showList(message) {
  await show('list');
  if (message && document.body.dataset.state === 'list') list.notice(message);
}

// Empties everything that can hold a secret, a passphrase or an account name: rows and
// codes, every input of every view, status lines and the screen-reader live region.
function clearSensitive() {
  list.clear();
  add.clearSensitive();
  settings.clearSensitive();
  $('#setup-form').reset();
  $('#unlock-form').reset();
  setText($('#setup-error'), '');
  setText($('#unlock-error'), '');
  clearAnnouncement();
}

// This page found the session locked (another page locked, or the stored key is gone).
async function showLocked() {
  clearSensitive();
  await show('locked');
}

function lock() {
  return local(async () => {
    // session.lock() invalidates in-flight work at once; the view is wiped before waiting
    // for the stored key to be removed, and reads "locked" only once it is.
    const locking = session.lock();
    clearSensitive();
    try {
      await locking;
    } finally {
      await show('locked');
    }
  });
}

function wireNavigation() {
  $('#add-btn').addEventListener('click', () => show('add'));
  $('#empty-add-btn').addEventListener('click', () => show('add'));
  $('#settings-btn').addEventListener('click', () => show('settings'));
  $('#lock-btn').addEventListener('click', lock);
  $('#add-cancel').addEventListener('click', () => showList());
  $('#settings-back').addEventListener('click', () => showList());

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape' || event.defaultPrevented) return;
    const state = document.body.dataset.state;
    const target = event.target;
    const typing = target instanceof HTMLElement && target.matches('input, textarea, select');
    if ((state === 'add' || state === 'settings') && !typing) {
      event.preventDefault();
      showList();
    }
  });
}

function wireSetup() {
  const form = $('#setup-form');
  const passEl = $('#setup-pass');
  const pass2El = $('#setup-pass2');
  const errorEl = $('#setup-error');
  const submit = $('#setup-submit');

  for (const input of [passEl, pass2El]) {
    input.addEventListener('input', () => setText(errorEl, ''));
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    setText(errorEl, '');
    const pass = passEl.value;
    if ([...pass].length < MIN_PASSPHRASE_LENGTH) {
      setText(errorEl, t('errTooShort', MIN_PASSPHRASE_LENGTH));
      passEl.focus();
      return;
    }
    if (pass !== pass2El.value) {
      setText(errorEl, t('errMismatch'));
      pass2El.focus();
      return;
    }
    await local(async () => {
      await withBusy(submit, t('setupBusy'), async () => {
        try {
          await session.create(pass);
        } catch (error) {
          if (error.code !== 'vault-exists' && error.code !== 'locked') {
            setText(errorEl, t('errSetupFailed', reason(error)));
          }
        }
      });
      if (session.isUnlocked()) {
        form.reset();
        await enterUnlocked();
      } else if (!errorEl.textContent) {
        // Another window created the vault meanwhile.
        await route(await session.resume());
      }
    });
  });
}

function wireUnlock() {
  const form = $('#unlock-form');
  const passEl = $('#unlock-pass');
  const errorEl = $('#unlock-error');
  const submit = $('#unlock-submit');

  passEl.addEventListener('input', () => setText(errorEl, ''));

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    setText(errorEl, '');
    const pass = passEl.value;
    if (!pass) {
      setText(errorEl, t('errEmptyPass'));
      passEl.focus();
      return;
    }
    await local(async () => {
      await withBusy(submit, t('unlockBusy'), async () => {
        try {
          await session.unlock(pass);
        } catch (error) {
          if (error.code === 'no-vault' || error.code === 'locked') return;
          setText(errorEl, session.isBadPassphrase(error) ? t('errWrongPass') : t('errUnlockFailed', reason(error)));
        }
      });
      if (session.isUnlocked()) {
        form.reset();
        await enterUnlocked();
      } else if (errorEl.textContent) {
        passEl.select();
      } else {
        await route(await session.resume());
      }
    });
  });
}

// Idle auto-lock. Activity in any extension page refreshes the shared lastActiveAt (at most
// once per TOUCH_INTERVAL_MS from this page); an open page checks it every IDLE_CHECK_MS and
// whenever it becomes visible, and locks every page once the limit has passed. Every check is
// decided by session.lockIfIdle() under the vault lock.
function wireIdleLock() {
  let lastTouch = 0;
  const activity = () => {
    if (!session.isUnlocked()) return;
    const now = Date.now();
    if (now - lastTouch < TOUCH_INTERVAL_MS) return;
    lastTouch = now;
    // session.touch() refuses to refresh a session that already sat idle too long, so the
    // first event in a page woken after the limit locks it instead of reviving it.
    session.touch().then((result) => (result === 'idle' ? idleLock() : undefined)).catch(() => {});
  };
  for (const type of ['pointerdown', 'pointermove', 'keydown', 'wheel']) {
    document.addEventListener(type, activity, { capture: true, passive: true });
  }
  const check = () => {
    idleLock().catch(() => {});
  };
  setInterval(check, IDLE_CHECK_MS);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') check();
  });
}

// Locks when the session is still idle once session.lockIfIdle() re-checks it under the vault
// lock. The view is wiped only when that call dropped this page's key: activity another page
// recorded meanwhile leaves everything being typed here as it is.
function idleLock() {
  if (!session.isUnlocked()) return Promise.resolve();
  return local(async () => {
    let locked;
    try {
      locked = await session.lockIfIdle();
    } catch (error) {
      // Removing the stored key failed after this page had dropped its own.
      if (session.isUnlocked()) throw error;
      locked = true;
    }
    if (locked) await showLocked();
  });
}

// Runs this page's own startup, create, unlock or lock with storage notifications held back,
// then re-checks once if any arrived meanwhile (state is re-read from storage, not dropped).
async function local(task) {
  localOps++;
  try {
    return await task();
  } finally {
    localOps--;
    if (localOps === 0 && recheck) {
      recheck = false;
      storageChanged();
    }
  }
}

// Another popup or tab changed the vault or locked it (or this is the echo of our own write).
// The notification is only a hint: the state is re-read from storage under the vault lock.
function storageChanged() {
  if (localOps > 0) {
    recheck = true;
    return;
  }
  reconciling = reconciling.then(reconcile).catch(() => {});
}

async function reconcile() {
  if (session.isUnlocked()) {
    const result = await session.refresh();
    if (result === 'changed') {
      if (document.body.dataset.state === 'list') await list.render();
    } else if (result === 'locked') {
      await showLocked();
    } else if (result === 'setup') {
      clearSensitive();
      await show('setup');
    }
    return;
  }
  const state = document.body.dataset.state;
  if (UNLOCKED_VIEWS.includes(state)) await showLocked();
  else if (state === 'setup' || state === 'locked') await route(await session.resume());
}
