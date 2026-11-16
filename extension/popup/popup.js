// Popup entry point. body[data-state] ∈ setup | locked | list | add | settings selects the
// visible view (popup.css). The same page also runs as a full tab (popup.html#add-file,
// popup.html#settings) for file pickers, which can close a popup on some platforms.
import * as store from '../lib/store.js';
import * as session from './session.js';
import { localize, t, uiLang } from './i18n.js';
import { $, setText, withBusy, reason } from './ui.js';
import { createListView } from './list.js';
import { createAddView, summary } from './add.js';
import { createSettingsView } from './settings.js';

const MIN_PASSPHRASE_LENGTH = 8;

let list;
let add;
let settings;
let isTab = false;
let intent = null;          // view to open right after unlocking: 'add' | 'add-file' | 'settings'
let localSessionChange = 0; // > 0 while this page creates or unlocks the vault itself

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
    done: (result) => showList(t('importedCount', [result.added, result.skipped])),
  });

  wireNavigation();
  wireSetup();
  wireUnlock();
  store.watch(storageChanged);

  await route(await session.resume());
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
  const next = intent;
  intent = null;
  if (next === 'add-file') await show('add', { fileMode: true });
  else if (next === 'add') await show('add');
  else if (next === 'settings') await show('settings');
  else await showList();
}

async function show(state, options = {}) {
  if (state === 'list') {
    // Rows and codes are ready before the list becomes visible.
    await list.render();
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
  if (message) list.notice(message);
}

async function lock() {
  list.clear();
  await session.lock();
  await show('locked');
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
    let created = false;
    localSessionChange++;
    try {
      await withBusy(submit, t('setupBusy'), async () => {
        try {
          await session.create(pass);
          created = true;
        } catch (error) {
          if (error.code !== 'vault-exists') setText(errorEl, t('errSetupFailed', reason(error)));
        }
      });
    } finally {
      localSessionChange--;
    }
    if (created) {
      form.reset();
      await enterUnlocked();
    } else if (!errorEl.textContent) {
      // Another window created the vault meanwhile.
      await route(await session.resume());
    }
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
    if (!passEl.value) {
      setText(errorEl, t('errEmptyPass'));
      passEl.focus();
      return;
    }
    let unlocked = false;
    localSessionChange++;
    try {
      await withBusy(submit, t('unlockBusy'), async () => {
        try {
          await session.unlock(passEl.value);
          unlocked = true;
        } catch (error) {
          if (error.code === 'no-vault') return;
          setText(errorEl, session.isBadPassphrase(error) ? t('errWrongPass') : t('errUnlockFailed', reason(error)));
        }
      });
    } finally {
      localSessionChange--;
    }
    if (unlocked) {
      form.reset();
      await enterUnlocked();
    } else if (errorEl.textContent) {
      passEl.select();
    } else {
      await route(await session.resume());
    }
  });
}

// Another popup or tab changed the vault or locked it.
async function storageChanged(change) {
  const state = document.body.dataset.state;
  if (change.locked) {
    if (session.isUnlocked() && localSessionChange === 0) {
      list.clear();
      session.forget();
      await show('locked');
    }
    return;
  }
  if (!('record' in change) || localSessionChange > 0) return;
  if (!session.isUnlocked()) {
    if (state === 'setup' || state === 'locked') await route(await session.resume());
    return;
  }
  if (session.isCurrentRecord(change.record)) return;
  if (await session.reload()) {
    if (state === 'list') await list.render();
  } else {
    list.clear();
    await show(change.record ? 'locked' : 'setup');
  }
}
