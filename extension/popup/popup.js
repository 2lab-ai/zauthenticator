// Popup entry point. body[data-state] ∈ setup | locked | list | add | settings | bind | export selects
// the visible view (popup.css). The same page also runs as a full tab (popup.html#add-file,
// popup.html#settings) for file pickers, which can close a popup on some platforms, and in a
// small window the service worker opens (popup.html#bind, popup.html#unlock; lib/nav.js
// openOwnWindow) that closes itself once its one job is done.
import * as store from '../lib/store.js';
import { normalizeOrigin } from '../lib/bindings.js';
import * as session from './session.js';
import { localize, t, uiLang } from './i18n.js';
import { $, setText, withBusy, reason, clearAnnouncement } from './ui.js';
import { createListView, paintAvatar, clearAvatar } from './list.js';
import { createAddView, summary } from './add.js';
import { createSettingsView, createPasskeyUnlock, accountTitle, takeOrphanNotice } from './settings.js';
import { createUnlockTime } from './unlock-time.js';
import { createExportView } from './export.js';
import { openOwnWindow } from '../lib/nav.js';

const MIN_PASSPHRASE_LENGTH = 8;
const UNLOCKED_VIEWS = ['list', 'add', 'settings', 'bind', 'export'];
// The window views: #bind offers to remember the site of the last menu fill; #unlock only asks
// for the passphrase.
const WINDOW_VIEWS = ['bind', 'unlock'];
// Idle auto-lock (the limit is session.IDLE_LOCK_MS): how often an open page checks it, and
// the least time between two activity writes from this page.
const IDLE_CHECK_MS = 30 * 1000;
const TOUCH_INTERVAL_MS = 30 * 1000;

let list;
let add;
let settings;
let bind;
let isTab = false;
let isWindow = false;  // opened by the service worker in its own window: close when done
let windowView = null; // 'bind' | 'unlock' from the hash; shown after every unlock until done
let intent = null;     // view to open right after unlocking: 'add' | 'add-file' | 'settings'
let showToken = 0;     // the latest show() call; an earlier one stops after its await
let localOps = 0;      // > 0 while this page starts up, creates, unlocks or locks itself
let recheck = false;   // a storage change arrived meanwhile: re-check once that ends
let reconciling = Promise.resolve();
let passkeyUnlock;
let unlockTime;
let exportView;

main().catch((error) => {
  setText($('.loading'), t('errStartup', reason(error)));
});

async function main() {
  document.documentElement.lang = uiLang();
  localize(document);
  localize($('#account-template').content);
  localize($('#binding-template').content);

  // tabs.getCurrent() finds a Tab both in a full tab and in the service worker's window; only the
  // toolbar popup has none. The hash tells the two apart (only openOwnWindow uses #bind, #unlock).
  const inTab = await detectTab();
  const hash = takeHash();
  windowView = WINDOW_VIEWS.includes(hash) ? hash : null;
  isWindow = inTab && windowView !== null;
  isTab = inTab && !isWindow;
  document.documentElement.classList.toggle('tab', isTab);
  document.documentElement.classList.toggle('window', isWindow);
  intent = ['add', 'add-file', 'settings'].includes(hash) ? hash : null;

  list = createListView();
  add = createAddView({ isTab, done: (result) => showList(summary(result)) });
  settings = createSettingsView({
    isTab,
    done: (result) => showList(`${t('importDone')} ${summary(result)}`),
    onOrphan: showOrphanNotice,
    onPassphraseChanged: syncMode,
  });
  // "Unlock with passkey": the toolbar popup opens the unlock window; in that window (or a tab)
  // the click runs the ceremony.
  passkeyUnlock = createPasskeyUnlock({
    inPopup: !isTab && !isWindow,
    openWindow: () => openOwnWindow('unlock'),
    onUnlocked: enterUnlocked,
  });
  bind = createBindView();
  exportView = createExportView({ back: () => show('settings') });
  // The list view's lock time and Extend. A lock time that has passed is checked like an idle one.
  unlockTime = createUnlockTime({ onExpired: () => { idleLock().catch(() => {}); } });

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

// → the view name in the hash ('' when none); the hash is removed from the address.
function takeHash() {
  const hash = location.hash.slice(1);
  if (hash) history.replaceState(null, '', location.pathname);
  return hash;
}

async function route(state) {
  if (state === 'list') await enterUnlocked();
  else await show(state);
}

async function enterUnlocked() {
  // Also when another page did the unlocking: no passphrase stays in a hidden gate field.
  passkeyUnlock.clear();
  $('#setup-form').reset();
  $('#unlock-form').reset();
  if (windowView === 'unlock') {
    await finishWindow();
    return;
  }
  if (windowView === 'bind') {
    await showBind();
    return;
  }
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
  // Secret keys shown for an export never outlive the view.
  if (state !== 'export') exportView.clear();
  if (state === 'list') {
    // Rows and codes are ready before the list becomes visible.
    await list.render();
    if (token !== showToken) return;
    if (!session.isUnlocked()) {
      await show('locked');
      return;
    }
    list.start();
    unlockTime.start();
  } else {
    list.stop();
    unlockTime.stop();
  }
  document.body.dataset.state = state;
  syncMode();
  $('#main').scrollTop = 0;
  if (state === 'setup') $('#setup-pass').focus();
  else if (state === 'locked') {
    $('#unlock-pass').focus();
    passkeyUnlock.refresh();
    showDeviceMissing(token);
  }
  else if (state === 'list') list.focus();
  else if (state === 'add') add.open(options);
  else if (state === 'settings') settings.open();
  else if (state === 'export') exportView.open();
  else if (state === 'bind') bind.focus();
  showOrphanNotice();
}

// Without a passphrase there is nothing to lock with: the Lock button goes (popup.css).
function syncMode() {
  document.body.classList.toggle('no-passphrase', session.isUnlocked() && !session.hasPassphrase());
}

// The locked view of a vault without a passphrase is reached only when its device key is gone:
// there is no passphrase to type, only the way out.
async function showDeviceMissing(token) {
  let device = false;
  try {
    ({ device } = await session.vaultInfo());
  } catch {
    device = false;
  }
  if (token !== showToken || document.body.dataset.state !== 'locked') return;
  $('#unlock-device-missing').hidden = !device;
  $('#unlock-form').hidden = device;
}

// An enrollment that created a passkey on the phone or key but could not store it (this page
// locked, or the vault changed, while the ceremony ran) owes the user a notice: the locked view or
// the list shows it once. The settings view shows it itself when it opens (settings.js).
function showOrphanNotice() {
  const state = document.body.dataset.state;
  if (state === 'locked') {
    if (takeOrphanNotice()) setText($('#unlock-passkey-status'), t('passkeyOrphan'));
  } else if (state === 'list') {
    if (takeOrphanNotice()) list.notice(t('passkeyOrphan'));
  }
}

async function showBind() {
  if (!(await bind.load())) return;
  await show('bind');
}

// The window's one job is done (or declined): close it. Anywhere else, go on to the list.
async function finishWindow() {
  windowView = null;
  if (isWindow) {
    window.close();
    return;
  }
  await showList();
}

async function showList(message) {
  await show('list');
  if (message && document.body.dataset.state === 'list') list.notice(message);
}

// Empties everything that can hold a secret, a passphrase or an account name: rows and
// codes, every input of every view, status lines and the screen-reader live region.
function clearSensitive() {
  passkeyUnlock.clear();
  unlockTime.clear();
  exportView.clear();
  list.clear();
  add.clearSensitive();
  settings.clearSensitive();
  bind.clear();
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
  $('#xp-open').addEventListener('click', () => show('export'));

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape' || event.defaultPrevented) return;
    const state = document.body.dataset.state;
    const target = event.target;
    const typing = target instanceof HTMLElement && target.matches('input, textarea, select');
    if (state === 'export' && !typing) {
      event.preventDefault();
      show('settings');
    } else if ((state === 'add' || state === 'settings') && !typing) {
      event.preventDefault();
      showList();
    } else if (state === 'bind') {
      event.preventDefault();
      bind.cancel();
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
    // A recorded activity moves the lock time: the list view shows the new one.
    session.touch().then((result) => {
      if (result === 'idle') return idleLock();
      if (result === 'touched' && document.body.dataset.state === 'list') return unlockTime.refresh();
      return undefined;
    }).catch(() => {});
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
      else if (document.body.dataset.state === 'settings') settings.refresh();
    } else if (result === 'locked') {
      // A vault without a passphrase opens again by itself (another page re-keyed it).
      if ((await session.vaultInfo()).device) await route(await session.resume());
      else await showLocked();
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

// The bind window (S2): shows the site and account of the offer the service worker stored after a
// menu fill; Allow asks the browser for access to exactly that site and then stores the binding.
function createBindView() {
  const originEl = $('#bind-origin');
  const accountEl = $('#bind-account');
  const avatarEl = $('#bind-avatar');
  const hintEl = $('#bind-hint');
  const errorEl = $('#bind-error');
  const allowBtn = $('#bind-allow');
  const cancelBtn = $('#bind-cancel');
  // "Replaces <account>", under the card, while the site is bound to another account: Allow binds
  // it to the offered one instead (session.addBinding replaces). It names an account, so it is
  // emptied with the rest of the view.
  const replacesEl = document.createElement('p');
  replacesEl.id = 'bind-replaces';
  replacesEl.className = 'hint';
  replacesEl.hidden = true;
  $('.bind-card').after(replacesEl);
  let offer = null; // { origin, accountId, at } on display, while unlocked
  // The stored offer this window read, usable or not: the only one its Close, Not now or a failed
  // Allow removes. Another menu fill meanwhile stores a newer offer (for its own window), which
  // stays.
  let readOffer = null;

  allowBtn.addEventListener('click', allow);
  cancelBtn.addEventListener('click', cancel);

  // Reads the stored offer into the view. → false when the vault locked meanwhile (the locked
  // view is shown instead).
  async function load() {
    const gen = session.generation();
    clear();
    let pending = null;
    try {
      pending = await session.takePendingBind();
    } catch {
      pending = null;
    }
    if (!session.isUnlocked() || session.generation() !== gen) return false;
    readOffer = pending;
    const origin = pending && typeof pending.origin === 'string' ? normalizeOrigin(pending.origin) : null;
    if (!origin || origin !== pending.origin) {
      unavailable(t('bindExpired'));
      return true;
    }
    const account = session.accounts().find((a) => a.id === pending.accountId);
    if (!account) {
      unavailable(t('bindNoAccount'));
      return true;
    }
    offer = { origin, accountId: account.id, at: pending.at };
    setText(originEl, origin);
    setText(accountEl, accountTitle(account));
    paintAvatar(avatarEl, account);
    showReplaced(origin, account.id);
    return true;
  }

  // The account the site is bound to now, when that is another one the vault still has. A binding
  // whose account is gone fills nothing, so there is nothing to name.
  function showReplaced(origin, accountId) {
    const current = session.bindings().find((b) => b.origin === origin);
    const replaced = current && current.accountId !== accountId ? session.accounts().find((a) => a.id === current.accountId) : null;
    setText(replacesEl, replaced ? t('bindReplaces', accountTitle(replaced)) : '');
    replacesEl.hidden = !replaced;
  }

  // Nothing to offer: only the message and a Close button remain.
  function unavailable(message) {
    offer = null;
    allowBtn.hidden = true;
    hintEl.hidden = true;
    setText(replacesEl, '');
    replacesEl.hidden = true;
    cancelBtn.textContent = t('bindClose');
    setText(errorEl, message);
  }

  // The offer is good for session.PENDING_BIND_MS after the menu fill (S2); checked without an
  // await so it can run before the permission request.
  function expired(current) {
    return Number.isFinite(current.at) && Date.now() - current.at >= session.PENDING_BIND_MS;
  }

  // permissions.request needs the click's user activation, so it is the first call here: no
  // await comes before it. A request whose prompt is still open stays pending; the button stays
  // disabled until it settles.
  function allow() {
    const current = offer;
    if (!current || allowBtn.disabled) return;
    if (expired(current)) {
      dropOffer(t('bindExpired'), current);
      return;
    }
    const asked = chrome.permissions.request({ origins: [`${current.origin}/*`] });
    const gen = session.generation();
    withBusy(allowBtn, null, () => finishAllow(asked, current, gen)).catch(() => {});
  }

  async function finishAllow(asked, current, gen) {
    const live = () => session.isUnlocked() && session.generation() === gen && offer === current;
    setText(errorEl, '');
    cancelBtn.disabled = true;
    try {
      let granted = false;
      try {
        granted = await asked;
      } catch {
        granted = false;
      }
      if (!live()) return;
      if (!granted) {
        setText(errorEl, t('bindDenied'));
        return;
      }
      // The offer must still be the one shown: a lock elsewhere, or a newer menu fill, replaces
      // or removes it.
      const still = await session.takePendingBind();
      if (!live()) return;
      if (!still || still.origin !== current.origin || still.accountId !== current.accountId) {
        dropOffer(t('bindExpired'), current);
        return;
      }
      // The binding is stored before the offer is cleared: the service worker, which takes back
      // site access nothing uses, then always finds this site offered or bound.
      try {
        await session.addBinding(current.origin, current.accountId);
      } catch (error) {
        if (!live() || error.code === 'locked') return;
        if (error.code === 'no-account') dropOffer(t('bindNoAccount'), current);
        else setText(errorEl, t('bindFailed', reason(error)));
        return;
      }
      await clearPending(current);
      if (!live()) return;
      await finishWindow();
    } finally {
      cancelBtn.disabled = false;
    }
  }

  // The offer `target` can no longer be stored: drop it (the service worker then takes back any
  // site access it no longer needs) and leave the message with a Close button.
  function dropOffer(message, target) {
    unavailable(message);
    clearPending(target);
  }

  // Removes the stored offer only while it is still exactly `target`.
  async function clearPending(target) {
    if (!target) return;
    try {
      await session.clearPendingBind(target);
    } catch {
      // nothing stored to clear
    }
  }

  // Not now / Close / Escape: nothing is stored, and only the offer this window read is dropped.
  async function cancel() {
    if (cancelBtn.disabled) return;
    cancelBtn.disabled = true;
    try {
      await clearPending(readOffer);
    } finally {
      cancelBtn.disabled = false;
    }
    await finishWindow();
  }

  // Empties the view (on lock, and before every load).
  function clear() {
    offer = null;
    readOffer = null;
    setText(originEl, '');
    setText(accountEl, '');
    clearAvatar(avatarEl);
    setText(replacesEl, '');
    replacesEl.hidden = true;
    setText(errorEl, '');
    allowBtn.hidden = false;
    hintEl.hidden = false;
    cancelBtn.textContent = t('bindCancel');
  }

  function focus() {
    (offer ? allowBtn : cancelBtn).focus();
  }

  return { load, clear, cancel, focus };
}
