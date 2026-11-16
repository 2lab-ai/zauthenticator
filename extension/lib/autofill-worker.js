// Auto-fill in the service worker (.prd/03-autofill.md S1-S4). background.js only wires browser
// events to the exports below; nothing here is a test hook.
//
// Every vault read goes through session.readUnlocked() or session.withVaultState(), which re-check
// the stored key and the idle limit under the vault Web Lock and lock a session that sat idle too
// long. This module never touches a page itself: fillFocused() is serialized by chrome.scripting
// and runs in the frame the menu was opened in, only while that frame still shows a document of
// the origin the click was in, and content/autofill.js asks handleMessage() for a code, which
// answers only for a bound origin while the vault is unlocked, with the digits only.
import { totp } from './totp.js';
import { normalizeOrigin, bindingFor, boundOrigins } from './bindings.js';
import { openOwnWindow } from './nav.js';
import * as store from './store.js';
import * as session from '../popup/session.js';
import { text } from '../popup/format.js';
import { t } from '../popup/i18n.js';

const MENU_ROOT = 'zauthenticator';
const MENU_UNLOCK = 'unlock';
const MENU_EMPTY = 'no-accounts';
const MENU_ACCOUNT = 'acct:';
const MENU_CONTEXTS = ['editable'];
const SCRIPT_ID = 'autofill';
// Run in this order in one isolated world. Content scripts registered at run time are classic
// scripts, so the field finder defines a global that content/autofill.js reads.
const CONTENT_SCRIPTS = ['lib/fieldfind.js', 'content/autofill.js'];
const CODE = /^\d{6,8}$/;

// Runs `task` one call at a time. A call made while an earlier run still waits to start joins
// that run: it would read the same state.
function serial(task) {
  let tail = Promise.resolve();
  let waiting = null;
  return () => {
    if (waiting) return waiting;
    const run = tail.then(() => {
      waiting = null;
      return task();
    });
    waiting = run;
    tail = run.catch(() => {});
    return run;
  };
}

const menuQueue = serial(buildMenu);
const syncQueue = serial(sync);

// Session storage holds the raw vault key: readable by extension pages and this worker only.
store.pinSessionAccess();

// The vault's accounts that can be named and found again: objects with a non-empty string id,
// the first entry for each id.
function accountsOf(data) {
  const list = data && Array.isArray(data.accounts) ? data.accounts : [];
  const ids = new Set();
  return list.filter((a) => {
    if (a === null || typeof a !== 'object' || Array.isArray(a)) return false;
    if (typeof a.id !== 'string' || a.id === '' || ids.has(a.id)) return false;
    ids.add(a.id);
    return true;
  });
}

// "issuer · label", either alone when the other is empty. Names come from scanned QR codes and
// pasted links; the menu shows them as plain text.
function accountTitle(account) {
  const issuer = text(account.issuer).trim();
  const label = text(account.label).trim();
  return (issuer && label ? `${issuer} · ${label}` : issuer || label) || t('menuUnnamed');
}

// contextMenus.create reports errors through a callback only. A failed item (none is expected)
// leaves the rest of the menu in place.
function createItem(properties) {
  return new Promise((resolve) => {
    chrome.contextMenus.create({ contexts: MENU_CONTEXTS, ...properties }, () => {
      void chrome.runtime.lastError;
      resolve();
    });
  });
}

/** Replaces the context menu: one item per account while unlocked, else "Unlock zauthenticator…". */
export function rebuildMenu() {
  return menuQueue();
}

async function buildMenu() {
  const data = await session.readUnlocked();
  await chrome.contextMenus.removeAll();
  await createItem({ id: MENU_ROOT, title: t('extName') });
  if (!data) {
    await createItem({ id: MENU_UNLOCK, parentId: MENU_ROOT, title: t('menuUnlock') });
    return;
  }
  const accounts = accountsOf(data);
  if (accounts.length === 0) {
    await createItem({ id: MENU_EMPTY, parentId: MENU_ROOT, title: t('menuNoAccounts'), enabled: false });
    return;
  }
  for (const account of accounts) {
    await createItem({ id: `${MENU_ACCOUNT}${account.id}`, parentId: MENU_ROOT, title: accountTitle(account) });
  }
}

/**
 * contextMenus.onClicked: fills the chosen account's code into the focused field of the clicked
 * frame (S1), then offers to remember the site for that account unless it is bound to it already.
 */
export async function handleMenuClick(info, tab) {
  rebuildMenu().catch(() => {});
  const itemId = String(info?.menuItemId ?? '');
  if (itemId === MENU_UNLOCK) {
    await openOwnWindow('unlock');
    return;
  }
  const tabId = tab?.id;
  if (!itemId.startsWith(MENU_ACCOUNT) || !Number.isInteger(tabId) || tabId < 0) return;
  // The origin of the document the click was in: the page's for the top frame, the frame's own for
  // any other (never the page's: a framed site is not the page). The fill happens only in a
  // document of that origin, and only that origin is offered. No URL for the frame: no fill.
  const frameId = Number.isInteger(info.frameId) ? info.frameId : 0;
  const expected = urlOrigin(frameId === 0 ? info.pageUrl : info.frameUrl);
  if (expected === null) return;

  // Choosing an account is activity.
  const data = await session.readUnlocked({ touch: true });
  if (!data) {
    await openOwnWindow('unlock');
    return;
  }
  const account = accountsOf(data).find((a) => a.id === itemId.slice(MENU_ACCOUNT.length));
  if (!account) {
    await rebuildMenu();
    return;
  }
  let code;
  try {
    code = await totp(account, Date.now());
  } catch {
    return; // invalid stored key
  }
  if (!CODE.test(code)) return;

  let filled = false;
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId, frameIds: [frameId] },
      func: fillFocused,
      args: [code, expected],
    });
    // fillFocused() answers with the origin it found the document at, which must be the one the
    // click was in.
    filled = results.some((r) => r && r.result === expected);
  } catch {
    return; // a page the extension may not script: no fill, no offer
  }
  if (!filled) return;

  // Offered: the https origin the fill was checked against, unless it is already bound to this
  // account. A site bound to another account is offered too: Allow then binds it to this one.
  const origin = normalizeOrigin(expected);
  if (origin !== expected || bindingFor(data, origin)?.accountId === account.id) return;
  // false: the vault locked (or went idle) since the read; there is nothing to offer.
  if ((await session.setPendingBind({ origin, accountId: account.id })) !== true) return;
  await openOwnWindow('bind');
}

/**
 * runtime.onMessage: { type: 'autofill-code' } from content/autofill.js → { code } for the
 * sender's bound origin while unlocked, else { code: null }. Does not count as activity.
 */
export async function handleMessage(message, sender) {
  rebuildMenu().catch(() => {});
  if (!message || message.type !== 'autofill-code') return { code: null };
  if (!sender || sender.id !== chrome.runtime.id) return { code: null };
  const origin = senderOrigin(sender);
  if (!origin) return { code: null };
  const data = await session.readUnlocked({ touch: false });
  if (!data) return { code: null };
  const binding = bindingFor(data, origin);
  if (!binding) return { code: null };
  const account = accountsOf(data).find((a) => a.id === binding.accountId);
  if (!account) return { code: null };
  try {
    const code = await totp(account, Date.now());
    return { code: CODE.test(code) ? code : null };
  } catch {
    return { code: null };
  }
}

// → new URL(url).origin (any scheme; 'null' for an opaque one), or null when url is not a URL.
function urlOrigin(url) {
  if (typeof url !== 'string') return null;
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

// The origin of the frame that sent the message (set by the browser), as a binding key, or null.
function senderOrigin(sender) {
  let raw = sender.origin;
  if (typeof raw !== 'string') {
    try {
      raw = new URL(sender.url).origin;
    } catch {
      return null;
    }
  }
  return normalizeOrigin(raw);
}

/**
 * The one reconciler (S2, S4): registers content/autofill.js for exactly the bound origins and
 * removes granted optional site access that no binding uses. Locked or idle: unregisters the
 * script (the next unlock registers it again) and leaves site access as it is.
 */
export function syncRegistrations() {
  return syncQueue();
}

async function sync() {
  const data = await session.readUnlocked();
  if (!data) {
    // Which sites are bound cannot be read while locked, so no access is removed; the script is
    // simply not injected anywhere until then.
    await registerAutofill([]);
    return;
  }
  const matches = boundOrigins(data).map((origin) => `${origin}/*`);
  try {
    await registerAutofill(matches);
  } finally {
    await removeUnusedAccess();
  }
}

async function registerAutofill(matches) {
  const registered = await chrome.scripting.getRegisteredContentScripts({ ids: [SCRIPT_ID] });
  if (matches.length === 0) {
    if (registered.length > 0) await chrome.scripting.unregisterContentScripts({ ids: [SCRIPT_ID] });
    return;
  }
  const script = {
    id: SCRIPT_ID,
    matches,
    js: CONTENT_SCRIPTS,
    allFrames: true,
    runAt: 'document_idle',
    // Gone when the browser restarts (the vault is locked then); the unlock registers it again.
    persistAcrossSessions: false,
  };
  if (registered.length > 0) await chrome.scripting.updateContentScripts([script]);
  else await chrome.scripting.registerContentScripts([script]);
}

// Decided and done under the vault lock (session.withVaultState), against the bindings and the
// offer stored at that moment: the bind window stores a binding before it clears its offer, so a
// site the browser has just granted is offered or bound here, never neither. Kept: the bound
// origins, the origin of a stored offer of any age (the bind window may sit between the
// permission prompt and storing the binding), and host permissions the manifest itself requests.
// Locked or idle: nothing is removed.
// Each removal stands alone, so one refused removal does not keep the others.
function removeUnusedAccess() {
  return session.withVaultState(async ({ data, pending }) => {
    if (!data) return;
    const keep = new Set(boundOrigins(data).map((origin) => `${origin}/*`));
    for (const pattern of chrome.runtime.getManifest().host_permissions ?? []) keep.add(pattern);
    if (pending) keep.add(`${pending.origin}/*`);
    const granted = await chrome.permissions.getAll();
    const unused = (granted.origins ?? []).filter((pattern) => pattern.startsWith('https:') && !keep.has(pattern));
    for (const pattern of unused) {
      try {
        await chrome.permissions.remove({ origins: [pattern] });
      } catch {
        // already gone, or not removable
      }
    }
  });
}

/**
 * storage.onChanged: the vault record changed, the session key was written or removed (unlock,
 * lock), or a bind offer was dropped → rebuild the menu and reconcile.
 */
export function onStorageChanged(changes, area) {
  const has = (key) => Boolean(changes) && Object.hasOwn(changes, key);
  const relevant =
    (area === 'local' && has(store.RECORD_KEY)) ||
    (area === 'session' && (has(store.SESSION_KEY) || (has(store.PENDING_KEY) && changes[store.PENDING_KEY].newValue === undefined)));
  if (!relevant) return Promise.resolve();
  return Promise.allSettled([rebuildMenu(), syncRegistrations()]).then(() => {});
}

// Injected by chrome.scripting.executeScript into the frame the menu was opened in, as source
// text: it may use nothing from this module. expected is the origin of the document the menu was
// opened in; when the frame shows a document of another origin now (it navigated while the code
// was made), nothing is touched. Fills the focused text field, or, when that is a single-character
// box, the run of boxes it belongs to (grouped as lib/fieldfind.js groups them) with one digit
// each, dispatching input and change. Submits nothing. → the document's origin when it filled,
// else false
function fillFocused(code, expected) {
  if (location.origin !== expected) return false;
  let el = document.activeElement;
  while (el && el.shadowRoot && el.shadowRoot.activeElement) el = el.shadowRoot.activeElement;
  const textTypes = ['text', 'tel', 'number', 'password', 'search', 'email', 'url'];
  const writable = (input) =>
    (input instanceof HTMLTextAreaElement || (input instanceof HTMLInputElement && textTypes.includes(input.type))) &&
    !input.matches(':disabled') &&
    !input.readOnly;
  if (!writable(el)) return false;
  const put = (input, value) => {
    input.value = value;
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  };
  const groupOf = (input) => {
    const parent = input.parentElement;
    if (parent && parent.parentElement && parent.querySelectorAll('input').length === 1) return parent.parentElement;
    return parent;
  };
  if (el instanceof HTMLInputElement && el.maxLength === 1) {
    const group = groupOf(el);
    const boxes = Array.from(el.getRootNode().querySelectorAll('input')).filter(
      (input) => input.maxLength === 1 && writable(input) && groupOf(input) === group,
    );
    if (boxes.length === code.length && boxes.includes(el)) {
      boxes.forEach((box, i) => put(box, code[i]));
      return location.origin;
    }
  }
  put(el, code);
  return location.origin;
}
