// Auto-fill on a bound site (.prd/03-autofill.md S3).
//
// lib/autofill-worker.js registers this file, right after lib/fieldfind.js, only for the exact
// https origins the user bound; both run in this extension's isolated world, in every frame of
// such an origin. Content scripts registered this way are classic scripts, so the field finder
// comes in as the zauthFieldFind global rather than an import.
//
// Once a code field is found the service worker is asked for a code. It answers only for a bound
// origin while the vault is unlocked, and only the digits reach this page. A code is asked for at
// most once per field, a field is filled only while it is empty, a page load gets one fill at most
// (the watch ends with it), and nothing is ever submitted. Until then, fields that appear or become
// visible later are looked for during the first minute.
(() => {
  'use strict';

  const finder = globalThis.zauthFieldFind;
  if (!finder) return;

  const WATCH_MS = 60 * 1000;
  // Mutations come in bursts; one look per burst.
  const SETTLE_MS = 100;
  // A field can become visible with no DOM change at all: an out-of-process iframe can still have
  // no size when this script runs, and then nothing in it has a box yet. Until a field is filled
  // the page is looked at again this often, besides the events below.
  const RETRY_MS = 500;
  const CODE = /^\d{6,8}$/;
  // Attribute changes that can make a field appear, become usable or turn into a code field.
  const WATCHED_ATTRIBUTES = [
    'style', 'class', 'hidden', 'disabled', 'readonly', 'type',
    'autocomplete', 'name', 'id', 'aria-label', 'placeholder', 'inputmode', 'maxlength',
  ];
  // Window events after which a field may be visible that was not: the frame got its size, the
  // page finished loading, or it came back from the back/forward cache.
  const WINDOW_EVENTS = ['resize', 'load', 'pageshow'];

  const seen = new WeakSet(); // fields a code was asked for, or filled, or found unfit to fill
  let stopped = false;
  let asking = false;
  let settleTimer = 0;
  let retryTimer = 0;

  const observer = new MutationObserver(schedule);
  observer.observe(document, { subtree: true, childList: true, attributes: true, attributeFilter: WATCHED_ATTRIBUTES });
  for (const type of WINDOW_EVENTS) window.addEventListener(type, schedule);
  // The tab was shown (or hidden: a look then is harmless).
  document.addEventListener('visibilitychange', schedule);
  const deadline = setTimeout(stop, WATCH_MS);
  retry();
  look();

  function schedule() {
    if (stopped || settleTimer) return;
    settleTimer = setTimeout(() => {
      settleTimer = 0;
      look();
    }, SETTLE_MS);
  }

  function retry() {
    if (stopped) return;
    retryTimer = setTimeout(() => {
      look();
      retry();
    }, RETRY_MS);
  }

  // The field(s) to fill now, or null when there is none or it was handled before.
  function target() {
    const fields = finder.findInDocument(document);
    return fields && !fields.some((el) => seen.has(el)) ? fields : null;
  }

  async function look() {
    if (stopped || asking) return;
    const asked = target();
    if (!asked) return;
    // A field whose code was asked for is never asked for again, even if it is not filled (the
    // user typed into it while the worker answered).
    for (const el of asked) seen.add(el);
    asking = true;
    let code = null;
    try {
      const reply = await chrome.runtime.sendMessage({ type: 'autofill-code' });
      if (reply && typeof reply.code === 'string' && CODE.test(reply.code)) code = reply.code;
    } catch {
      // The worker could not be reached (the extension was reloaded or updated).
    }
    asking = false;
    if (stopped) return;
    if (code === null) {
      // Locked, idle, not bound, or no answer: nothing will be filled on this page.
      stop();
      return;
    }
    // The page may have changed while the worker answered: find the field again before filling.
    // It is filled if it is the one just asked for, or one no code was asked for yet.
    const fields = finder.findInDocument(document);
    if (fields && fields.every((el) => asked.includes(el) || !seen.has(el)) && fill(fields, code)) {
      // One fill per page load: a later field (another code-like field, the same form shown again)
      // gets no fresh code.
      stop();
      return;
    }
    // Mutations that arrived while asking were dropped by look(); check once more.
    schedule();
  }

  // → true when the field(s) were filled
  function fill(fields, code) {
    for (const el of fields) seen.add(el);
    if (fields.length === 1) {
      const [el] = fields;
      if (el.value !== '' || (el.maxLength >= 0 && el.maxLength < code.length)) return false;
      put(el, code);
      return true;
    }
    // Split boxes: one digit each, only when there is exactly one box per digit.
    if (fields.length !== code.length || fields.some((el) => el.value !== '')) return false;
    fields.forEach((el, i) => put(el, code[i]));
    return true;
  }

  function put(el, value) {
    el.value = value;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function stop() {
    stopped = true;
    observer.disconnect();
    for (const type of WINDOW_EVENTS) window.removeEventListener(type, schedule);
    document.removeEventListener('visibilitychange', schedule);
    clearTimeout(settleTimer);
    clearTimeout(retryTimer);
    clearTimeout(deadline);
  }
})();
