// Auto-fill on a bound site (.prd/03-autofill.md S3).
//
// lib/autofill-worker.js registers this file, right after lib/fieldfind.js, only for the exact
// https origins the user bound; both run in this extension's isolated world, in every frame of
// such an origin. Content scripts registered this way are classic scripts, so the field finder
// comes in as the zauthFieldFind global rather than an import.
//
// Once a code field is found the service worker is asked for a code. It answers only for a bound
// origin while the vault is unlocked, and only the digits reach this page. A field is filled only
// while it is empty and at most once per page load, and nothing is ever submitted. Fields that
// appear later are looked for during the first minute.
(() => {
  'use strict';

  const finder = globalThis.zauthFieldFind;
  if (!finder) return;

  const WATCH_MS = 60 * 1000;
  // Mutations come in bursts; one look per burst.
  const SETTLE_MS = 100;
  const CODE = /^\d{6,8}$/;
  // Attribute changes that can make a field appear, become usable or turn into a code field.
  const WATCHED_ATTRIBUTES = [
    'style', 'class', 'hidden', 'disabled', 'readonly', 'type',
    'autocomplete', 'name', 'id', 'aria-label', 'placeholder', 'inputmode', 'maxlength',
  ];

  const seen = new WeakSet(); // fields already filled (or found unfit to fill)
  let stopped = false;
  let asking = false;
  let settleTimer = 0;

  const observer = new MutationObserver(schedule);
  observer.observe(document, { subtree: true, childList: true, attributes: true, attributeFilter: WATCHED_ATTRIBUTES });
  const deadline = setTimeout(stop, WATCH_MS);
  look();

  function schedule() {
    if (stopped || settleTimer) return;
    settleTimer = setTimeout(() => {
      settleTimer = 0;
      look();
    }, SETTLE_MS);
  }

  // The field(s) to fill now, or null when there is none or it was handled before.
  function target() {
    const fields = finder.findInDocument(document);
    return fields && !fields.some((el) => seen.has(el)) ? fields : null;
  }

  async function look() {
    if (stopped || asking || !target()) return;
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
    const fields = target();
    if (fields) fill(fields, code);
    // Mutations that arrived while asking were dropped by look(); check once more.
    schedule();
  }

  function fill(fields, code) {
    for (const el of fields) seen.add(el);
    if (fields.length === 1) {
      const [el] = fields;
      if (el.value !== '' || (el.maxLength >= 0 && el.maxLength < code.length)) return;
      put(el, code);
      return;
    }
    // Split boxes: one digit each, only when there is exactly one box per digit.
    if (fields.length !== code.length || fields.some((el) => el.value !== '')) return;
    fields.forEach((el, i) => put(el, code[i]));
  }

  function put(el, value) {
    el.value = value;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function stop() {
    stopped = true;
    observer.disconnect();
    clearTimeout(settleTimer);
    clearTimeout(deadline);
  }
})();
