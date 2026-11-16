// Auto-fill on a bound site (.prd/03-autofill.md S3, "Fresh code and retry after a failed attempt").
//
// lib/autofill-worker.js registers this file, right after lib/fieldfind.js, only for the exact
// https origins the user bound; both run in this extension's isolated world, in every frame of
// such an origin. Content scripts registered this way are classic scripts, so the field finder
// comes in as the zauthFieldFind global rather than an import.
//
// Once a code field is found the service worker is asked for a code. It answers only for a bound
// origin while the vault is unlocked, and only the digits and how long they stay valid reach this
// page. A code with less than 3 s left is not filled: the next period's code is asked for instead.
// Fields that appear or become visible later are looked for during the first minute. After the
// first fill the filled field is followed for 5 minutes: when its code expires while it still holds
// it, the next code replaces it (3 times at most per field set); when the page empties it or
// replaces it with a new code field (a rejected code), it is filled again with a current code, up
// to 4 fills in all. A field the page emptied is never given the code it just held again: that
// code's period is waited out first. A field is written only while it is empty or holds what this
// script put there; once the user typed into the filled field, or the worker answers with no code,
// the watch ends. No other field is filled while the filled one is in the page, and nothing is ever
// submitted.
(() => {
  'use strict';

  const finder = globalThis.zauthFieldFind;
  if (!finder) return;

  const WATCH_MS = 60 * 1000;
  // Counted from the first fill.
  const FOLLOW_MS = 5 * 60 * 1000;
  // The first fill and three more after the page emptied or replaced the field. Replacing a code
  // that expired untouched is not counted.
  const MAX_FILLS = 4;
  // Replacements of a code that expired untouched, per filled field set (refilling the same set
  // does not start a new count): then the code is left as is. A site that submits on input would
  // otherwise get a new attempt every period.
  const MAX_REFRESHES = 3;
  // Less than this left of a code's period: too little to submit it.
  const LATE_MS = 3000;
  // A code is asked for this long after a period ends, so the worker is in the next one.
  const MARGIN_MS = 250;
  // The longest period lib/totp.js accepts.
  const MAX_VALID_MS = 300 * 1000;
  // Mutations come in bursts; one look per burst.
  const SETTLE_MS = 100;
  // A field can become visible with no DOM change at all: an out-of-process iframe can still have
  // no size when this script runs, and then nothing in it has a box yet. A page's own script can
  // also empty a filled field without one. The page is looked at again this often while the
  // watch is on, besides the events below.
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

  const seen = new WeakSet(); // fields never to fill: the code did not fit, or the user typed first
  let stopped = false;
  let asking = false;
  let settleTimer = 0;
  let retryTimer = 0;
  let waitTimer = 0; // the next period is waited for before asking again
  let freshTimer = 0; // the filled code expires
  let deadline = 0;
  let fills = 0;
  let refreshes = 0; // of the filled field set
  // The field(s) filled last and the code put there (one digit per box for split boxes), and
  // whether that code has expired.
  let filledFields = null;
  let filledCode = '';
  let expired = false;

  const observer = new MutationObserver(schedule);
  observer.observe(document, { subtree: true, childList: true, attributes: true, attributeFilter: WATCHED_ATTRIBUTES });
  for (const type of WINDOW_EVENTS) window.addEventListener(type, schedule);
  // The tab was shown (or hidden: a look then is harmless).
  document.addEventListener('visibilitychange', schedule);
  deadline = setTimeout(stop, WATCH_MS);
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

  // What this script put into box i of the filled field(s).
  function part(i) {
    return filledFields.length === 1 ? filledCode : filledCode[i];
  }

  // The field(s) to ask a code for now, or null. While the filled field(s) are in the page they
  // are the only candidate: asked for again when their code expired while they still hold it, or
  // when the page emptied them and they are still where a code field is found. Changed to anything
  // else: the user typed, and the watch ends.
  function target() {
    if (filledFields) {
      const inPage = filledFields.filter((el) => el.getRootNode() === document);
      if (inPage.length === filledFields.length) {
        if (filledFields.some((el, i) => el.value !== '' && el.value !== part(i))) {
          stop();
          return null;
        }
        if (filledFields.every((el, i) => el.value === part(i))) return expired ? filledFields : null;
        // Some boxes emptied, not all: the page is not done yet.
        if (filledFields.some((el) => el.value !== '')) return null;
        if (fills >= MAX_FILLS) {
          stop();
          return null;
        }
        const found = finder.findInDocument(document);
        const same = found && found.length === filledFields.length && found.every((el, i) => el === filledFields[i]);
        return same ? filledFields : null;
      }
      // Part of a run of boxes is gone: wait for the rest.
      if (inPage.length > 0) return null;
      // All gone: a new code field may come.
      if (fills >= MAX_FILLS) {
        stop();
        return null;
      }
    }
    const fields = finder.findInDocument(document);
    return fields && !fields.some((el) => seen.has(el)) ? fields : null;
  }

  // afterWait: this look ends a wait for the next period, and its code is filled however little of
  // it is left (a period that short has no later code with more).
  async function look(afterWait = false) {
    if (stopped || asking || waitTimer) return;
    const asked = target();
    if (!asked) return;
    asking = true;
    const reply = await ask();
    asking = false;
    if (stopped) return;
    if (reply === null) {
      // Locked, idle, not bound, or no answer: nothing more will be filled on this page.
      stop();
      return;
    }
    passTyped(asked);
    if (reply.validMs < LATE_MS && !afterWait) {
      // Too little left to submit this code: the next one is asked for when its period starts.
      askNextPeriod(asked, reply.validMs);
      return;
    }
    // The page may have changed while the worker answered: find the field(s) again (right before
    // writing, so nothing the user typed meanwhile is overwritten).
    const fields = target();
    if (fields && fields === filledFields && reply.code === filledCode && fields.every((el) => el.value === '')) {
      // The page emptied the code this script put there, so it was turned down: the same code
      // would be too. The next period's code is asked for when that period starts.
      askNextPeriod(asked, reply.validMs);
      return;
    }
    if (fields && fill(fields, reply.code, reply.validMs)) return;
    // Mutations that arrived while asking were dropped by look(); check once more.
    schedule();
  }

  // Asks again once the period of the code just received has ended (no look asks meanwhile).
  function askNextPeriod(asked, validMs) {
    waitTimer = setTimeout(() => {
      waitTimer = 0;
      passTyped(asked);
      look(true);
    }, validMs + MARGIN_MS);
  }

  // The worker's answer when it is { code, validMs } with a 6-8 digit code and 1 ms to a whole
  // period left, else null.
  async function ask() {
    try {
      const reply = await chrome.runtime.sendMessage({ type: 'autofill-code' });
      if (
        reply &&
        typeof reply.code === 'string' &&
        CODE.test(reply.code) &&
        typeof reply.validMs === 'number' &&
        reply.validMs > 0 &&
        reply.validMs <= MAX_VALID_MS
      ) {
        return reply;
      }
    } catch {
      // The worker could not be reached (the extension was reloaded or updated).
    }
    return null;
  }

  // Fields a code was asked for that the user typed into meanwhile are never filled, even when
  // emptied again. (The filled field(s) end the watch instead: see target().)
  function passTyped(asked) {
    if (asked === filledFields) return;
    for (const el of asked) if (el.value !== '') seen.add(el);
  }

  // Puts `code` into `fields`, just returned by target(). → true when filled
  function fill(fields, code, validMs) {
    const fits = fields.length === 1 ? !(fields[0].maxLength >= 0 && fields[0].maxLength < code.length) : fields.length === code.length;
    if (!fits) {
      // Split boxes for another number of digits, or a field too short: never asked for again.
      for (const el of fields) seen.add(el);
      if (fields === filledFields) stop();
      return false;
    }
    // A code that expired untouched is replaced; otherwise this is a fill, and the first one starts
    // the follow window.
    const replacing = fields === filledFields && filledFields.every((el, i) => el.value === part(i));
    if (fields !== filledFields) refreshes = 0;
    else if (replacing) refreshes += 1;
    if (!replacing) {
      fills += 1;
      if (fills === 1) {
        clearTimeout(deadline);
        deadline = setTimeout(stop, FOLLOW_MS);
      }
    }
    if (fields.length === 1) put(fields[0], code);
    else fields.forEach((el, i) => put(el, code[i]));
    filledFields = fields;
    filledCode = code;
    expired = false;
    clearTimeout(freshTimer);
    freshTimer = 0;
    // Kept current MAX_REFRESHES times per field set; after that the code stays as it is.
    if (refreshes < MAX_REFRESHES) {
      freshTimer = setTimeout(() => {
        freshTimer = 0;
        expired = true;
        look();
      }, validMs + MARGIN_MS);
    }
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
    clearTimeout(waitTimer);
    clearTimeout(freshTimer);
    clearTimeout(deadline);
  }
})();
