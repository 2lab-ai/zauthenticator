// content/autofill.js (.prd/03-autofill.md S3 and "Fresh code and retry after a failed attempt"):
// while the worker is answering a request for one field, no other look on the page sends a
// request; a code with under 3 s left is not filled, the next one is; a filled code is replaced
// when its period ends while the field still holds it; a field the page empties or replaces is
// filled again, at most 4 fills in the 5 minutes after the first; a value the user typed is never
// touched. The script runs after lib/fieldfind.js in a fresh context, as the registered content
// script does, over the same tiny element shim as test/fieldfind.test.mjs (copied here: that file
// belongs to the field-detection tests).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const read = (rel) => fs.readFileSync(new URL(`../extension/${rel}`, import.meta.url), 'utf8');
const FIELDFIND_SOURCE = read('lib/fieldfind.js');
const AUTOFILL_SOURCE = read('content/autofill.js');

// ---- element shim ------------------------------------------------------------------------------

const VOID = new Set(['input', 'br', 'img']);

class El {
  constructor(tag, attrs = {}) {
    this.tag = tag;
    this.attrs = attrs;
    this.children = [];
    this.parentElement = null;
    this.events = [];
    this.currentValue = attrs.value ?? '';
  }
  append(child) {
    child.parentElement = this;
    this.children.push(child);
  }
  // Takes the element out of the page (the test's own helper; the script never calls it).
  detach() {
    const parent = this.parentElement;
    parent.children.splice(parent.children.indexOf(this), 1);
    this.parentElement = null;
  }
  // The top of the tree the element is in: the document while it is in the page.
  getRootNode() {
    let node = this;
    while (node.parentElement) node = node.parentElement;
    return node;
  }
  getAttribute(name) {
    return Object.hasOwn(this.attrs, name) ? this.attrs[name] : null;
  }
  hasAttribute(name) {
    return Object.hasOwn(this.attrs, name);
  }
  querySelectorAll(selector) {
    assert.equal(selector, 'input', 'the shim answers querySelectorAll("input") only');
    const out = [];
    const walk = (node) => {
      for (const child of node.children) {
        if (child.tag === 'input') out.push(child);
        walk(child);
      }
    };
    walk(this);
    return out;
  }
  get value() {
    return this.currentValue;
  }
  set value(v) {
    this.currentValue = String(v);
  }
  get readOnly() {
    return this.hasAttribute('readonly');
  }
  get maxLength() {
    const raw = this.getAttribute('maxlength');
    return raw !== null && /^\d+$/.test(raw.trim()) ? Number(raw) : -1;
  }
  matches(selector) {
    assert.equal(selector, ':disabled', 'the shim answers matches(":disabled") only');
    if (this.hasAttribute('disabled')) return true;
    for (let node = this.parentElement; node; node = node.parentElement) {
      if (node.tag === 'fieldset' && node.hasAttribute('disabled')) return true;
    }
    return false;
  }
  checkVisibility() {
    if (this.tag === 'input' && (this.getAttribute('type') ?? '').toLowerCase() === 'hidden') return false;
    for (let node = this; node; node = node.parentElement) {
      const style = node.getAttribute('style') ?? '';
      if (node.hasAttribute('hidden') || /display:\s*none|visibility:\s*hidden/.test(style)) return false;
    }
    return true;
  }
  dispatchEvent(event) {
    this.events.push(`${event.type}${event.bubbles ? '' : ' (not bubbling)'}`);
    return true;
  }
}

// A snippet of plain tags ("<form><input name=\"otp\"></form>") → the document root.
function parse(html) {
  const root = new El('#document');
  const stack = [root];
  for (const [, closing, tag, rest] of html.matchAll(/<(\/?)([a-z]+)([^>]*)>/gi)) {
    if (closing) {
      stack.pop();
      continue;
    }
    const attrs = {};
    for (const [, name, value] of rest.matchAll(/([a-z][a-z-]*)(?:\s*=\s*"([^"]*)")?/gi)) attrs[name.toLowerCase()] = value ?? '';
    const el = new El(tag.toLowerCase(), attrs);
    stack.at(-1).append(el);
    if (!VOID.has(el.tag)) stack.push(el);
  }
  return root;
}

const byTag = (root, t) => root.querySelectorAll('input').find((el) => el.attrs['data-t'] === t);

// ---- content script sandbox --------------------------------------------------------------------

// content/autofill.js: a look waits this long after a burst of changes, and the page is looked
// at again this often while the script runs. Fields are looked for during the first minute; after
// the first fill the filled field is followed for 5 minutes; a code with less than 3 s left is not
// filled, and a code is asked for 250 ms after a period ends.
const SETTLE_MS = 100;
const RETRY_MS = 500;
const WATCH_MS = 60 * 1000;
const FOLLOW_MS = 5 * 60 * 1000;
const MARGIN_MS = 250;
// The longest a code stays valid (a 300-second period): with it, no keep-fresh request comes
// before the follow window ends.
const LONGEST_VALID_MS = 300 * 1000;

const flush = () => new Promise((resolve) => setImmediate(resolve));

// Timers on a manual clock, so the 60-second watch never holds the test process open.
function fakeTimers() {
  let now = 0;
  let seq = 0;
  const timers = new Map();
  return {
    setTimeout(fn, ms = 0) {
      seq += 1;
      timers.set(seq, { at: now + ms, fn });
      return seq;
    },
    clearTimeout(id) {
      timers.delete(id);
    },
    pending: () => timers.size,
    async advance(ms) {
      const end = now + ms;
      for (;;) {
        const next = [...timers].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
        if (!next) break;
        timers.delete(next[0]);
        now = next[1].at;
        next[1].fn();
        await flush();
      }
      now = end;
      await flush();
    },
  };
}

// The worker's answer, held back until answer() is called.
function heldReply(reply) {
  let release;
  const answered = new Promise((resolve) => (release = resolve));
  return { reply: () => answered, answer: () => release(reply) };
}

// A worker the test answers one request at a time: answer(reply) answers the oldest open request
// and lets the script act on it.
function manualWorker() {
  const open = [];
  return {
    reply: () => new Promise((resolve) => open.push(resolve)),
    async answer(reply) {
      assert.ok(open.length > 0, 'a request is open');
      open.shift()(reply);
      await flush();
      await flush();
    },
    open: () => open.length,
  };
}

// A worker that answers every request at once with the next code (100001, 100002, ...), each with
// `validMs` left.
function countingWorker(validMs) {
  let n = 0;
  return () => {
    n += 1;
    return { code: String(100000 + n), validMs };
  };
}

// The script has stopped and left nothing behind: no timer, no listener, no observer.
function assertStopped(run, what) {
  assert.equal(run.timers.pending(), 0, `${what}: timers left`);
  assert.equal(run.listeners.length, 0, `${what}: listeners left`);
  assert.ok(run.observers.every((o) => o.disconnected), `${what}: observer still connected`);
}

// Runs lib/fieldfind.js then content/autofill.js in one fresh context. `reply` is the worker's
// answer (or a function returning it, or a promise of it).
async function runContentScript(html, reply) {
  const doc = parse(html);
  const timers = fakeTimers();
  const messages = [];
  const observers = [];
  // Event listeners on window and document: { target, type, fn }.
  const listeners = [];
  const eventTarget = (target) => ({
    addEventListener(type, fn) {
      listeners.push({ target, type, fn });
    },
    removeEventListener(type, fn) {
      const i = listeners.findIndex((l) => l.target === target && l.type === type && l.fn === fn);
      if (i !== -1) listeners.splice(i, 1);
    },
  });
  Object.assign(doc, eventTarget('document'));
  const context = vm.createContext({
    window: eventTarget('window'),
    document: doc,
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout,
    Event: class {
      constructor(type, init = {}) {
        this.type = type;
        this.bubbles = Boolean(init.bubbles);
      }
    },
    MutationObserver: class {
      constructor(callback) {
        this.callback = callback;
        this.disconnected = false;
        observers.push(this);
      }
      observe(target, options) {
        this.target = target;
        this.options = options;
      }
      disconnect() {
        this.disconnected = true;
      }
    },
    chrome: {
      runtime: {
        async sendMessage(message) {
          // Copied out of the context's realm so deepEqual compares plain values.
          messages.push(JSON.parse(JSON.stringify(message)));
          return typeof reply === 'function' ? reply(doc) : reply;
        },
      },
    },
  });
  vm.runInContext(FIELDFIND_SOURCE, context, { filename: 'lib/fieldfind.js' });
  vm.runInContext(AUTOFILL_SOURCE, context, { filename: 'content/autofill.js' });
  await flush();
  await flush();
  const mutate = async () => {
    for (const o of observers) if (!o.disconnected) o.callback([]);
    await timers.advance(SETTLE_MS);
  };
  // Dispatches an event of `type` to the listeners on window and document; no time passes.
  const fire = async (type) => {
    for (const l of listeners.filter((x) => x.type === type)) l.fn({ type });
    await flush();
  };
  return { doc, timers, messages, observers, mutate, fire, listeners };
}

// Every kind of look the script makes while the worker answers: a retry tick, each window or
// document event, and a DOM change. The watch is still on throughout (its listeners and timers
// are in place), so no request means none was sent, not that nothing looked.
async function lookEverywayWhileWaiting(run) {
  await run.timers.advance(RETRY_MS + 50);
  for (const type of ['resize', 'load', 'pageshow', 'visibilitychange']) {
    assert.ok(run.listeners.some((l) => l.type === type), `still listening for ${type}`);
    await run.fire(type);
    await run.timers.advance(SETTLE_MS + 50);
  }
  assert.ok(run.observers.some((o) => !o.disconnected), 'still observing the page');
  await run.mutate();
  await run.timers.advance(RETRY_MS);
  assert.ok(run.timers.pending() > 0, 'still retrying');
}

const TWO_CODE_FIELDS =
  '<form><input name="username" value="alice"><input autocomplete="one-time-code" data-t="one"><input autocomplete="one-time-code" data-t="two"></form>';
const ONE_CODE_FIELD = '<form data-t="form"><input name="username" value="alice"><input autocomplete="one-time-code" data-t="one"></form>';

// The form of ONE_CODE_FIELD.
const formOf = (doc) => doc.children.find((el) => el.attrs['data-t'] === 'form');

// ---- one request in flight ---------------------------------------------------------------------

test('content script: two code fields, the answer delayed, a retry tick and a resize meanwhile → one request; only the first field is filled', async () => {
  const held = heldReply({ code: '123456', validMs: LONGEST_VALID_MS });
  const run = await runContentScript(TWO_CODE_FIELDS, held.reply);
  assert.deepEqual(run.messages, [{ type: 'autofill-code' }]);
  // A retry tick, then a resize, while the worker has not answered yet.
  await run.timers.advance(RETRY_MS + 50);
  await run.fire('resize');
  await run.timers.advance(SETTLE_MS + 50);
  assert.equal(run.messages.length, 1);
  assert.equal(byTag(run.doc, 'one').value, '');
  held.answer();
  await flush();
  await flush();
  assert.equal(byTag(run.doc, 'one').value, '123456');
  assert.deepEqual(byTag(run.doc, 'one').events, ['input', 'change']);
  assert.equal(byTag(run.doc, 'two').value, '');
  assert.deepEqual(byTag(run.doc, 'two').events, []);
  // While the filled field is in the page no other field is filled, though the finder now picks
  // the empty one; nothing more is asked for (the code is valid past the follow window).
  await run.fire('resize');
  await run.timers.advance(FOLLOW_MS - 1000);
  assert.equal(run.messages.length, 1);
  assert.equal(byTag(run.doc, 'two').value, '');
  assert.ok(run.timers.pending() > 0, 'still following the filled field');
  // 5 minutes after the fill the watch ends.
  await run.timers.advance(1000);
  assert.equal(run.messages.length, 1);
  assert.deepEqual(byTag(run.doc, 'one').events, ['input', 'change']);
  assertStopped(run, 'after the follow window');
});

test('content script: the field asked for leaves the page while the worker answers → the next field is not asked for meanwhile, by any kind of look', async () => {
  const held = heldReply({ code: '654321', validMs: LONGEST_VALID_MS });
  const run = await runContentScript(TWO_CODE_FIELDS, held.reply);
  assert.equal(run.messages.length, 1);
  // The page swaps the first form step for the second: the field just asked for is hidden, so
  // the finder now picks the other one, for which no code was asked yet.
  byTag(run.doc, 'one').attrs.style = 'display: none';
  await lookEverywayWhileWaiting(run);
  assert.deepEqual(run.messages, [{ type: 'autofill-code' }]);
  assert.equal(byTag(run.doc, 'two').value, '');
  // The one answer fills one field (the one the page shows now).
  held.answer();
  await flush();
  await flush();
  assert.equal(byTag(run.doc, 'one').value, '');
  assert.equal(byTag(run.doc, 'two').value, '654321');
  await run.timers.advance(FOLLOW_MS);
  assert.equal(run.messages.length, 1);
  assert.equal(byTag(run.doc, 'one').value, '');
  assertStopped(run, 'after the follow window');
});

test('content script: no code in the delayed answer → still one request, nothing filled, the watch stops', async () => {
  const held = heldReply({ code: null });
  const run = await runContentScript(TWO_CODE_FIELDS, held.reply);
  byTag(run.doc, 'one').attrs.style = 'display: none';
  await lookEverywayWhileWaiting(run);
  assert.equal(run.messages.length, 1);
  held.answer();
  await flush();
  await flush();
  await run.timers.advance(60 * 1000);
  assert.equal(run.messages.length, 1);
  assert.equal(byTag(run.doc, 'one').value, '');
  assert.equal(byTag(run.doc, 'two').value, '');
  assertStopped(run, 'after { code: null }');
});

test('content script: an answer without a usable validMs is no answer → nothing filled, the watch stops', async () => {
  for (const reply of [
    { code: '123456' },
    { code: '123456', validMs: 0 },
    { code: '123456', validMs: -1 },
    { code: '123456', validMs: 300 * 1000 + 1 },
    { code: '123456', validMs: '5000' },
    { code: '123456', validMs: Number.NaN },
  ]) {
    const run = await runContentScript(ONE_CODE_FIELD, reply);
    await run.timers.advance(RETRY_MS * 4);
    assert.equal(run.messages.length, 1, JSON.stringify(reply));
    assert.equal(byTag(run.doc, 'one').value, '', JSON.stringify(reply));
    assertStopped(run, JSON.stringify(reply));
  }
});

// ---- a fresh code ------------------------------------------------------------------------------

test('content script: a code with 1.5 s left is not filled; the next period\'s code is asked for 1.75 s later and filled', async () => {
  const worker = manualWorker();
  const run = await runContentScript(ONE_CODE_FIELD, worker.reply);
  const one = byTag(run.doc, 'one');
  assert.equal(run.messages.length, 1);
  await worker.answer({ code: '111111', validMs: 1500 });
  assert.equal(one.value, '');
  // Retry ticks and page events during the wait ask for nothing.
  await run.timers.advance(1000);
  await run.fire('resize');
  await run.mutate();
  await run.timers.advance(1500 + MARGIN_MS - 1100 - 1);
  assert.equal(run.messages.length, 1);
  assert.equal(one.value, '');
  await run.timers.advance(1);
  assert.equal(run.messages.length, 2);
  await worker.answer({ code: '222222', validMs: 30 * 1000 - MARGIN_MS });
  assert.equal(one.value, '222222');
  assert.deepEqual(one.events, ['input', 'change']);
});

test('content script: the field leaves the page during the wait for the next period → a later field\'s late code is waited for again', async () => {
  const worker = manualWorker();
  const run = await runContentScript(ONE_CODE_FIELD, worker.reply);
  const one = byTag(run.doc, 'one');
  await worker.answer({ code: '111111', validMs: 1500 });
  one.detach();
  await run.timers.advance(1500 + MARGIN_MS);
  assert.equal(run.messages.length, 1);
  const fresh = new El('input', { autocomplete: 'one-time-code', 'data-t': 'fresh' });
  formOf(run.doc).append(fresh);
  await run.mutate();
  assert.equal(run.messages.length, 2);
  await worker.answer({ code: '222222', validMs: 1200 });
  assert.equal(fresh.value, '');
  await run.timers.advance(1200 + MARGIN_MS);
  assert.equal(run.messages.length, 3);
  await worker.answer({ code: '333333', validMs: 30 * 1000 - MARGIN_MS });
  assert.equal(fresh.value, '333333');
  assert.equal(one.value, '');
});

test('content script: every code has under 3 s left (a 2-second period) → filled after one wait, and the watch still ends', async () => {
  const run = await runContentScript(ONE_CODE_FIELD, countingWorker(2000));
  const one = byTag(run.doc, 'one');
  assert.equal(one.value, '');
  await run.timers.advance(2000 + MARGIN_MS);
  assert.equal(run.messages.length, 2);
  assert.equal(one.value, '100002');
  // Kept current every period until the follow window ends.
  await run.timers.advance(FOLLOW_MS);
  // Far fewer requests than one per look (one per 500 ms): one or two per period.
  assert.ok(run.messages.length <= 2 + FOLLOW_MS / 2000, `${run.messages.length} requests`);
  assertStopped(run, 'after the follow window');
});

test('content script: the filled code is replaced by the next one when its period ends, while the field still holds it', async () => {
  const worker = manualWorker();
  const run = await runContentScript(ONE_CODE_FIELD, worker.reply);
  const one = byTag(run.doc, 'one');
  await worker.answer({ code: '111111', validMs: 10 * 1000 });
  assert.equal(one.value, '111111');
  await run.timers.advance(10 * 1000 + MARGIN_MS - 1);
  assert.equal(run.messages.length, 1);
  await run.timers.advance(1);
  assert.equal(run.messages.length, 2);
  await worker.answer({ code: '222222', validMs: 30 * 1000 - MARGIN_MS });
  assert.equal(one.value, '222222');
  assert.deepEqual(one.events, ['input', 'change', 'input', 'change']);
  // And again at the end of the next period.
  await run.timers.advance(30 * 1000);
  assert.equal(run.messages.length, 3);
  await worker.answer({ code: '333333', validMs: 30 * 1000 - MARGIN_MS });
  assert.equal(one.value, '333333');
});

test('content script: { code: null } for a fresher code → the filled code stays, the watch stops', async () => {
  const worker = manualWorker();
  const run = await runContentScript(ONE_CODE_FIELD, worker.reply);
  const one = byTag(run.doc, 'one');
  await worker.answer({ code: '111111', validMs: 10 * 1000 });
  await run.timers.advance(10 * 1000 + MARGIN_MS);
  assert.equal(run.messages.length, 2);
  await worker.answer({ code: null });
  assert.equal(one.value, '111111');
  assert.deepEqual(one.events, ['input', 'change']);
  assertStopped(run, 'after { code: null }');
});

// ---- the user's own value ----------------------------------------------------------------------

test('content script: the user typed over the filled code → it is never replaced, the watch stops', async () => {
  const worker = manualWorker();
  const run = await runContentScript(ONE_CODE_FIELD, worker.reply);
  const one = byTag(run.doc, 'one');
  await worker.answer({ code: '111111', validMs: 10 * 1000 });
  one.value = '999999';
  await run.timers.advance(60 * 1000);
  assert.equal(run.messages.length, 1);
  assert.equal(one.value, '999999');
  assertStopped(run, 'after the user typed');
});

test('content script: the user types while a fresher code or a refill is being asked for → the answer is not written', async () => {
  // While the code that replaces an expired one is asked for.
  {
    const worker = manualWorker();
    const run = await runContentScript(ONE_CODE_FIELD, worker.reply);
    const one = byTag(run.doc, 'one');
    await worker.answer({ code: '111111', validMs: 10 * 1000 });
    await run.timers.advance(10 * 1000 + MARGIN_MS);
    assert.equal(run.messages.length, 2);
    one.value = '999999';
    await worker.answer({ code: '222222', validMs: 30 * 1000 - MARGIN_MS });
    assert.equal(one.value, '999999');
    assertStopped(run, 'typed during the keep-fresh request');
  }
  // While the code for an emptied field is asked for.
  {
    const worker = manualWorker();
    const run = await runContentScript(ONE_CODE_FIELD, worker.reply);
    const one = byTag(run.doc, 'one');
    await worker.answer({ code: '111111', validMs: 20 * 1000 });
    one.value = '';
    await run.timers.advance(RETRY_MS);
    assert.equal(run.messages.length, 2);
    one.value = '9';
    await worker.answer({ code: '222222', validMs: 19 * 1000 });
    assert.equal(one.value, '9');
    assertStopped(run, 'typed during the refill request');
  }
});

test('content script: a field the user typed into before any fill is never filled, even once emptied again', async () => {
  // Typed while the first code was asked for.
  {
    const worker = manualWorker();
    const run = await runContentScript(ONE_CODE_FIELD, worker.reply);
    const one = byTag(run.doc, 'one');
    one.value = '12';
    await worker.answer({ code: '111111', validMs: 20 * 1000 });
    assert.equal(one.value, '12');
    one.value = '';
    await run.timers.advance(RETRY_MS * 4);
    assert.equal(run.messages.length, 1);
    assert.equal(one.value, '');
  }
  // Typed while the next period was waited for.
  {
    const worker = manualWorker();
    const run = await runContentScript(ONE_CODE_FIELD, worker.reply);
    const one = byTag(run.doc, 'one');
    await worker.answer({ code: '111111', validMs: 1500 });
    one.value = '12';
    await run.timers.advance(1500 + MARGIN_MS);
    assert.equal(run.messages.length, 1);
    one.value = '';
    await run.timers.advance(RETRY_MS * 4);
    assert.equal(run.messages.length, 1);
    assert.equal(one.value, '');
  }
});

// ---- retry after a failed attempt --------------------------------------------------------------

test('content script: the page empties the filled field (a rejected code) → one more request, filled with the fresh code', async () => {
  const worker = manualWorker();
  const run = await runContentScript(ONE_CODE_FIELD, worker.reply);
  const one = byTag(run.doc, 'one');
  await worker.answer({ code: '111111', validMs: 20 * 1000 });
  assert.equal(one.value, '111111');
  // The page's own script clears the field: no DOM change, no event; the next look sees it.
  one.value = '';
  await run.timers.advance(RETRY_MS);
  assert.equal(run.messages.length, 2);
  await worker.answer({ code: '222222', validMs: 19 * 1000 });
  assert.equal(one.value, '222222');
  assert.deepEqual(one.events, ['input', 'change', 'input', 'change']);
  await run.timers.advance(5000);
  assert.equal(run.messages.length, 2);
});

test('content script: the page replaces the filled field with a new one → the new one is filled; the old one is left alone', async () => {
  const worker = manualWorker();
  const run = await runContentScript(ONE_CODE_FIELD, worker.reply);
  const one = byTag(run.doc, 'one');
  await worker.answer({ code: '111111', validMs: 20 * 1000 });
  one.detach();
  const fresh = new El('input', { autocomplete: 'one-time-code', 'data-t': 'fresh' });
  formOf(run.doc).append(fresh);
  await run.mutate();
  assert.equal(run.messages.length, 2);
  await worker.answer({ code: '222222', validMs: 19 * 1000 });
  assert.equal(fresh.value, '222222');
  assert.equal(one.value, '111111');
  assert.deepEqual(one.events, ['input', 'change']);
});

test('content script: while the filled field is in the page (hidden and emptied), no other field is filled; once it is gone the next one is', async () => {
  const worker = manualWorker();
  const run = await runContentScript(TWO_CODE_FIELDS, worker.reply);
  const one = byTag(run.doc, 'one');
  const two = byTag(run.doc, 'two');
  await worker.answer({ code: '111111', validMs: 60 * 1000 });
  assert.equal(one.value, '111111');
  // The page hides and empties it and shows the other one, which the finder now picks.
  one.attrs.style = 'display: none';
  one.value = '';
  await run.mutate();
  await run.timers.advance(5000);
  assert.equal(run.messages.length, 1);
  assert.equal(two.value, '');
  assert.equal(one.value, '');
  // The first field leaves the page: the other one is a new field to fill.
  one.detach();
  await run.mutate();
  assert.equal(run.messages.length, 2);
  await worker.answer({ code: '222222', validMs: 50 * 1000 });
  assert.equal(two.value, '222222');
  assert.equal(one.value, '');
});

test('content script: split boxes are kept current and filled again like one field; one box typed into ends the watch', async () => {
  const boxes = Array.from({ length: 6 }, (_, i) => `<input maxlength="1" data-t="b${i + 1}">`).join('');
  const worker = manualWorker();
  const run = await runContentScript(`<div aria-label="Verification code">${boxes}</div>`, worker.reply);
  const box = (i) => byTag(run.doc, `b${i + 1}`);
  const values = () => Array.from({ length: 6 }, (_, i) => box(i).value).join('');
  await worker.answer({ code: '123456', validMs: 20 * 1000 });
  assert.equal(values(), '123456');
  // The page empties every box: one more request, one digit each again.
  for (let i = 0; i < 6; i++) box(i).value = '';
  await run.timers.advance(RETRY_MS);
  assert.equal(run.messages.length, 2);
  await worker.answer({ code: '234567', validMs: 9000 });
  assert.equal(values(), '234567');
  // The period ends while every box still holds its digit: replaced.
  await run.timers.advance(9000 + MARGIN_MS);
  assert.equal(run.messages.length, 3);
  await worker.answer({ code: '345678', validMs: 30 * 1000 - MARGIN_MS });
  assert.equal(values(), '345678');
  // Some boxes emptied, not all: nothing is asked for yet.
  box(0).value = '';
  await run.timers.advance(RETRY_MS * 2);
  assert.equal(run.messages.length, 3);
  // The user types into one box: nothing is touched again.
  box(0).value = '9';
  await run.timers.advance(RETRY_MS);
  assert.equal(values(), '945678');
  assertStopped(run, 'after the user typed into a box');
});

test('content script: at most 4 fills (1 + 3 refills); keeping a code current is not one of them', async () => {
  const worker = manualWorker();
  const run = await runContentScript(ONE_CODE_FIELD, worker.reply);
  const one = byTag(run.doc, 'one');
  await worker.answer({ code: '100001', validMs: 10 * 1000 });
  // A keep-fresh replacement.
  await run.timers.advance(10 * 1000 + MARGIN_MS);
  await worker.answer({ code: '100002', validMs: 20 * 1000 });
  assert.equal(one.value, '100002');
  // Three refills of an emptied field, with one more keep-fresh replacement between them.
  for (const code of ['100003', '100004', '100005']) {
    one.value = '';
    await run.timers.advance(RETRY_MS);
    await worker.answer({ code, validMs: 20 * 1000 });
    assert.equal(one.value, code);
    if (code === '100003') {
      await run.timers.advance(20 * 1000 + MARGIN_MS);
      await worker.answer({ code: '100006', validMs: 20 * 1000 });
      assert.equal(one.value, '100006');
    }
  }
  assert.equal(run.messages.length, 6);
  // A fifth fill is not made: the watch ends.
  one.value = '';
  await run.timers.advance(RETRY_MS * 4);
  assert.equal(run.messages.length, 6);
  assert.equal(one.value, '');
  assertStopped(run, 'after the fourth fill was emptied');
});

test('content script: the follow window ends 5 minutes after the first fill; a field emptied after that is not filled again', async () => {
  const worker = manualWorker();
  const run = await runContentScript(ONE_CODE_FIELD, worker.reply);
  const one = byTag(run.doc, 'one');
  await worker.answer({ code: '111111', validMs: LONGEST_VALID_MS });
  // Emptied 10 s before the end: filled again.
  await run.timers.advance(FOLLOW_MS - 10 * 1000);
  one.value = '';
  await run.timers.advance(RETRY_MS);
  assert.equal(run.messages.length, 2);
  await worker.answer({ code: '222222', validMs: LONGEST_VALID_MS });
  assert.equal(one.value, '222222');
  // The window is counted from the first fill, not the latest.
  await run.timers.advance(10 * 1000);
  assertStopped(run, 'after the follow window');
  one.value = '';
  await run.timers.advance(60 * 1000);
  assert.equal(run.messages.length, 2);
  assert.equal(one.value, '');
});

test('content script: no field within the first minute → the watch ends, also while it waits for the next period', async () => {
  const worker = manualWorker();
  const run = await runContentScript('<form data-t="form"><input name="username" value="alice"></form>', worker.reply);
  await run.timers.advance(WATCH_MS - 1000);
  assert.equal(run.messages.length, 0);
  const late = new El('input', { autocomplete: 'one-time-code', 'data-t': 'late' });
  formOf(run.doc).append(late);
  await run.mutate();
  assert.equal(run.messages.length, 1);
  // Too little left: the next period would start after the minute is over.
  await worker.answer({ code: '111111', validMs: 1500 });
  await run.timers.advance(2000);
  assert.equal(run.messages.length, 1);
  assert.equal(late.value, '');
  assertStopped(run, 'after the first minute');
});
