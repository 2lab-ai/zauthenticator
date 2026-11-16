// content/autofill.js (.prd/03-autofill.md S3): while the worker is answering a request for one
// field, no other look on the page sends a request. The script runs after lib/fieldfind.js in a
// fresh context, as the registered content script does, over the same tiny element shim as
// test/fieldfind.test.mjs (copied here: that file belongs to the field-detection tests).
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
// at again this often until a field is filled.
const SETTLE_MS = 100;
const RETRY_MS = 500;

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

// ---- one request in flight ---------------------------------------------------------------------

test('content script: two code fields, the answer delayed, a retry tick and a resize meanwhile → one request; only the first field is filled', async () => {
  const held = heldReply({ code: '123456' });
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
  // The watch ends with the fill: nothing more is asked for or filled.
  await run.fire('resize');
  await run.timers.advance(60 * 1000);
  assert.equal(run.messages.length, 1);
  assert.equal(byTag(run.doc, 'two').value, '');
  assert.equal(run.timers.pending(), 0);
  assert.equal(run.listeners.length, 0);
  assert.ok(run.observers.every((o) => o.disconnected));
});

test('content script: the field asked for leaves the page while the worker answers → the next field is not asked for meanwhile, by any kind of look', async () => {
  const held = heldReply({ code: '654321' });
  const run = await runContentScript(TWO_CODE_FIELDS, held.reply);
  assert.equal(run.messages.length, 1);
  // The page swaps the first form step for the second: the field just asked for is hidden, so
  // the finder now picks the other one, for which no code was asked yet.
  byTag(run.doc, 'one').attrs.style = 'display: none';
  await lookEverywayWhileWaiting(run);
  assert.deepEqual(run.messages, [{ type: 'autofill-code' }]);
  assert.equal(byTag(run.doc, 'two').value, '');
  // The one answer fills one field (the one the page shows now) and ends the watch.
  held.answer();
  await flush();
  await flush();
  assert.equal(byTag(run.doc, 'one').value, '');
  assert.equal(byTag(run.doc, 'two').value, '654321');
  await run.timers.advance(60 * 1000);
  assert.equal(run.messages.length, 1);
  assert.equal(run.timers.pending(), 0);
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
  assert.equal(run.timers.pending(), 0);
  assert.equal(run.listeners.length, 0);
});
