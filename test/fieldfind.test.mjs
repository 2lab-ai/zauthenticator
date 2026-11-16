// lib/fieldfind.js (one-time-code field detection, .prd/03-autofill.md S3) and the auto-fill content
// script that uses it. Both are classic scripts in the extension; fieldfind.js also loads as a
// module here, where it defines the same zauthFieldFind global. Pages are fixture snippets parsed
// into a tiny element shim that has just what fieldfind.js and content/autofill.js read.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const read = (rel) => fs.readFileSync(new URL(`../extension/${rel}`, import.meta.url), 'utf8');
const FIELDFIND_SOURCE = read('lib/fieldfind.js');
const AUTOFILL_SOURCE = read('content/autofill.js');

await import('../extension/lib/fieldfind.js');
const ff = globalThis.zauthFieldFind;

// ---- element shim ------------------------------------------------------------------------------

const VOID = new Set(['input', 'br', 'img']);

class El {
  constructor(tag, attrs = {}) {
    this.tag = tag;
    this.attrs = attrs;
    this.children = [];
    this.parentElement = null;
    this.events = [];
    this.submits = 0;
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
  submit() {
    this.submits++;
  }
  requestSubmit() {
    this.submits++;
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

const all = (root) => root.querySelectorAll('input');
const byTag = (root, t) => all(root).find((el) => el.attrs['data-t'] === t);
// The data-t labels of the field(s) findInDocument() picks, or null.
function found(html) {
  const fields = ff.findInDocument(parse(html));
  return fields && fields.map((el) => el.attrs['data-t'] ?? '?');
}
const boxes = (n, extra = '') =>
  Array.from({ length: n }, (_, i) => `<input name="otp-${i + 1}" maxlength="1" inputmode="numeric" data-t="b${i + 1}"${i === 0 ? extra : ''}>`).join('');
const labels = (n) => Array.from({ length: n }, (_, i) => `b${i + 1}`);

// ---- detection: positive -----------------------------------------------------------------------

test('autocomplete="one-time-code" is found after unrelated fields', () => {
  const page = '<form><input name="username" value="alice"><input type="password" name="password"><input autocomplete="one-time-code" data-t="hit"></form>';
  assert.deepEqual(found(page), ['hit']);
  assert.deepEqual(found('<input autocomplete="section-login ONE-TIME-CODE" data-t="hit">'), ['hit']);
});

test('name, id, aria-label or placeholder that names a code is found', () => {
  assert.deepEqual(found('<form><input type="email" name="email"><input name="otp" data-t="hit"></form>'), ['hit']);
  assert.deepEqual(found('<input id="totp-code" data-t="hit">'), ['hit']);
  assert.deepEqual(found('<input aria-label="Verification code" data-t="hit">'), ['hit']);
  assert.deepEqual(found('<input placeholder="Enter your 2FA code" data-t="hit">'), ['hit']);
  assert.deepEqual(found('<input name="mfaToken" data-t="hit">'), ['hit']);
  assert.deepEqual(found('<input name="one_time_password" data-t="hit">'), ['hit']);
  assert.deepEqual(found('<input id="authentication-code" type="tel" data-t="hit">'), ['hit']);
  assert.deepEqual(found('<input name="security code" type="number" data-t="hit">'), ['hit']);
});

test('a numeric field sized for a code is found', () => {
  assert.deepEqual(found('<input inputmode="numeric" maxlength="6" data-t="hit">'), ['hit']);
  assert.deepEqual(found('<input type="tel" maxlength="8" data-t="hit">'), ['hit']);
  assert.deepEqual(found('<input type="number" maxlength="7" data-t="hit">'), ['hit']);
  assert.deepEqual(found('<input type="TEL" maxlength=" 6 " data-t="hit">'), ['hit']);
});

test('6 to 8 single-character boxes are found as one run, the first named and marked one-time-code', () => {
  assert.deepEqual(found(`<form><input name="user" value="a"><div class="boxes">${boxes(6, ' autocomplete="one-time-code"')}</div></form>`), labels(6));
  assert.deepEqual(found(`<div>${boxes(8)}</div>`), labels(8));
  // Each box in its own wrapper.
  const wrapped = Array.from({ length: 6 }, (_, i) => `<div class="cell"><input maxlength="1" data-t="b${i + 1}"></div>`).join('');
  assert.deepEqual(found(`<div class="row">${wrapped}</div>`), labels(6));
  // A hidden input holding the joined value does not break the run.
  const withHidden = Array.from({ length: 6 }, (_, i) => `<input maxlength="1" data-t="b${i + 1}">`);
  withHidden.splice(3, 0, '<input type="hidden" name="otp">');
  assert.deepEqual(found(`<div>${withHidden.join('')}</div>`), labels(6));
});

test('the rules apply in order: one-time-code, then names, then numeric size, then boxes', () => {
  assert.deepEqual(found('<input name="verification" data-t="named"><input autocomplete="one-time-code" data-t="otc">'), ['otc']);
  assert.deepEqual(found('<input inputmode="numeric" maxlength="6" data-t="sized"><input name="otp" data-t="named">'), ['named']);
  assert.deepEqual(found(`<div>${boxes(6)}</div><input type="tel" maxlength="6" data-t="sized">`), ['sized']);
  // Within a rule the first field in document order wins.
  assert.deepEqual(found('<input name="otp" data-t="first"><input name="totp" data-t="second">'), ['first']);
});

// ---- detection: negative -----------------------------------------------------------------------

test('password, email, search and other non-code inputs are never picked', () => {
  assert.equal(found('<input type="password" name="password">'), null);
  assert.equal(found('<input type="password" name="otp" autocomplete="one-time-code">'), null);
  assert.equal(found('<input type="email" name="email">'), null);
  assert.equal(found('<input type="email" name="verification-email">'), null);
  assert.equal(found('<input type="search" name="q">'), null);
  assert.equal(found('<input type="search" name="otp-search">'), null);
  assert.equal(found('<input type="checkbox" name="remember-2fa">'), null);
  assert.equal(found('<input type="hidden" name="otp">'), null);
});

test('a plain text input, even one sized for 50 characters, is not a code field', () => {
  assert.equal(found('<input type="text" maxlength="50">'), null);
  assert.equal(found('<input type="text" name="username" maxlength="50">'), null);
  assert.equal(found('<input inputmode="numeric">'), null);
  assert.equal(found('<input inputmode="numeric" maxlength="5">'), null);
  assert.equal(found('<input type="tel" maxlength="9">'), null);
  // A named field too short for a code is not a whole field.
  assert.equal(found('<input name="otp" maxlength="4">'), null);
});

test('disabled, read-only, hidden and non-empty fields are skipped', () => {
  assert.equal(found('<input name="otp" disabled>'), null);
  assert.equal(found('<fieldset disabled><input name="otp"></fieldset>'), null);
  assert.equal(found('<input name="otp" readonly>'), null);
  assert.equal(found('<div hidden><input name="otp"></div>'), null);
  assert.equal(found('<input name="otp" style="display: none">'), null);
  assert.equal(found('<div style="visibility: hidden"><input autocomplete="one-time-code"></div>'), null);
  assert.equal(found('<input name="otp" value="123456">'), null);
  // The next eligible field is still found.
  assert.deepEqual(found('<input name="otp" value="1"><input name="totp" data-t="hit">'), ['hit']);
});

test('box runs that are too short, too long, broken or partly typed are skipped', () => {
  assert.equal(found(`<div>${boxes(5)}</div>`), null);
  assert.equal(found(`<div>${boxes(9)}</div>`), null);
  const partly = boxes(6).replace('data-t="b2"', 'data-t="b2" value="4"');
  assert.equal(found(`<div>${partly}</div>`), null);
  // Two groups of 3 are not one run.
  assert.equal(found(`<div>${boxes(3)}</div><div>${boxes(3)}</div>`), null);
  // A visible text field in the middle ends the run.
  assert.equal(found(`<div>${boxes(3)}<input name="x">${boxes(3)}</div>`), null);
});

test('findOtpField reads plain attribute maps (no DOM needed)', () => {
  const field = (attrs, extra = {}) => ({ attrs, value: '', disabled: false, readOnly: false, visible: true, group: 'g', ...extra });
  assert.deepEqual(ff.findOtpField([field({ name: 'user' }), field({ autocomplete: 'one-time-code' })]), [1]);
  assert.deepEqual(ff.findOtpField(Array.from({ length: 6 }, () => field({ maxlength: '1' }))), [0, 1, 2, 3, 4, 5]);
  assert.equal(ff.findOtpField([field({ name: 'otp' }, { visible: false })]), null);
  assert.equal(ff.findOtpField([field({ name: 'otp' }, { value: '1' })]), null);
  assert.equal(ff.findOtpField([]), null);
  // Missing or odd attribute values are read as absent.
  assert.equal(ff.findOtpField([{ attrs: { name: 42 }, value: '', visible: true }]), null);
});

// ---- content/autofill.js -----------------------------------------------------------------------

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

// Runs lib/fieldfind.js then content/autofill.js in one fresh context, as the registered
// content script does. `reply` is the worker's answer (or a function returning it).
async function runContentScript(html, reply) {
  const doc = parse(html);
  const timers = fakeTimers();
  const messages = [];
  const observers = [];
  const context = vm.createContext({
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
    await timers.advance(1000);
  };
  return { doc, timers, messages, observers, mutate };
}

test('content script: fills the code field once with input and change events, nothing else', async () => {
  const page = '<form><input name="username" value="alice" data-t="user"><input name="otp" data-t="otp"></form>';
  const run = await runContentScript(page, { code: '123456' });
  assert.deepEqual(run.messages, [{ type: 'autofill-code' }]);
  const otp = byTag(run.doc, 'otp');
  assert.equal(otp.value, '123456');
  assert.deepEqual(otp.events, ['input', 'change']);
  assert.deepEqual(byTag(run.doc, 'user').events, []);
  assert.equal(byTag(run.doc, 'user').value, 'alice');
  assert.equal(run.doc.children[0].submits, 0);
  // The page clears the field again: it was filled once, so it stays empty.
  otp.value = '';
  await run.mutate();
  assert.equal(otp.value, '');
  assert.equal(run.messages.length, 1);
});

test('content script: no code (locked, idle, unbound) → nothing filled and the watch stops', async () => {
  const run = await runContentScript('<input name="otp" data-t="otp">', { code: null });
  assert.equal(run.messages.length, 1);
  assert.equal(byTag(run.doc, 'otp').value, '');
  assert.deepEqual(byTag(run.doc, 'otp').events, []);
  assert.ok(run.observers.every((o) => o.disconnected));
  assert.equal(run.timers.pending(), 0);
});

test('content script: anything but 6 to 8 digits from the worker is ignored', async () => {
  for (const reply of [{ code: '12345' }, { code: '123456789' }, { code: '12a456' }, { code: 123456 }, undefined, 'x']) {
    const run = await runContentScript('<input name="otp" data-t="otp">', reply);
    assert.equal(byTag(run.doc, 'otp').value, '', JSON.stringify(reply));
  }
  const failing = await runContentScript('<input name="otp" data-t="otp">', () => {
    throw new Error('Could not establish connection');
  });
  assert.equal(byTag(failing.doc, 'otp').value, '');
});

test('content script: a field that is not empty is never touched, and no code is asked for', async () => {
  const run = await runContentScript('<input name="otp" value="99" data-t="otp">', { code: '123456' });
  assert.equal(run.messages.length, 0);
  assert.equal(byTag(run.doc, 'otp').value, '99');
});

test('content script: a value typed while the worker answers is kept', async () => {
  const run = await runContentScript('<input name="otp" data-t="otp">', (doc) => {
    byTag(doc, 'otp').value = '4';
    return { code: '123456' };
  });
  assert.equal(byTag(run.doc, 'otp').value, '4');
  assert.deepEqual(byTag(run.doc, 'otp').events, []);
});

test('content script: a field added later is filled; after 60 s nothing is watched', async () => {
  const run = await runContentScript('<form id="f"></form>', { code: '654321' });
  assert.equal(run.messages.length, 0);
  assert.ok(run.observers.length === 1 && run.observers[0].options.subtree && run.observers[0].options.childList);
  const late = new El('input', { autocomplete: 'one-time-code' });
  run.doc.children[0].append(late);
  await run.mutate();
  assert.equal(late.value, '654321');

  const idle = await runContentScript('<form></form>', { code: '654321' });
  await idle.timers.advance(60 * 1000);
  assert.ok(idle.observers.every((o) => o.disconnected));
  const tooLate = new El('input', { name: 'otp' });
  idle.doc.children[0].append(tooLate);
  await idle.mutate();
  assert.equal(tooLate.value, '');
  assert.equal(idle.messages.length, 0);
});

test('content script: split boxes get one digit each', async () => {
  const run = await runContentScript(`<div>${boxes(6)}</div>`, { code: '102938' });
  assert.deepEqual(labels(6).map((t) => byTag(run.doc, t).value), ['1', '0', '2', '9', '3', '8']);
  assert.deepEqual(byTag(run.doc, 'b6').events, ['input', 'change']);
  // An 8-digit code does not fit 6 boxes: nothing is filled.
  const mismatch = await runContentScript(`<div>${boxes(6)}</div>`, { code: '10293847' });
  assert.ok(labels(6).every((t) => byTag(mismatch.doc, t).value === ''));
});

test('content script: a single field whose maxlength is shorter than the code is not filled', async () => {
  const run = await runContentScript('<input type="tel" maxlength="6" data-t="f">', { code: '12345678' });
  assert.equal(byTag(run.doc, 'f').value, '');
});

// ---- packaging ---------------------------------------------------------------------------------

test('every registered content script file compiles as a classic script (no import or export)', () => {
  const worker = read('lib/autofill-worker.js');
  const list = worker.match(/const CONTENT_SCRIPTS = \[([^\]]*)\]/);
  assert.ok(list, 'lib/autofill-worker.js declares CONTENT_SCRIPTS');
  const files = [...list[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
  assert.deepEqual(files, ['lib/fieldfind.js', 'content/autofill.js']);
  for (const file of files) {
    assert.doesNotThrow(() => new vm.Script(read(file), { filename: file }), file);
  }
});

test('fieldfind.js defines exactly one global, frozen', () => {
  const context = vm.createContext({});
  vm.runInContext(FIELDFIND_SOURCE, context);
  assert.deepEqual(Object.keys(context), ['zauthFieldFind']);
  assert.ok(Object.isFrozen(context.zauthFieldFind));
  assert.equal(typeof context.zauthFieldFind.findOtpField, 'function');
  assert.equal(typeof context.zauthFieldFind.findInDocument, 'function');
});
