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
    this.listeners = [];
    this.submits = 0;
    this.currentValue = attrs.value ?? '';
  }
  append(child) {
    child.parentElement = this;
    this.children.push(child);
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
  // content/autofill.js listens on the fields it filled for the user's own edits.
  addEventListener(type, fn) {
    this.listeners.push({ type, fn });
  }
  removeEventListener(type, fn) {
    const i = this.listeners.findIndex((l) => l.type === type && l.fn === fn);
    if (i !== -1) this.listeners.splice(i, 1);
  }
  dispatchEvent(event) {
    this.events.push(`${event.type}${event.bubbles ? '' : ' (not bubbling)'}`);
    for (const l of this.listeners.filter((x) => x.type === event.type)) l.fn(event);
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
// Split boxes named otp-1, otp-2, ...: the names say they hold a code. `extra` goes on the first.
const boxes = (n, extra = '') =>
  Array.from({ length: n }, (_, i) => `<input name="otp-${i + 1}" maxlength="1" inputmode="numeric" data-t="b${i + 1}"${i === 0 ? extra : ''}>`).join('');
// The same boxes with no name: nothing in them says code (a PIN entry looks like this).
const bareBoxes = (n, extra = '', tag = 'b') =>
  Array.from({ length: n }, (_, i) => `<input maxlength="1" inputmode="numeric" data-t="${tag}${i + 1}"${i === 0 ? extra : ''}>`).join('');
const labels = (n, tag = 'b') => Array.from({ length: n }, (_, i) => `${tag}${i + 1}`);

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
});

// Rule 2 reads otp, totp, mfa and 2fa as whole words: names are split at anything that is not a
// letter or digit, at camelCase humps and where letters meet digits.
test('otp, totp, mfa and 2fa are found as whole words in any spelling of a name', () => {
  for (const name of ['otp', 'OTP', 'otpCode', 'OTPCode', 'otp_code', 'otp-code', 'mfa-token', 'mfaCode', 'MFA', 'totp', 'userTotp', 'totp_value', '2fa', '2faCode', 'enter2FA', 'code-2fa', 'otp1', 'login.otp']) {
    assert.deepEqual(found(`<input name="${name}" data-t="hit">`), ['hit'], name);
  }
  assert.deepEqual(found('<input placeholder="Enter your MFA code" data-t="hit">'), ['hit']);
  assert.deepEqual(found('<input aria-label="TOTP" data-t="hit">'), ['hit']);
});

test('otp, totp, mfa and 2fa inside another word are not a code name', () => {
  for (const name of ['footprint', 'hotpot', 'spotprice', 'notpaid', 'hotpink', 'Footprint', 'despotism', 'mfaq', 'sumfactor', 'b2far', 'otpx', 'xtotp']) {
    assert.equal(found(`<input name="${name}">`), null, name);
    assert.equal(found(`<input id="${name}" placeholder="${name}">`), null, name);
  }
});

test('one-time is a code name only before code, pass, password or pin; verification only before code', () => {
  for (const name of ['one_time_password', 'oneTimeCode', 'one-time-pin', 'One-time passcode', 'onetimepass', 'verificationCode', 'verification_code', 'Verification code', 'email-verification-code']) {
    assert.deepEqual(found(`<input name="${name}" data-t="hit">`), ['hit'], name);
  }
  for (const name of ['oneTimeFee', 'one-time', 'one time donation', 'verification', 'verificationEmail', 'email-verification', 'verification-status']) {
    assert.equal(found(`<input name="${name}">`), null, name);
  }
});

test('security code is not a code name (it is what card forms call the CVV)', () => {
  for (const name of ['security code', 'securityCode', 'security-code']) {
    assert.equal(found(`<input name="${name}" type="number">`), null, name);
    assert.equal(found(`<input aria-label="${name}" maxlength="4">`), null, name);
  }
});

// Rules 2 and 3 skip a field whose name, id, label, placeholder or autocomplete names something
// else a short number goes into, and a field whose autocomplete asks for any other kind of value.
const EXCLUDED_WORDS = [
  'zip', 'postal', 'phone', 'tel', 'mobile', 'amount', 'price', 'card', 'cc', 'cvv', 'cvc', 'csc', 'birth',
  'bday', 'dob', 'date', 'year', 'month', 'day', 'search', 'account', 'qty', 'quantity', 'captcha',
];

test('rules 2 and 3 skip a field named for another number, in name, id, aria-label, placeholder or autocomplete', () => {
  for (const word of EXCLUDED_WORDS) {
    for (const attr of ['name', 'id', 'aria-label', 'placeholder', 'autocomplete']) {
      // Rule 2: a code name with the word beside it.
      assert.equal(found(`<input ${attr === 'name' ? '' : 'name="otp" '}${attr}="${attr === 'name' ? `otp-${word}` : word}">`), null, `rule 2, ${attr}=${word}`);
      // Rule 3: split boxes named for a code, one of them also so named.
      const marked = attr === 'name' ? boxes(6).replace('name="otp-3"', `name="${word}-3"`) : boxes(6).replace('data-t="b3"', `data-t="b3" ${attr}="${word}"`);
      assert.equal(found(`<div>${marked}</div>`), null, `rule 3, ${attr}=${word}`);
    }
  }
  // camelCase and compounds, beside a label that names a code.
  for (const name of ['postalCode', 'zipCode', 'zipcode', 'postcode', 'phoneNumber', 'telephone', 'mobileNo', 'cardNumber', 'ccNumber', 'cvc2', 'birthYear', 'birthday', 'dateOfBirth', 'expiryMonth', 'accountNumber', 'captchaInput', 'searchQuery']) {
    assert.equal(found(`<input type="tel" maxlength="6" name="${name}" aria-label="Verification code">`), null, name);
  }
  // The postal field next to a code field: the code field is the one found.
  assert.deepEqual(found('<input name="postal" aria-label="Verification code"><input aria-label="Verification code" data-t="hit">'), ['hit']);
});

test('the excluded words count only as whole words: hotel, today, update, cardinal and the like are not', () => {
  for (const name of ['hotelCode', 'today', 'updateCode', 'success', 'accepted', 'cardinal', 'research', 'holiday', 'zipper', 'spotprice']) {
    assert.deepEqual(found(`<input inputmode="numeric" maxlength="6" name="${name}" aria-label="Verification code" data-t="hit">`), ['hit'], name);
  }
});

test('rules 2 and 3 skip a field whose autocomplete is anything but one-time-code, off, on or empty', () => {
  for (const value of ['', 'off', 'on', 'OFF', ' on ', 'one-time-code']) {
    assert.deepEqual(found(`<input name="otp" autocomplete="${value}" data-t="hit">`), ['hit'], value);
    assert.deepEqual(found(`<div>${boxes(6, ` autocomplete="${value}"`)}</div>`), labels(6), value);
  }
  for (const value of ['nope', 'new-password', 'username', 'email', 'transaction-amount', 'section-login otp']) {
    assert.equal(found(`<input name="otp" autocomplete="${value}">`), null, value);
    assert.equal(found(`<div>${boxes(6, ` autocomplete="${value}"`)}</div>`), null, value);
  }
});

test('rule 1 (autocomplete one-time-code) is not narrowed: it wins whatever the field is named', () => {
  assert.deepEqual(found('<input autocomplete="one-time-code" name="phone-code" placeholder="Code from your mobile" data-t="hit">'), ['hit']);
  assert.deepEqual(found('<input autocomplete="section-sms one-time-code" id="zip" data-t="hit">'), ['hit']);
});

// Auto-fill writes with no click from the user, so a field only sized like a code (a PIN, a short
// number) is not taken: it is left to the right-click menu.
test('a field only sized for a code (numeric, tel or number, maxlength 6 to 8) is not found', () => {
  assert.equal(found('<input name="pin" inputmode="numeric" maxlength="6">'), null);
  assert.equal(found('<input type="tel" maxlength="8">'), null);
  assert.equal(found('<input inputmode="numeric" maxlength="6">'), null);
  assert.equal(found('<input type="number" maxlength="7">'), null);
  assert.equal(found('<input type="TEL" maxlength=" 6 ">'), null);
  // A label on an element around a lone field does not count for it (rule 2 reads the field's own
  // name, id, label and placeholder only).
  assert.equal(found('<div aria-label="Enter verification code"><input inputmode="numeric" maxlength="6"></div>'), null);
  assert.equal(found('<form id="otp-form"><input inputmode="numeric" maxlength="6"></form>'), null);
  // The same fields named for a code are found.
  assert.deepEqual(found('<input name="pin" inputmode="numeric" maxlength="6" aria-label="One-time code" data-t="hit">'), ['hit']);
  assert.deepEqual(found('<input type="tel" maxlength="8" name="otp" data-t="hit">'), ['hit']);
});

test('6 to 8 single-character boxes are found as one run, the first named and marked one-time-code', () => {
  assert.deepEqual(found(`<form><input name="user" value="a"><div class="boxes">${boxes(6, ' autocomplete="one-time-code"')}</div></form>`), labels(6));
  assert.deepEqual(found(`<div>${boxes(8)}</div>`), labels(8));
  // Each box in its own wrapper: the row around the wrappers is the group, and its label counts.
  const wrapped = Array.from({ length: 6 }, (_, i) => `<div class="cell"><input maxlength="1" data-t="b${i + 1}"></div>`).join('');
  assert.deepEqual(found(`<div class="row" aria-label="Enter verification code">${wrapped}</div>`), labels(6));
  assert.equal(found(`<div class="row">${wrapped}</div>`), null);
  // A hidden input holding the joined value does not break the run, and does not speak for it.
  const withHidden = Array.from({ length: 6 }, (_, i) => `<input maxlength="1" data-t="b${i + 1}">`);
  withHidden.splice(3, 0, '<input type="hidden" name="otp">');
  assert.deepEqual(found(`<div id="otp-boxes">${withHidden.join('')}</div>`), labels(6));
  assert.equal(found(`<div>${withHidden.join('')}</div>`), null);
});

// Rule 3 needs a sign of a code too: a box marked one-time-code, a box whose name, id, label or
// placeholder names a code, or a group (the element around the boxes) whose aria-label or id does.
test('split boxes with no sign of a code (a PIN entry) are not found', () => {
  assert.equal(found(`<div>${bareBoxes(6)}</div>`), null);
  assert.equal(found(`<div>${bareBoxes(8)}</div>`), null);
  assert.equal(found(`<form><input name="user" value="a"><div class="pin">${bareBoxes(6)}</div></form>`), null);
  // A label on an element further out than the group does not count.
  assert.equal(found(`<div aria-label="Enter verification code"><div class="row">${bareBoxes(6)}</div></div>`), null);
  // Neither does a group label that names no code.
  assert.equal(found(`<div aria-label="Enter your PIN" id="pin-boxes">${bareBoxes(6)}</div>`), null);
});

test('split boxes with a sign of a code are found: on a box, or on the group', () => {
  assert.deepEqual(found(`<div>${bareBoxes(6, ' aria-label="OTP digit 1"')}</div>`), labels(6));
  assert.deepEqual(found(`<div aria-label="Enter verification code">${bareBoxes(6)}</div>`), labels(6));
  assert.deepEqual(found(`<div>${bareBoxes(6, ' autocomplete="one-time-code"')}</div>`), labels(6));
  assert.deepEqual(found(`<div id="totp-input">${bareBoxes(8)}</div>`), labels(8));
  assert.deepEqual(found(`<div>${bareBoxes(6, ' placeholder="2FA"')}</div>`), labels(6));
  // The sign may be on any box of the run, not only the first.
  assert.deepEqual(found(`<div>${bareBoxes(6).replace('data-t="b4"', 'data-t="b4" id="otp-4"')}</div>`), labels(6));
  // A PIN run first and a code run after it: the code run is the one found.
  assert.deepEqual(found(`<div>${bareBoxes(6, '', 'p')}</div><div aria-label="Verification code">${bareBoxes(6)}</div>`), labels(6));
});

// A group label or id with a word for another number (the code went to a phone) skips the run,
// whatever sign of a code the group or its boxes carry; the same whole words as for one field.
test('rule 3 skips a run whose group aria-label or id names another number', () => {
  const phone = 'aria-label="Verification code sent to your phone"';
  assert.equal(found(`<div ${phone}>${bareBoxes(6)}</div>`), null);
  assert.equal(found(`<div ${phone}>${boxes(6)}</div>`), null);
  assert.equal(found(`<div ${phone}>${bareBoxes(6, ' autocomplete="one-time-code"')}</div>`), null);
  assert.equal(found(`<div id="phone-otp">${bareBoxes(6)}</div>`), null);
  // Each box in its own wrapper: the row is the group.
  const wrapped = Array.from({ length: 6 }, (_, i) => `<div class="cell"><input maxlength="1" data-t="b${i + 1}"></div>`).join('');
  assert.equal(found(`<div class="row" aria-label="Enter the verification code we sent to your mobile">${wrapped}</div>`), null);
  // The skipped run is passed over, and a code run after it is found.
  assert.deepEqual(found(`<div ${phone}>${bareBoxes(6, '', 'p')}</div><div aria-label="Verification code">${bareBoxes(6)}</div>`), labels(6));
  // The same in plain attribute maps.
  const sixBoxes = (attrs) => Array.from({ length: 6 }, () => ({ attrs: { maxlength: '1', ...attrs }, value: '', visible: true, group: 'g' }));
  assert.equal(ff.findOtpField(sixBoxes({ 'group-aria-label': 'Verification code sent to your phone' })), null);
  assert.equal(ff.findOtpField(sixBoxes({ 'group-id': 'otp-phone' })), null);
});

test('rule 3 still takes a run whose group names a code and no other number', () => {
  assert.deepEqual(found(`<div aria-label="Verification code">${bareBoxes(6)}</div>`), labels(6));
  // Whole words only: today is not day.
  assert.deepEqual(found(`<div aria-label="Verification code for today">${bareBoxes(6)}</div>`), labels(6));
  // Rule 2 still does not read the group label, for or against a lone field.
  const lone = { attrs: { name: 'otp', 'group-aria-label': 'Code sent to your phone' }, value: '', visible: true, group: 'g' };
  assert.deepEqual(ff.findOtpField([lone]), [0]);
});

// Hidden inputs (type=hidden, or not shown) say nothing for a run and do not break it.
test('a hidden input inside a run of boxes is passed over', () => {
  const run = (middle) => Array.from({ length: 6 }, (_, i) => `<input maxlength="1" data-t="b${i + 1}">`).toSpliced(3, 0, middle).join('');
  assert.deepEqual(found(`<div aria-label="Verification code">${run('<input type="hidden" name="joined">')}</div>`), labels(6));
  assert.deepEqual(found(`<div aria-label="Verification code">${run('<input type="password" style="display: none">')}</div>`), labels(6));
  // A shown input of another type after the run ends it; the run is still found.
  assert.deepEqual(found(`<div aria-label="Verification code">${run('')}<input type="password"></div>`), labels(6));
  // Plain attribute maps: type=hidden is passed over even when described as shown.
  const box = (attrs = { maxlength: '1', 'group-id': 'otp' }) => ({ attrs, value: '', visible: true, group: 'g' });
  const fields = [box(), box(), box(), box({ type: 'hidden' }), box(), box(), box()];
  assert.deepEqual(ff.findOtpField(fields), [0, 1, 2, 4, 5, 6]);
});

test('the rules apply in order: one-time-code, then names, then boxes', () => {
  assert.deepEqual(found('<input name="verification" data-t="named"><input autocomplete="one-time-code" data-t="otc">'), ['otc']);
  assert.deepEqual(found(`<div>${boxes(6)}</div><input name="otp" data-t="named">`), ['named']);
  // A field only sized for a code is not a rule of its own: the boxes are found.
  assert.deepEqual(found(`<div>${boxes(6)}</div><input type="tel" maxlength="6" data-t="sized">`), labels(6));
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

test('a shown input of a type no code goes into (password, email, ...) ends a run of boxes', () => {
  const otpBoxes = (from) => Array.from({ length: 3 }, (_, i) => `<input type="text" maxlength="1" aria-label="OTP" data-t="b${from + i}">`).join('');
  for (const middle of ['<input type="password">', '<input type="password" maxlength="1">', '<input type="email">', '<input type="search">', '<input type="checkbox">']) {
    assert.equal(found(`<div aria-label="OTP">${otpBoxes(1)}${middle}${otpBoxes(4)}</div>`), null, middle);
  }
  // The same in plain attribute maps.
  const box = (attrs = { maxlength: '1', 'aria-label': 'OTP' }) => ({ attrs, value: '', visible: true, group: 'g' });
  assert.equal(ff.findOtpField([box(), box(), box(), box({ type: 'password' }), box(), box(), box()]), null);
});

test('findOtpField reads plain attribute maps (no DOM needed)', () => {
  const field = (attrs, extra = {}) => ({ attrs, value: '', disabled: false, readOnly: false, visible: true, group: 'g', ...extra });
  assert.deepEqual(ff.findOtpField([field({ name: 'user' }), field({ autocomplete: 'one-time-code' })]), [1]);
  assert.equal(ff.findOtpField([field({ name: 'pin', inputmode: 'numeric', maxlength: '6' })]), null);
  // Boxes: the group's label and id come in attrs as group-aria-label and group-id.
  const sixBoxes = (attrs = {}) => Array.from({ length: 6 }, () => field({ maxlength: '1', ...attrs }));
  assert.equal(ff.findOtpField(sixBoxes()), null);
  assert.deepEqual(ff.findOtpField(sixBoxes({ 'group-aria-label': 'Enter verification code' })), [0, 1, 2, 3, 4, 5]);
  assert.deepEqual(ff.findOtpField(sixBoxes({ 'group-id': 'otp' })), [0, 1, 2, 3, 4, 5]);
  // A lone field's group label is not read.
  assert.equal(ff.findOtpField([field({ inputmode: 'numeric', maxlength: '6', 'group-aria-label': 'Verification code' })]), null);
  assert.equal(ff.findOtpField([field({ name: 'otp' }, { visible: false })]), null);
  assert.equal(ff.findOtpField([field({ name: 'otp' }, { value: '1' })]), null);
  assert.equal(ff.findOtpField([]), null);
  // Missing or odd attribute values are read as absent.
  assert.equal(ff.findOtpField([{ attrs: { name: 42 }, value: '', visible: true }]), null);
});

// ---- content/autofill.js -----------------------------------------------------------------------
// Fresh codes, keep-fresh and refills after a rejected code are tested in
// test/content-autofill.test.mjs; here every code the worker sends stays valid VALID_MS, longer
// than the 5 minutes (FOLLOW_MS) the script follows a filled field, so none is replaced.

const VALID_MS = 300 * 1000;
const FOLLOW_MS = 5 * 60 * 1000;

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
// content script does. `reply` is the worker's answer (or a function returning it). `setup`, if
// given, gets the parsed page before the scripts run.
async function runContentScript(html, reply, setup) {
  const doc = parse(html);
  // content/autofill.js follows a filled field only while the page stays at this path.
  doc.URL = 'https://otp.test/login';
  if (setup) setup(doc);
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
  // One querySelectorAll on the document per look.
  let looks = 0;
  const query = doc.querySelectorAll.bind(doc);
  doc.querySelectorAll = (selector) => {
    looks += 1;
    return query(selector);
  };
  const context = vm.createContext({
    window: eventTarget('window'),
    document: doc,
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout,
    Event: class {
      constructor(type, init = {}) {
        this.type = type;
        this.bubbles = Boolean(init.bubbles);
        this.isTrusted = false;
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
  // Dispatches an event of `type` to the listeners on window and document; no time passes.
  const fire = async (type) => {
    for (const l of listeners.filter((x) => x.type === type)) l.fn({ type });
    await flush();
  };
  return { doc, timers, messages, observers, mutate, fire, listeners, looks: () => looks };
}

// A page whose code field the browser does not show yet, and that does not change when it does
// (an out-of-process iframe with no size yet when the script runs: nothing in it has a box).
// → { html, setup } for runContentScript(), and show()
function notShownYet(html = '<form><input name="otp" data-t="otp"></form>') {
  let shown = false;
  return {
    html,
    setup: (doc) => (byTag(doc, 'otp').checkVisibility = () => shown),
    show: () => (shown = true),
  };
}

test('content script: fills the code field with input and change events, nothing else', async () => {
  const page = '<form><input name="username" value="alice" data-t="user"><input name="otp" data-t="otp"></form>';
  // The second request is answered with the code of a later period.
  const codes = ['123456', '654321'];
  let n = 0;
  const run = await runContentScript(page, () => ({ code: codes[Math.min(n++, 1)], validMs: VALID_MS }));
  assert.deepEqual(run.messages, [{ type: 'autofill-code' }]);
  const otp = byTag(run.doc, 'otp');
  assert.equal(otp.value, '123456');
  assert.deepEqual(otp.events, ['input', 'change']);
  assert.deepEqual(byTag(run.doc, 'user').events, []);
  assert.equal(byTag(run.doc, 'user').value, 'alice');
  assert.equal(run.doc.children[0].submits, 0);
  // The page clears the field again (a rejected code): it is filled again with a fresh code, and
  // still nothing else is touched or submitted.
  otp.value = '';
  await run.mutate();
  assert.equal(run.messages.length, 2);
  assert.equal(otp.value, '654321');
  assert.deepEqual(otp.events, ['input', 'change', 'input', 'change']);
  assert.deepEqual(byTag(run.doc, 'user').events, []);
  assert.equal(run.doc.children[0].submits, 0);
});

test('content script: one filled field at a time: a second candidate is never asked for or filled, and the watch stops after the follow window', async () => {
  // The OTP field and, after it, a field rule 2 also takes (named for a code).
  const page = '<form><input name="otp" data-t="otp"><input name="totp" data-t="second"></form>';
  let n = 0;
  const run = await runContentScript(page, () => ({ code: String(111111 * ++n).padStart(6, '0'), validMs: VALID_MS }));
  assert.equal(byTag(run.doc, 'otp').value, '111111');
  await run.mutate();
  for (const type of ['load', 'pageshow', 'resize', 'visibilitychange']) await run.fire(type);
  await run.timers.advance(60 * 1000);
  assert.deepEqual(run.messages, [{ type: 'autofill-code' }]);
  assert.equal(byTag(run.doc, 'second').value, '');
  assert.deepEqual(byTag(run.doc, 'second').events, []);
  // Nothing is left running 5 minutes after the fill.
  await run.timers.advance(FOLLOW_MS - 60 * 1000);
  assert.equal(run.messages.length, 1);
  assert.ok(run.observers.every((o) => o.disconnected));
  assert.equal(run.timers.pending(), 0);
  assert.equal(run.listeners.length, 0);
  // A field that appears later is not filled either.
  const late = new El('input', { autocomplete: 'one-time-code' });
  run.doc.children[0].append(late);
  await run.mutate();
  assert.equal(late.value, '');
  assert.equal(run.messages.length, 1);
});

test('content script: split boxes filled → a second run of boxes stays empty, and the watch stops after the follow window', async () => {
  // The second run is labelled for a code as well, so rule 3 would take it.
  const second = Array.from({ length: 6 }, (_, i) => `<input maxlength="1" data-t="c${i + 1}">`).join('');
  const run = await runContentScript(`<div>${boxes(6)}</div><div aria-label="Verification code">${second}</div>`, { code: '102938', validMs: VALID_MS });
  assert.deepEqual(labels(6).map((t) => byTag(run.doc, t).value), ['1', '0', '2', '9', '3', '8']);
  await run.timers.advance(FOLLOW_MS);
  assert.equal(run.messages.length, 1);
  assert.ok(['c1', 'c2', 'c3', 'c4', 'c5', 'c6'].every((t) => byTag(run.doc, t).value === ''));
  assert.equal(run.timers.pending(), 0);
  assert.equal(run.listeners.length, 0);
});

test('content script: a page with only a PIN field, a short numeric field and PIN boxes → no code asked for, nothing filled', async () => {
  const page = `<form><input name="pin" inputmode="numeric" maxlength="6" data-t="pin"><input type="tel" maxlength="8" data-t="tel"><div>${bareBoxes(6)}</div></form>`;
  const run = await runContentScript(page, { code: '123456', validMs: VALID_MS });
  for (const type of ['load', 'pageshow', 'resize', 'visibilitychange']) await run.fire(type);
  await run.mutate();
  await run.timers.advance(60 * 1000);
  assert.equal(run.messages.length, 0);
  for (const t of ['pin', 'tel', ...labels(6)]) {
    assert.equal(byTag(run.doc, t).value, '', t);
    assert.deepEqual(byTag(run.doc, t).events, [], t);
  }
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
  const badCodes = [{ code: '12345' }, { code: '123456789' }, { code: '12a456' }, { code: 123456 }].map((r) => ({ ...r, validMs: VALID_MS }));
  for (const reply of [...badCodes, undefined, 'x']) {
    const run = await runContentScript('<input name="otp" data-t="otp">', reply);
    assert.equal(byTag(run.doc, 'otp').value, '', JSON.stringify(reply));
  }
  const failing = await runContentScript('<input name="otp" data-t="otp">', () => {
    throw new Error('Could not establish connection');
  });
  assert.equal(byTag(failing.doc, 'otp').value, '');
});

test('content script: a field that is not empty is never touched, and no code is asked for', async () => {
  const run = await runContentScript('<input name="otp" value="99" data-t="otp">', { code: '123456', validMs: VALID_MS });
  assert.equal(run.messages.length, 0);
  assert.equal(byTag(run.doc, 'otp').value, '99');
});

test('content script: a value typed while the worker answers is kept', async () => {
  const run = await runContentScript('<input name="otp" data-t="otp">', (doc) => {
    byTag(doc, 'otp').value = '4';
    return { code: '123456', validMs: VALID_MS };
  });
  assert.equal(byTag(run.doc, 'otp').value, '4');
  assert.deepEqual(byTag(run.doc, 'otp').events, []);
  // Cleared again later: a code was asked for this field once already, so it is not asked again.
  byTag(run.doc, 'otp').value = '';
  await run.mutate();
  await run.timers.advance(60 * 1000);
  assert.equal(run.messages.length, 1);
  assert.equal(byTag(run.doc, 'otp').value, '');
});

test('content script: no code → no further looks, no timer and no listener left', async () => {
  const run = await runContentScript('<input name="otp" data-t="otp">', { code: null });
  assert.equal(run.messages.length, 1);
  const looks = run.looks();
  assert.equal(run.timers.pending(), 0);
  assert.equal(run.listeners.length, 0);
  for (const type of ['load', 'pageshow', 'resize', 'visibilitychange']) await run.fire(type);
  await run.mutate();
  await run.timers.advance(60 * 1000);
  assert.equal(run.looks(), looks);
  assert.equal(run.messages.length, 1);
});

test('content script: a field added later is filled; after 60 s nothing is watched', async () => {
  const run = await runContentScript('<form id="f"></form>', { code: '654321', validMs: VALID_MS });
  assert.equal(run.messages.length, 0);
  assert.ok(run.observers.length === 1 && run.observers[0].options.subtree && run.observers[0].options.childList);
  const late = new El('input', { autocomplete: 'one-time-code' });
  run.doc.children[0].append(late);
  await run.mutate();
  assert.equal(late.value, '654321');

  const idle = await runContentScript('<form></form>', { code: '654321', validMs: VALID_MS });
  await idle.timers.advance(60 * 1000);
  assert.ok(idle.observers.every((o) => o.disconnected));
  const tooLate = new El('input', { name: 'otp' });
  idle.doc.children[0].append(tooLate);
  await idle.mutate();
  assert.equal(tooLate.value, '');
  assert.equal(idle.messages.length, 0);
});

// The frame is laid out only after the first look, and the DOM does not change when it is.
test('content script: a field shown after the first look is filled once when the frame is resized, loaded or shown', async () => {
  for (const type of ['resize', 'load', 'pageshow', 'visibilitychange']) {
    const late = notShownYet();
    const run = await runContentScript(late.html, { code: '246810', validMs: VALID_MS }, late.setup);
    assert.equal(run.messages.length, 0, type);
    late.show();
    await run.fire(type);
    // Less than the retry interval: the event, not the retry, found the field.
    await run.timers.advance(200);
    assert.equal(run.messages.length, 1, type);
    assert.equal(byTag(run.doc, 'otp').value, '246810', type);
    await run.fire(type);
    await run.timers.advance(60 * 1000);
    assert.equal(run.messages.length, 1, type);
    assert.deepEqual(byTag(run.doc, 'otp').events, ['input', 'change'], type);
  }
});

test('content script: a field shown after the first look, with no event and no DOM change, is filled once by a later look', async () => {
  const late = notShownYet();
  const run = await runContentScript(late.html, { code: '135790', validMs: VALID_MS }, late.setup);
  assert.equal(run.messages.length, 0);
  late.show();
  await run.timers.advance(1000);
  assert.equal(run.messages.length, 1);
  assert.equal(byTag(run.doc, 'otp').value, '135790');
  assert.deepEqual(byTag(run.doc, 'otp').events, ['input', 'change']);
  // While the filled field holds its code the page is not searched again.
  const looks = run.looks();
  await run.timers.advance(10 * 1000);
  assert.equal(run.looks(), looks);
  await run.timers.advance(FOLLOW_MS);
  assert.equal(run.messages.length, 1);
  assert.equal(run.timers.pending(), 0);
});

test('content script: a field that never shows → no code asked for, and after 60 s nothing is left running', async () => {
  const hidden = notShownYet();
  const run = await runContentScript(hidden.html, { code: '112233', validMs: VALID_MS }, hidden.setup);
  await run.timers.advance(60 * 1000);
  assert.equal(run.messages.length, 0);
  assert.equal(run.timers.pending(), 0);
  assert.equal(run.listeners.length, 0);
  assert.ok(run.observers.every((o) => o.disconnected));
  // Shown only after the watch: never filled.
  hidden.show();
  const looks = run.looks();
  for (const type of ['load', 'pageshow', 'resize', 'visibilitychange']) await run.fire(type);
  await run.mutate();
  await run.timers.advance(5000);
  assert.equal(run.looks(), looks);
  assert.equal(run.messages.length, 0);
  assert.equal(byTag(run.doc, 'otp').value, '');
});

test('content script: split boxes get one digit each', async () => {
  const run = await runContentScript(`<div>${boxes(6)}</div>`, { code: '102938', validMs: VALID_MS });
  assert.deepEqual(labels(6).map((t) => byTag(run.doc, t).value), ['1', '0', '2', '9', '3', '8']);
  assert.deepEqual(byTag(run.doc, 'b6').events, ['input', 'change']);
  // An 8-digit code does not fit 6 boxes: nothing is filled.
  const mismatch = await runContentScript(`<div>${boxes(6)}</div>`, { code: '10293847', validMs: VALID_MS });
  assert.ok(labels(6).every((t) => byTag(mismatch.doc, t).value === ''));
});

test('content script: a single field whose maxlength is shorter than the code is not filled', async () => {
  const run = await runContentScript('<input name="otp" type="tel" maxlength="6" data-t="f">', { code: '12345678', validMs: VALID_MS });
  // The field was found and a code asked for; the code does not fit.
  assert.equal(run.messages.length, 1);
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
