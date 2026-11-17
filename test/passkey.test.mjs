import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { support, enrollCeremony, unlockCeremony } from '../extension/popup/passkey.js';

Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });
const salt = new Uint8Array(32).fill(3);
const cred = new Uint8Array([1, 2, 3]);
const prf = new Uint8Array(32).fill(9);
const result = (id = cred, output = prf, uv = true) => ({
  rawId: id.buffer.slice(id.byteOffset, id.byteOffset + id.byteLength),
  response: { authenticatorData: new Uint8Array([...new Uint8Array(32), uv ? 4 : 0, 0, 0, 0, 0]).buffer },
  getClientExtensionResults: () => ({ prf: output === null ? {} : { results: { first: output.buffer } } }),
});
function mock(create, get, capabilities = async () => ({ 'extension:prf': true })) {
  globalThis.PublicKeyCredential = class { static getClientCapabilities = capabilities; static async isUserVerifyingPlatformAuthenticatorAvailable() { return false; } };
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { credentials: { create, get } } });
}
afterEach(() => { delete globalThis.PublicKeyCredential; delete globalThis.navigator; });

test('support detection fails safely', async () => {
  assert.equal(await support(), 'no');
  mock(null, null, async () => { throw Error(); });
  assert.equal(await support(), 'unknown');
  delete globalThis.PublicKeyCredential.getClientCapabilities;
  assert.equal(await support(), 'unknown');
});

test('enrollment creates and always gets exact credential with PRF and UV', async () => {
  let createOptions, getOptions;
  mock(async (o) => { createOptions = o.publicKey; return result(cred, null); }, async (o) => { getOptions = o.publicKey; return result(); });
  const out = await enrollCeremony({ prfSalt: salt });
  assert.deepEqual(out, { cred, prf });
  assert.equal(createOptions.rp.id, undefined);
  assert.equal(createOptions.authenticatorSelection.residentKey, 'required');
  assert.equal(createOptions.authenticatorSelection.userVerification, 'required');
  assert.equal(createOptions.authenticatorSelection.authenticatorAttachment, 'cross-platform');
  assert.deepEqual(createOptions.pubKeyCredParams.map(x => x.alg), [-8, -7, -257]);
  assert.deepEqual(getOptions.allowCredentials[0].id, cred);
  assert.equal(getOptions.userVerification, 'required');
  assert.deepEqual(getOptions.extensions.prf.eval.first, salt);
});

test('matching creation PRF is accepted and unlock requests exact credential', async () => {
  let options;
  mock(async () => result(), async (o) => { options = o.publicKey; return result(); });
  assert.deepEqual(await enrollCeremony({ prfSalt: salt }), { cred, prf });
  assert.deepEqual(await unlockCeremony({ credBytes: cred, prfSalt: salt }), prf);
  assert.deepEqual(options.allowCredentials[0].id, cred);
  assert.deepEqual(options.extensions.prf.eval.first, salt);
});

test('rejects mismatch, missing PRF, wrong credential, missing UV and cancellation', async () => {
  mock(async () => result(), async () => result(cred, new Uint8Array(32).fill(1)));
  await assert.rejects(enrollCeremony({ prfSalt: salt }), { code: 'mismatch', orphan: true });
  mock(async () => result(cred, null), async () => result(cred, null));
  await assert.rejects(enrollCeremony({ prfSalt: salt }), { code: 'no-prf', orphan: true });
  mock(async () => result(), async () => result(new Uint8Array([5])));
  await assert.rejects(enrollCeremony({ prfSalt: salt }), { code: 'failed', orphan: true });
  mock(null, async () => result(cred, prf, false));
  await assert.rejects(unlockCeremony({ credBytes: cred, prfSalt: salt }), { code: 'failed' });
  mock(null, async () => { throw new DOMException('cancel', 'NotAllowedError'); });
  await assert.rejects(unlockCeremony({ credBytes: cred, prfSalt: salt }), { code: 'cancelled' });
});

test('rejects malformed input before browser call', async () => {
  let called = false;
  mock(() => { called = true; }, () => { called = true; });
  await assert.rejects(enrollCeremony({ prfSalt: new Uint8Array(31) }));
  await assert.rejects(unlockCeremony({ credBytes: new Uint8Array(), prfSalt: salt }));
  assert.equal(called, false);
});

// ---- ceremony pins (review nice-to-have) ----

test('create reporting prf {enabled:false} with no results still runs get and uses its PRF', async () => {
  let gets = 0;
  const created = { ...result(), getClientExtensionResults: () => ({ prf: { enabled: false } }) };
  mock(async () => created, async () => { gets++; return result(); });
  assert.deepEqual(await enrollCeremony({ prfSalt: salt }), { cred, prf });
  assert.equal(gets, 1);
});

test('a 16-byte PRF from get is no-prf (unlock, and enroll with orphan)', async () => {
  mock(async () => result(cred, null), async () => result(cred, new Uint8Array(16).fill(9)));
  await assert.rejects(unlockCeremony({ credBytes: cred, prfSalt: salt }), { code: 'no-prf', orphan: false });
  await assert.rejects(enrollCeremony({ prfSalt: salt }), { code: 'no-prf', orphan: true });
});

test('cancelling the get after a successful create is cancelled with orphan', async () => {
  mock(async () => result(cred, null), async () => { throw new DOMException('cancel', 'NotAllowedError'); });
  await assert.rejects(enrollCeremony({ prfSalt: salt }), { code: 'cancelled', orphan: true });
  mock(async () => { throw new DOMException('cancel', 'NotAllowedError'); }, async () => result());
  await assert.rejects(enrollCeremony({ prfSalt: salt }), { code: 'cancelled', orphan: false });
});

// ---- Settings passkey block, on a fake DOM (no browser) ----

const settings = await import('../extension/popup/settings.js');
const { PasskeyError } = await import('../extension/popup/passkey.js');

function fakeDom() {
  const els = new Map();
  const el = (sel) => {
    if (!els.has(sel)) {
      const listeners = {};
      els.set(sel, {
        hidden: false, value: '', textContent: '', disabled: false,
        addEventListener(type, fn) { (listeners[type] ??= []).push(fn); },
        fire(type) { for (const fn of listeners[type] ?? []) fn({ preventDefault() {} }); },
        focus() {}, select() {},
        reset() {
          if (sel === '#passkey-form') { el('#passkey-pass').value = ''; el('#passkey-label').value = ''; }
        },
      });
    }
    return els.get(sel);
  };
  Object.defineProperty(globalThis, 'document', { configurable: true, value: { querySelector: el, body: { dataset: { state: 'locked' } } } });
  globalThis.window = { closed: 0, close() { this.closed++; } };
  globalThis.chrome = { i18n: { getMessage: (key) => key } };
  return el;
}

function fakeSession() {
  const s = {
    unlocked: true, gen: 1, slot: null, enrolled: 0,
    isUnlocked: () => s.unlocked,
    generation: () => s.gen,
    isBadPassphrase: (e) => e?.code === 'bad-passphrase',
    passkeyState: async () => ({ slot: s.slot }),
    captureForCeremony: async () => ({ rev: 'r', lockGen: 'g', identity: { v: 1 }, slot: s.slot }),
    checkPassphrase: async () => true,
    enrollPasskey: async () => { s.enrolled++; },
    removePasskey: async () => {},
  };
  return s;
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((a, b) => { resolve = a; reject = b; });
  return { promise, resolve, reject };
}
const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r)); };

async function typed(el, section) {
  await section.open();
  el('#passkey-pass').value = 'recovery passphrase';
  el('#passkey-label').value = 'phone';
}

test('every path that hides the enroll form empties the passphrase and label', async () => {
  const cases = [
    ['slot found by another tab', true, (s) => { s.slot = { cred: 'AQ', label: 'x' }; }, 'yes'],
    ['support no', true, () => {}, 'no'],
    ['passkeyState throws', true, (s) => { s.passkeyState = async () => { throw new Error('x'); }; }, 'yes'],
    ['toolbar popup', false, () => {}, 'yes'],
  ];
  for (const [name, isTab, change, after] of cases) {
    const el = fakeDom();
    const s = fakeSession();
    let available = 'yes';
    const section = settings.createPasskeySection({ isTab, sessions: s, ceremony: { support: async () => available } });
    await typed(el, section);
    change(s);
    available = after;
    await section.refresh();
    const hidden = el('#passkey-section').hidden || el('#passkey-tab').hidden || el('#passkey-form').hidden;
    assert.equal(hidden, true, `${name}: form hidden`);
    assert.equal(el('#passkey-pass').value, '', `${name}: passphrase emptied`);
    assert.equal(el('#passkey-label').value, '', `${name}: label emptied`);
  }
});

test('the visible enroll form keeps what is being typed across a refresh', async () => {
  const el = fakeDom();
  const s = fakeSession();
  const section = settings.createPasskeySection({ isTab: true, sessions: s, ceremony: { support: async () => 'yes' } });
  await typed(el, section);
  await section.refresh();
  assert.equal(el('#passkey-form').hidden, false);
  assert.equal(el('#passkey-pass').value, 'recovery passphrase');
});

// Invalidation while the ceremony runs (lock via clear(), or another generation), then the
// ceremony settles: the orphan notice survives, nothing is stored, no typed content comes back.
const invalidations = [
  ['lock (clear)', (section) => section.clear()],
  ['generation change', (section, s) => { s.gen++; }],
];
const outcomes = [
  ['get succeeds', (d) => d.resolve({ cred: new Uint8Array([1]), prf: new Uint8Array(32) }), true],
  ['get rejects (orphan)', (d) => d.reject(new PasskeyError('cancelled', true)), true],
  ['create cancelled (no orphan)', (d) => d.reject(new PasskeyError('cancelled', false)), false],
];
for (const [invName, invalidate] of invalidations) {
  for (const [outName, finish, orphan] of outcomes) {
    test(`orphan notice after ${invName} when ${outName}: ${orphan ? 'kept' : 'not raised'}`, async () => {
      settings.takeOrphanNotice?.();
      const el = fakeDom();
      const s = fakeSession();
      const d = deferred();
      let notified = 0;
      const section = settings.createPasskeySection({
        isTab: true, sessions: s, onOrphan: () => { notified++; },
        ceremony: { support: async () => 'yes', enrollCeremony: () => d.promise },
      });
      await typed(el, section);
      el('#passkey-form').fire('submit');
      await settle();
      invalidate(section, s);
      finish(d);
      await settle();
      assert.equal(s.enrolled, 0, 'nothing stored');
      assert.equal(el('#passkey-pass').value, '', 'typed passphrase not kept');
      assert.equal(notified, orphan ? 1 : 0, 'onOrphan');
      assert.equal(settings.takeOrphanNotice?.(), orphan, 'pending notice');
      assert.equal(settings.takeOrphanNotice?.(), false, 'consumed once');
    });
  }
}

test('a pending orphan notice shows when the settings block opens again', async () => {
  settings.takeOrphanNotice?.();
  const el = fakeDom();
  const s = fakeSession();
  const d = deferred();
  const section = settings.createPasskeySection({
    isTab: true, sessions: s, ceremony: { support: async () => 'yes', enrollCeremony: () => d.promise },
  });
  await typed(el, section);
  el('#passkey-form').fire('submit');
  await settle();
  section.clear();
  d.resolve({ cred: new Uint8Array([1]), prf: new Uint8Array(32) });
  await settle();
  await section.open();
  assert.match(el('#passkey-error').textContent, /passkeyOrphan/);
  assert.equal(settings.takeOrphanNotice?.(), false, 'consumed by open()');
});

test('while the page stays live: a failed commit after create says orphan inline and owes nothing; success stores', async () => {
  settings.takeOrphanNotice();
  for (const fails of [true, false]) {
    const el = fakeDom();
    const s = fakeSession();
    if (fails) s.enrollPasskey = async () => { throw Object.assign(new Error('changed'), { code: 'changed' }); };
    let notified = 0;
    const section = settings.createPasskeySection({
      isTab: true, sessions: s, onOrphan: () => { notified++; },
      ceremony: { support: async () => 'yes', enrollCeremony: async () => ({ cred: new Uint8Array([1]), prf: new Uint8Array(32) }) },
    });
    await typed(el, section);
    el('#passkey-form').fire('submit');
    await settle();
    assert.equal(el('#passkey-pass').value, '');
    assert.equal(notified, 0);
    assert.equal(settings.takeOrphanNotice(), false);
    if (fails) {
      assert.match(el('#passkey-error').textContent, /passkeyChanged passkeyOrphan/);
    } else {
      assert.equal(s.enrolled, 1);
      assert.equal(el('#passkey-status').textContent, 'passkeyAdded');
      assert.equal(el('#passkey-error').textContent, '');
    }
  }
});

// ---- locked view: "Unlock with passkey" ----

function unlockHarness({ inPopup = false } = {}) {
  const el = fakeDom();
  const s = fakeSession();
  s.unlocked = false;
  s.slot = { cred: 'AQ', credBytes: new Uint8Array([1]), prfSalt: new Uint8Array(32) };
  s.commits = 0;
  s.unlockWithPasskey = async () => { s.commits++; s.unlocked = true; };
  const d = deferred();
  const seen = { unlocked: 0, opened: 0, ceremonies: 0 };
  const ctl = settings.createPasskeyUnlock({
    inPopup,
    openWindow: async () => { seen.opened++; },
    onUnlocked: async () => { seen.unlocked++; },
    sessions: s,
    ceremony: { support: async () => 'yes', unlockCeremony: () => { seen.ceremonies++; return d.promise; } },
  });
  return { el, s, d, ctl, seen };
}

async function clickUnlock(h) {
  await h.ctl.refresh();
  assert.equal(h.el('#unlock-passkey').hidden, false);
  h.el('#unlock-passkey').fire('click');
  await settle();
  assert.equal(h.el('#unlock-passkey-status').textContent, 'passkeyWorking');
  assert.equal(h.el('#unlock-passkey').disabled, true);
}

const ended = (h) => {
  assert.equal(h.el('#unlock-passkey-status').textContent, '', 'working status cleared');
  assert.equal(h.el('#unlock-passkey').disabled, false, 'button enabled again');
};

test('a storage hint while locked (the locked view re-shown) does not cancel an unlock ceremony', async () => {
  const h = unlockHarness();
  await clickUnlock(h);
  await h.ctl.refresh();
  h.d.resolve(new Uint8Array(32));
  await settle();
  assert.equal(h.s.commits, 1, 'session commit decides');
  assert.equal(h.seen.unlocked, 1);
  ended(h);
});

for (const [name, finish] of [
  ['the ceremony succeeds', (d) => d.resolve(new Uint8Array(32))],
  ['the ceremony fails', (d) => d.reject(new PasskeyError('cancelled'))],
]) {
  test(`lock-unlock-lock in this page while waiting, then ${name}: discarded with the changed message`, async () => {
    const h = unlockHarness();
    await clickUnlock(h);
    h.ctl.clear(); // unlocked (enterUnlocked)
    h.ctl.clear(); // locked again (clearSensitive)
    await h.ctl.refresh(); // show('locked')
    finish(h.d);
    await settle();
    assert.equal(h.s.commits, 0, 'nothing committed');
    assert.equal(h.seen.unlocked, 0);
    assert.equal(h.el('#unlock-passkey-error').textContent, 'passkeyChanged');
    ended(h);
  });
}

test('the page left the locked view while waiting: discarded quietly', async () => {
  const h = unlockHarness();
  await clickUnlock(h);
  h.ctl.clear();
  document.body.dataset.state = 'list';
  h.d.resolve(new Uint8Array(32));
  await settle();
  assert.equal(h.s.commits, 0);
  assert.equal(h.el('#unlock-passkey-error').textContent, '');
  ended(h);
});

test('the session commit refusing (changed) shows the changed message and ends the ceremony', async () => {
  const h = unlockHarness();
  h.s.unlockWithPasskey = async () => { throw Object.assign(new Error('changed'), { code: 'changed' }); };
  await clickUnlock(h);
  h.d.resolve(new Uint8Array(32));
  await settle();
  assert.equal(h.el('#unlock-passkey-error').textContent, 'passkeyChanged');
  assert.equal(h.seen.unlocked, 0);
  ended(h);
});

test('the toolbar popup only opens the unlock window; no ceremony there', async () => {
  const h = unlockHarness({ inPopup: true });
  await h.ctl.refresh();
  h.el('#unlock-passkey').fire('click');
  await settle();
  assert.equal(h.seen.opened, 1);
  assert.equal(h.seen.ceremonies, 0);
  assert.equal(window.closed, 1);
});
