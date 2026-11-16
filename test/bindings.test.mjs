import { test } from 'node:test';
import assert from 'node:assert/strict';
// A namespace import: one missing helper fails its own case, not the whole file.
import * as b from '../extension/lib/bindings.js';

const A = { id: 'a', issuer: 'Ex', label: 'a@b', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 };
const B = { ...A, id: 'b', issuer: 'Other' };
const bind = (origin, accountId, createdAt = 1) => ({ origin, accountId, createdAt });

// Freezes every object and array reachable from value, so any write into an input throws.
function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const v of Object.values(value)) deepFreeze(v);
  }
  return value;
}

for (const [input, expected] of [
  ['https://a.b', 'https://a.b'],
  ['https://a.b/', 'https://a.b'],
  ['https://a.b:443/x?y', 'https://a.b'],
  ['https://a.b/x#frag', 'https://a.b'],
  ['https://a.b:8443/x', 'https://a.b:8443'],
  ['HTTPS://Sub.Example.COM/Path', 'https://sub.example.com'],
  ['https://user:pw@a.b/x', 'https://a.b'],
  ['https://127.0.0.1/x', 'https://127.0.0.1'],
  ['https://[::1]:8443/', 'https://[::1]:8443'],
  ['https://bücher.example/', 'https://xn--bcher-kva.example'],
  [new URL('https://otp.test/login'), 'https://otp.test'],
  ['http://a.b', null],
  ['http://localhost', null],
  ['http://localhost:3000/x', null],
  ['ftp://a.b', null],
  ['wss://a.b', null],
  ['file:///etc/hosts', null],
  ['data:text/html,x', null],
  ['blob:https://a.b/0b8e4ac9-1a3c-4d1b-9b62-2f0c7c9d6a11', null],
  ['about:blank', null],
  ['chrome-extension://abcdefghijklmnop/popup/popup.html', null],
  ['https://', null],
  ['https:a', 'https://a'],
  ['/relative', null],
  ['not a url', null],
  ['null', null],
  ['', null],
  [null, null],
  [undefined, null],
  [42, null],
  [{ href: 'https://a.b' }, null],
]) {
  test(`normalizeOrigin(${typeof input === 'string' ? JSON.stringify(input) : String(input)}) → ${expected}`, () => {
    assert.equal(b.normalizeOrigin(input), expected);
  });
}

test('bindingsOf: missing or non-array bindings read as none', () => {
  for (const data of [{ accounts: [A] }, { accounts: [A], bindings: 'x' }, { accounts: [A], bindings: { 0: bind('https://a.b', 'a') } }, null, undefined, 'x', []]) {
    assert.deepEqual(b.bindingsOf(data), [], JSON.stringify(data));
  }
});

test('bindingsOf: malformed entries are ignored, the first entry for an origin wins', () => {
  const data = {
    accounts: [A, B],
    bindings: [
      null, 5, 'https://a.b', ['https://a.b', 'a'], {},
      bind('http://a.b', 'a'),
      bind('https://a.b/x', 'a'),
      bind('https://A.b', 'a'),
      bind('https://a.b', ''),
      bind('https://a.b', 7),
      { origin: 'https://a.b', accountId: 'a', createdAt: 5, extra: true },
      bind('https://a.b', 'b', 6),
      { origin: 'https://c.d', accountId: 'b', createdAt: 'yesterday' },
    ],
  };
  assert.deepEqual(b.bindingsOf(data), [bind('https://a.b', 'a', 5), bind('https://c.d', 'b', null)]);
});

test('bindingsOf returns copies: changing them changes nothing stored', () => {
  const data = { accounts: [A], bindings: [bind('https://a.b', 'a')] };
  const [first] = b.bindingsOf(data);
  first.accountId = 'z';
  assert.equal(data.bindings[0].accountId, 'a');
});

test('withBinding adds to data without bindings and leaves the input as it was', () => {
  const data = deepFreeze({ accounts: [A], other: { kept: true } });
  const next = b.withBinding(data, 'https://otp.test', 'a', 1000);
  assert.notEqual(next, data);
  assert.deepEqual(next, { accounts: [A], other: { kept: true }, bindings: [bind('https://otp.test', 'a', 1000)] });
  assert.equal('bindings' in data, false);
});

test('withBinding replaces the binding of that origin and keeps the rest, malformed entries included', () => {
  const data = deepFreeze({
    accounts: [A, B],
    bindings: [bind('https://otp.test', 'a', 1), 'junk', bind('https://c.d', 'a', 2), bind('https://otp.test', 'b', 3)],
  });
  const next = b.withBinding(data, 'https://otp.test', 'b', 9);
  assert.deepEqual(next.bindings, ['junk', bind('https://c.d', 'a', 2), bind('https://otp.test', 'b', 9)]);
  assert.deepEqual(b.bindingFor(next, 'https://otp.test'), bind('https://otp.test', 'b', 9));
  assert.deepEqual(data.bindings[0], bind('https://otp.test', 'a', 1));
});

test('withBinding over a non-array bindings value starts a new list', () => {
  const next = b.withBinding(deepFreeze({ accounts: [A], bindings: { x: 1 } }), 'https://otp.test', 'a', 1);
  assert.deepEqual(next.bindings, [bind('https://otp.test', 'a', 1)]);
});

test('withBinding stores what new URL(..).origin gives and refuses anything else', () => {
  for (const url of ['https://otp.test/login', 'https://otp.test:8443/x', 'https://[::1]/', 'https://bücher.example/']) {
    const origin = new URL(url).origin;
    assert.deepEqual(b.bindingsOf(b.withBinding({ accounts: [A] }, origin, 'a', 1)), [bind(origin, 'a', 1)]);
  }
  for (const origin of ['https://otp.test/', 'https://otp.test/login', 'https://OTP.test', 'https://otp.test:443', 'http://otp.test', 'otp.test', '', null]) {
    assert.throws(() => b.withBinding({ accounts: [A] }, origin, 'a', 1), TypeError, String(origin));
  }
  for (const accountId of ['', 7, null, undefined]) {
    assert.throws(() => b.withBinding({ accounts: [A] }, 'https://otp.test', accountId, 1), TypeError, String(accountId));
  }
});

test('withBinding defaults createdAt to now', () => {
  const before = Date.now();
  const [stored] = b.bindingsOf(b.withBinding({ accounts: [A] }, 'https://otp.test', 'a'));
  assert.ok(stored.createdAt >= before && stored.createdAt <= Date.now());
});

test('withoutBinding removes that origin only; a full URL of the origin finds it', () => {
  const data = deepFreeze({ accounts: [A, B], bindings: [bind('https://otp.test', 'a'), 'junk', bind('https://c.d', 'b')] });
  assert.deepEqual(b.withoutBinding(data, 'https://otp.test').bindings, ['junk', bind('https://c.d', 'b')]);
  assert.deepEqual(b.withoutBinding(data, 'https://otp.test/login?x').bindings, ['junk', bind('https://c.d', 'b')]);
  for (const other of ['https://sub.otp.test', 'https://otp.test:8443', 'http://otp.test', 'https://otp.test.evil', '', null]) {
    assert.deepEqual(b.withoutBinding(data, other).bindings, data.bindings, String(other));
  }
  assert.equal(data.bindings.length, 3);
});

test('withoutBinding and withoutAccountBindings never add a bindings key or replace a non-array value', () => {
  const plain = deepFreeze({ accounts: [A] });
  for (const next of [b.withoutBinding(plain, 'https://otp.test'), b.withoutAccountBindings(plain, 'a')]) {
    assert.notEqual(next, plain);
    assert.deepEqual(next, { accounts: [A] });
    assert.equal('bindings' in next, false);
  }
  const odd = deepFreeze({ accounts: [A], bindings: 'x' });
  assert.deepEqual(b.withoutBinding(odd, 'https://otp.test'), { accounts: [A], bindings: 'x' });
  assert.deepEqual(b.withoutAccountBindings(odd, 'a'), { accounts: [A], bindings: 'x' });
});

test('withoutAccountBindings removes every binding of that account and keeps the rest', () => {
  const data = deepFreeze({
    accounts: [A, B],
    bindings: [bind('https://otp.test', 'a'), bind('https://c.d', 'b'), null, bind('https://e.f', 'a')],
  });
  assert.deepEqual(b.withoutAccountBindings(data, 'a').bindings, [bind('https://c.d', 'b'), null]);
  assert.deepEqual(b.withoutAccountBindings(data, 'z').bindings, data.bindings);
  assert.equal(data.bindings.length, 4);
});

test('bindingFor matches the exact origin only', () => {
  const data = deepFreeze({ accounts: [A], bindings: [bind('https://otp.test', 'a', 4)] });
  assert.deepEqual(b.bindingFor(data, 'https://otp.test'), bind('https://otp.test', 'a', 4));
  assert.deepEqual(b.bindingFor(data, 'https://otp.test/login'), bind('https://otp.test', 'a', 4));
  assert.deepEqual(b.bindingFor(data, 'https://OTP.test:443'), bind('https://otp.test', 'a', 4));
  for (const other of [
    'https://sub.otp.test', 'https://otp.test.evil', 'https://otp-test', 'https://otp.test:8443',
    'http://otp.test', 'blob:https://otp.test/x', '', null, undefined,
  ]) {
    assert.equal(b.bindingFor(data, other), null, String(other));
  }
  assert.equal(b.bindingFor({ accounts: [A] }, 'https://otp.test'), null);
  assert.equal(b.bindingFor({ accounts: [A], bindings: 'x' }, 'https://otp.test'), null);
});

test('bindingFor returns a copy', () => {
  const data = { accounts: [A], bindings: [bind('https://otp.test', 'a')] };
  b.bindingFor(data, 'https://otp.test').accountId = 'z';
  assert.equal(data.bindings[0].accountId, 'a');
});

test('boundOrigins: sorted, unique, only origins whose account exists', () => {
  const data = deepFreeze({
    accounts: [A, ['array', 'entry'], null, B, { issuer: 'no id' }],
    bindings: [
      bind('https://z.test', 'a'),
      bind('https://gone.test', 'deleted'),
      bind('https://b.test', 'b'),
      bind('https://b.test', 'a'),
      bind('https://m.test:8443', 'a'),
      bind('http://plain.test', 'a'),
      bind('https://n.test', ''),
    ],
  });
  assert.deepEqual(b.boundOrigins(data), ['https://b.test', 'https://m.test:8443', 'https://z.test']);
  assert.deepEqual(b.boundOrigins(b.withoutAccountBindings(data, 'a')), ['https://b.test']);
  assert.deepEqual(b.boundOrigins({ accounts: 'x', bindings: [bind('https://z.test', 'a')] }), []);
  assert.deepEqual(b.boundOrigins({ accounts: [A] }), []);
  assert.deepEqual(b.boundOrigins(null), []);
});
