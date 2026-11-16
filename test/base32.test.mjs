import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decode, encode } from '../extension/lib/base32.js';

const ascii = (s) => new TextEncoder().encode(s);

// RFC 4648 section 10 test vectors (padding stripped on encode).
const RFC4648 = [
  ['', ''],
  ['f', 'MY'],
  ['fo', 'MZXQ'],
  ['foo', 'MZXW6'],
  ['foob', 'MZXW6YQ'],
  ['fooba', 'MZXW6YTB'],
  ['foobar', 'MZXW6YTBOI'],
];

test('encode matches RFC 4648 vectors, uppercase without padding', () => {
  for (const [plain, b32] of RFC4648) assert.equal(encode(ascii(plain)), b32, plain);
});

test('decode matches RFC 4648 vectors, with and without padding', () => {
  const padded = ['MY======', 'MZXQ====', 'MZXW6===', 'MZXW6YQ=', 'MZXW6YTB', 'MZXW6YTBOI======'];
  for (const [i, [plain, b32]] of RFC4648.slice(1).entries()) {
    assert.deepEqual(decode(b32), ascii(plain), b32);
    assert.deepEqual(decode(padded[i]), ascii(plain), padded[i]);
  }
});

test('decode is case-insensitive and ignores whitespace and dashes', () => {
  const expected = ascii('12345678901234567890');
  assert.deepEqual(decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'), expected);
  assert.deepEqual(decode('gezdgnbvgy3tqojqgezdgnbvgy3tqojq'), expected);
  assert.deepEqual(decode(' gezd gnbv gy3t qojq\tGEZD-GNBV-GY3T-QOJQ\n'), expected);
});

test('round-trips arbitrary bytes of every length remainder', () => {
  for (let len = 1; len <= 40; len++) {
    const bytes = Uint8Array.from({ length: len }, (_, i) => (i * 37 + len * 11) & 0xff);
    assert.deepEqual(decode(encode(bytes)), bytes, `length ${len}`);
  }
  assert.equal(encode(new Uint8Array(0)), '');
});

test('decode rejects empty input', () => {
  for (const input of ['', '   ', '====', '- -']) {
    assert.throws(() => decode(input), /empty input/, JSON.stringify(input));
  }
});

test('decode rejects characters outside the alphabet', () => {
  for (const input of ['MZXW1', 'MZXW8', 'MZXW0', 'MZ!W6', 'MZ=XW6', 'MZXW6ß', 'ßS']) {
    assert.throws(() => decode(input), /invalid character/, input);
  }
});

test('decode rejects lengths that cannot come from whole bytes', () => {
  for (const input of ['M', 'MZX', 'MZXW6Y', 'MZXW6YTBO']) {
    assert.throws(() => decode(input), /invalid length/, input);
  }
});

test('decode and encode reject wrong argument types', () => {
  assert.throws(() => decode(null), TypeError);
  assert.throws(() => encode('MZXW6'), TypeError);
});
