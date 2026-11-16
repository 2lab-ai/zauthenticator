import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encode } from '../extension/lib/base32.js';
import { hotp, totp, remainingSeconds } from '../extension/lib/totp.js';

const ascii = (s) => new TextEncoder().encode(s);

// RFC 6238 Appendix B: each hash has its own seed length.
const SEEDS = {
  SHA1: ascii('12345678901234567890'),
  SHA256: ascii('12345678901234567890123456789012'),
  SHA512: ascii('1234567890123456789012345678901234567890123456789012345678901234'),
};

// RFC 4226 Appendix D (SHA1, 6 digits, seed "12345678901234567890").
const HOTP_VECTORS = [
  '755224', '287082', '359152', '969429', '338314',
  '254676', '287922', '162583', '399871', '520489',
];

// RFC 6238 Appendix B (8 digits, period 30); cross-checked with Python hmac/hashlib.
const TOTP_VECTORS = [
  { time: 59, SHA1: '94287082', SHA256: '46119246', SHA512: '90693936' },
  { time: 1111111109, SHA1: '07081804', SHA256: '68084774', SHA512: '25091201' },
  { time: 1111111111, SHA1: '14050471', SHA256: '67062674', SHA512: '99943326' },
  { time: 1234567890, SHA1: '89005924', SHA256: '91819424', SHA512: '93441116' },
  { time: 2000000000, SHA1: '69279037', SHA256: '90698825', SHA512: '38618901' },
  { time: 20000000000, SHA1: '65353130', SHA256: '77737706', SHA512: '47863826' },
];

// Counters at and above 2^32 exercise the high word (none of the RFC vectors do);
// expected values from Python hmac with struct.pack('>Q', counter).
const WIDE_COUNTERS = [
  [2 ** 32 - 1, '57117190'],
  [2 ** 32, '55999456'],
  [2 ** 32 + 1, '39108930'],
  [Number.MAX_SAFE_INTEGER, '41891307'],
];

test('hotp matches RFC 4226 Appendix D', async () => {
  for (const [counter, expected] of HOTP_VECTORS.entries()) {
    assert.equal(await hotp(SEEDS.SHA1, counter), expected, `counter ${counter}`);
  }
});

test('hotp matches RFC 6238 Appendix B for SHA1, SHA256 and SHA512', async () => {
  for (const vector of TOTP_VECTORS) {
    const counter = Math.floor(vector.time / 30);
    for (const algorithm of ['SHA1', 'SHA256', 'SHA512']) {
      const code = await hotp(SEEDS[algorithm], counter, { algorithm, digits: 8 });
      assert.equal(code, vector[algorithm], `${algorithm} T=${vector.time}`);
    }
  }
});

test('hotp encodes the counter as 64-bit big-endian (number and bigint)', async () => {
  for (const [counter, expected] of WIDE_COUNTERS) {
    assert.equal(await hotp(SEEDS.SHA1, counter, { digits: 8 }), expected, `counter ${counter}`);
    assert.equal(await hotp(SEEDS.SHA1, BigInt(counter), { digits: 8 }), expected, `counter ${counter}n`);
  }
  assert.equal(await hotp(SEEDS.SHA1, 2n ** 64n - 1n, { digits: 8 }), '63094451');
});

test('hotp truncates to 6, 7 and 8 digits with zero padding', async () => {
  assert.equal(await hotp(SEEDS.SHA1, 1, { digits: 6 }), '287082');
  assert.equal(await hotp(SEEDS.SHA1, 1, { digits: 7 }), '4287082');
  assert.equal(await hotp(SEEDS.SHA1, 1, { digits: 8 }), '94287082');
  assert.equal(await hotp(SEEDS.SHA1, 2n ** 64n - 1n, { digits: 6 }), '094451');
});

test('hotp rejects bad algorithm, digits, counter and key', async () => {
  for (const algorithm of ['MD5', 'sha1', 'SHA-1', 'toString']) {
    await assert.rejects(hotp(SEEDS.SHA1, 0, { algorithm }), /Unsupported algorithm/, algorithm);
  }
  for (const digits of [5, 9, 6.5, '6']) {
    await assert.rejects(hotp(SEEDS.SHA1, 0, { digits }), RangeError, String(digits));
  }
  for (const counter of [-1, 1.5, 2 ** 53, -1n, 2n ** 64n, '1']) {
    await assert.rejects(hotp(SEEDS.SHA1, counter), RangeError, String(counter));
  }
  await assert.rejects(hotp(new Uint8Array(0), 0), TypeError);
  await assert.rejects(hotp('12345678901234567890', 0), TypeError);
});

test('totp through the base32 path matches RFC 6238 Appendix B', async () => {
  for (const vector of TOTP_VECTORS) {
    for (const algorithm of ['SHA1', 'SHA256', 'SHA512']) {
      const account = { secret: encode(SEEDS[algorithm]), algorithm, digits: 8, period: 30 };
      assert.equal(await totp(account, vector.time * 1000), vector[algorithm], `${algorithm} T=${vector.time}`);
    }
  }
});

test('totp accepts lowercase, spaced base32 and defaults to SHA1/6/30', async () => {
  const secret = 'gezd gnbv gy3t qojq gezd gnbv gy3t qojq';
  assert.equal(await totp({ secret }, 59_000), '287082');
  assert.equal(await totp({ secret, algorithm: 'SHA1', digits: 6, period: 30 }, 59_000), '287082');
});

test('totp steps exactly on period boundaries, ignoring milliseconds', async () => {
  const account = { secret: encode(SEEDS.SHA1), algorithm: 'SHA1', digits: 8, period: 30 };
  assert.equal(await totp(account, 1111111109_999), '07081804');
  assert.equal(await totp(account, 1111111110_000), '14050471');
  assert.equal(await totp(account, 59_999), '94287082');
  assert.equal(await totp(account, 60_000), await hotp(SEEDS.SHA1, 2, { digits: 8 }));
});

test('totp handles counters above 32 bits', async () => {
  const account = { secret: encode(SEEDS.SHA1), digits: 8, period: 1 };
  assert.equal(await totp(account, 2 ** 32 * 1000), '55999456');
});

test('totp rejects bad period and time', async () => {
  const secret = encode(SEEDS.SHA1);
  for (const period of [0, 301, 30.5, '30']) {
    await assert.rejects(totp({ secret, period }, 0), RangeError, String(period));
  }
  for (const nowMs of [-1, NaN, Infinity]) {
    await assert.rejects(totp({ secret }, nowMs), RangeError, String(nowMs));
  }
  await assert.rejects(totp({ secret: 'not base32!' }, 0), /base32/);
});

test('remainingSeconds counts down from period to 1', () => {
  assert.equal(remainingSeconds(30, 0), 30);
  assert.equal(remainingSeconds(30, 999), 30);
  assert.equal(remainingSeconds(30, 1_000), 29);
  assert.equal(remainingSeconds(30, 29_000), 1);
  assert.equal(remainingSeconds(30, 29_999), 1);
  assert.equal(remainingSeconds(30, 30_000), 30);
  assert.equal(remainingSeconds(30, 1111111110_000), 30);
  assert.equal(remainingSeconds(30, 1111111109_500), 1);
  assert.equal(remainingSeconds(60, 59_000), 1);
  assert.equal(remainingSeconds(1, 12_345), 1);
});

test('remainingSeconds stays within 1..period for the current time', () => {
  const left = remainingSeconds(30);
  assert.ok(Number.isInteger(left) && left >= 1 && left <= 30, String(left));
});

test('remainingSeconds rejects bad period and time', () => {
  for (const period of [0, 301, 1.5, undefined]) {
    assert.throws(() => remainingSeconds(period, 0), RangeError, String(period));
  }
  assert.throws(() => remainingSeconds(30, -1), RangeError);
});
