import { test } from 'node:test';
import assert from 'node:assert/strict';
import { migrationBatches, migrationIssue } from '../extension/lib/migration.js';
import { decode as base32Decode, encode as base32Encode } from '../extension/lib/base32.js';
import { normalize } from '../extension/lib/otpauth.js';

// ---- a small protobuf reader, written independently of the module under test ----------------

const PREFIX = 'otpauth-migration://offline?data=';

function readVarint(bytes, pos) {
  let value = 0n;
  for (let shift = 0n; ; shift += 7n) {
    if (pos >= bytes.length) throw new Error('truncated varint');
    const b = bytes[pos++];
    value |= BigInt(b & 0x7f) << shift;
    if (!(b & 0x80)) return [value, pos];
    if (shift > 63n) throw new Error('varint too long');
  }
}

// → [{ field, wire, value (BigInt for varints, Uint8Array for length-delimited), raw }] in order.
function readFields(bytes) {
  const fields = [];
  let pos = 0;
  while (pos < bytes.length) {
    const start = pos;
    let key;
    [key, pos] = readVarint(bytes, pos);
    const field = Number(key >> 3n);
    const wire = Number(key & 7n);
    let value;
    if (wire === 0) [value, pos] = readVarint(bytes, pos);
    else if (wire === 2) {
      let length;
      [length, pos] = readVarint(bytes, pos);
      if (pos + Number(length) > bytes.length) throw new Error('truncated field');
      value = bytes.subarray(pos, pos + Number(length));
      pos += Number(length);
    } else throw new Error(`unexpected wire type ${wire}`);
    fields.push({ field, wire, value, raw: bytes.subarray(start, pos) });
  }
  return fields;
}

const text = (bytes) => new TextDecoder('utf-8', { fatal: true }).decode(bytes);

// Each known field at most once (except repeated otp_parameters), with the expected wire type;
// unknown fields fail the test.
function decodeMessage(bytes, schema) {
  const out = {};
  for (const { field, wire, value, raw } of readFields(bytes)) {
    const spec = schema[field];
    assert.ok(spec, `unknown field ${field}`);
    assert.equal(wire, spec.wire, `wire type of field ${field}`);
    if (spec.repeated) (out[spec.name] ??= []).push({ value, raw });
    else {
      assert.ok(!(spec.name in out), `field ${spec.name} repeated`);
      out[spec.name] = wire === 0 ? Number(value) : value;
    }
  }
  return out;
}

const OTP_SCHEMA = {
  1: { name: 'secret', wire: 2 },
  2: { name: 'name', wire: 2 },
  3: { name: 'issuer', wire: 2 },
  4: { name: 'algorithm', wire: 0 },
  5: { name: 'digits', wire: 0 },
  6: { name: 'type', wire: 0 },
  7: { name: 'counter', wire: 0 },
};
const PAYLOAD_SCHEMA = {
  1: { name: 'otp', wire: 2, repeated: true },
  2: { name: 'version', wire: 0 },
  3: { name: 'batchSize', wire: 0 },
  4: { name: 'batchIndex', wire: 0 },
  5: { name: 'batchId', wire: 0 },
};

function payloadBytes(uri) {
  assert.ok(uri.startsWith(PREFIX), uri);
  const data = decodeURIComponent(uri.slice(PREFIX.length));
  assert.match(data, /^[A-Za-z0-9+/]*={0,2}$/);
  assert.equal(data.length % 4, 0);
  // Every character outside the base64 alphabet letters/digits is percent-encoded in the URI.
  assert.match(uri.slice(PREFIX.length), /^(?:[A-Za-z0-9]|%2B|%2F|%3D)*$/);
  return new Uint8Array(Buffer.from(data, 'base64'));
}

function decodeUri(uri) {
  const payload = decodeMessage(payloadBytes(uri), PAYLOAD_SCHEMA);
  const entries = (payload.otp ?? []).map(({ value, raw }) => {
    const otp = decodeMessage(value, OTP_SCHEMA);
    return {
      raw,
      secret: otp.secret,
      name: otp.name === undefined ? undefined : text(otp.name),
      issuer: otp.issuer === undefined ? undefined : text(otp.issuer),
      algorithm: otp.algorithm,
      digits: otp.digits,
      type: otp.type,
      counter: otp.counter,
    };
  });
  return { ...payload, otp: entries };
}

// ---- test accounts ----------------------------------------------------------------------------

const bytesOf = (length, seed) => Uint8Array.from({ length }, (_, i) => (i * 73 + seed * 151 + 11) & 0xff);
const secretOf = (length, seed) => base32Encode(bytesOf(length, seed));

const MIX = [
  { issuer: 'GitHub', label: 'octocat', secret: secretOf(10, 1), algorithm: 'SHA1', digits: 6 },
  { issuer: '네이버', label: '홍길동@naver.com', secret: secretOf(20, 2), algorithm: 'SHA256', digits: 8 },
  { issuer: '', label: 'no-issuer@example.com', secret: secretOf(32, 3), algorithm: 'SHA512', digits: 6 },
  { issuer: 'Only Issuer', label: '', secret: secretOf(64, 4), algorithm: 'SHA1', digits: 8 },
  { issuer: '', label: '', secret: secretOf(20, 5), algorithm: 'SHA256', digits: 6 },
  { issuer: '카카오 🍫', label: 'ryan', secret: secretOf(64, 6), algorithm: 'SHA512', digits: 8, period: 30 },
];

const ALGORITHM_CODE = { SHA1: 1, SHA256: 2, SHA512: 3 };
const DIGITS_CODE = { 6: 1, 8: 2 };

// What each account must decode to (after the defaults SHA1, 6 digits).
function expectedEntry(input) {
  const account = normalize(input);
  const name = account.label || account.issuer;
  return {
    secret: base32Decode(account.secret),
    name: name === '' ? undefined : name,
    issuer: account.issuer === '' ? undefined : account.issuer,
    algorithm: ALGORITHM_CODE[account.algorithm],
    digits: DIGITS_CODE[account.digits],
    type: 2,
    counter: undefined,
  };
}

// Decodes every batch, checks the batch header fields and the returned objects against each
// other, and returns the accounts' entries in order.
function decodeAll(batches, batchId) {
  const entries = [];
  const ids = new Set();
  batches.forEach((batch, i) => {
    const decoded = decodeUri(batch.uri);
    assert.equal(decoded.version, 1);
    assert.equal(decoded.batchSize, batches.length);
    assert.equal(decoded.batchIndex ?? 0, i);
    assert.ok(Number.isInteger(decoded.batchId) && decoded.batchId >= 1 && decoded.batchId <= 0x7fffffff);
    if (batchId !== undefined) assert.equal(decoded.batchId, batchId);
    ids.add(decoded.batchId);
    assert.deepEqual({ count: batch.count, index: batch.index, size: batch.size }, { count: decoded.otp.length, index: i, size: batches.length });
    assert.deepEqual(Object.keys(batch).sort(), ['count', 'index', 'size', 'uri']);
    entries.push(...decoded.otp);
  });
  assert.equal(ids.size, 1, 'one batch id per export');
  return entries;
}

const strip = ({ raw, ...entry }) => entry;

// ---- tests ------------------------------------------------------------------------------------

test('known answer: one account, batch 1 of 1, id 1', () => {
  const account = { secret: 'JBSWY3DPEHPK3PXP', label: 'alice@example.com', issuer: 'Example' };
  // Built by hand from the schema.
  const ascii = (s) => Array.from(s, (c) => c.charCodeAt(0));
  const otp = [
    0x0a, 10, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef, // 1 secret: base32 JBSWY3DPEHPK3PXP
    0x12, 17, ...ascii('alice@example.com'), // 2 name
    0x1a, 7, ...ascii('Example'), // 3 issuer
    0x20, 1, // 4 algorithm SHA1
    0x28, 1, // 5 digits SIX
    0x30, 2, // 6 type TOTP
  ];
  assert.equal(otp.length, 46);
  const payload = [
    0x0a, 46, ...otp, // 1 otp_parameters
    0x10, 1, // 2 version
    0x18, 1, // 3 batch_size
    0x20, 0, // 4 batch_index
    0x28, 1, // 5 batch_id
  ];
  const expected = PREFIX + encodeURIComponent(Buffer.from(payload).toString('base64'));
  assert.equal(expected, 'otpauth-migration://offline?data=Ci4KCkhlbGxvId6tvu8SEWFsaWNlQGV4YW1wbGUuY29tGgdFeGFtcGxlIAEoATACEAEYASAAKAE%3D');
  assert.deepEqual(migrationBatches([account], { batchId: 1 }), [{ uri: expected, count: 1, index: 0, size: 1 }]);
});

test('every field round-trips for a mix of accounts', () => {
  const batches = migrationBatches(MIX, { batchId: 424242 });
  const entries = decodeAll(batches, 424242);
  assert.deepEqual(entries.map(strip), MIX.map(expectedEntry));
  // Spot checks on what the mix covers.
  assert.deepEqual(entries.map((e) => e.secret.length), [10, 20, 32, 64, 20, 64]);
  assert.equal(entries[1].name, '홍길동@naver.com');
  assert.equal(entries[3].name, 'Only Issuer'); // empty label: the issuer is the name
  assert.equal(entries[2].issuer, undefined); // empty issuer: no field at all
  assert.equal(entries[4].name, undefined);
  assert.equal(entries[5].issuer, '카카오 🍫');
});

test('accounts are normalized first', () => {
  const [batch] = migrationBatches([{ issuer: '  Example ', label: ' alice ', secret: 'jbsw y3dp-ehpk 3pxp', algorithm: 'sha-256', digits: '8', period: '30' }], { batchId: 7 });
  const [entry] = decodeAll([batch], 7);
  assert.deepEqual(strip(entry), expectedEntry({ issuer: 'Example', label: 'alice', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA256', digits: 8 }));
});

test('accounts are packed in order, up to maxPerBatch each', () => {
  const small = Array.from({ length: 25 }, (_, i) => ({ issuer: 'X', label: `user${i}`, secret: secretOf(10, i) }));
  const batches = migrationBatches(small, { batchId: 99 });
  assert.deepEqual(batches.map((b) => b.count), [10, 10, 5]);
  const entries = decodeAll(batches, 99);
  assert.deepEqual(entries.map((e) => e.name), small.map((a) => a.label));
  assert.deepEqual(migrationBatches(small, { batchId: 99, maxPerBatch: 7 }).map((b) => b.count), [7, 7, 7, 4]);
  assert.deepEqual(migrationBatches(small, { batchId: 99, maxPerBatch: 25, maxChars: 1e6 }).map((b) => b.count), [25]);
});

// The same framing as the module, for checking that a batch could not have taken one more account.
function varintBytes(n) {
  const out = [];
  while (n > 0x7f) {
    out.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  out.push(n);
  return out;
}
function uriOf(rawEntries, size, index, id) {
  const header = [0x10, 1, 0x18, ...varintBytes(size), 0x20, ...varintBytes(index), 0x28, ...varintBytes(id)];
  const bytes = Buffer.concat([...rawEntries, Buffer.from(header)]);
  return PREFIX + encodeURIComponent(bytes.toString('base64'));
}

function checkGreedy(batches, maxChars, maxPerBatch) {
  const decoded = batches.map((b) => decodeUri(b.uri));
  batches.forEach((batch, i) => {
    const { otp, batchSize, batchIndex = 0, batchId } = decoded[i];
    const raws = otp.map((e) => e.raw);
    assert.equal(uriOf(raws, batchSize, batchIndex, batchId), batch.uri, 'test framing matches');
    assert.ok(batch.count <= maxPerBatch);
    if (batch.count > 1) assert.ok(batch.uri.length <= maxChars, `batch ${i}: ${batch.uri.length} > ${maxChars}`);
    if (i + 1 < batches.length && batch.count < maxPerBatch) {
      const grown = uriOf([...raws, decoded[i + 1].otp[0].raw], batchSize, batchIndex, batchId);
      assert.ok(grown.length > maxChars, `batch ${i} could have taken the next account`);
    }
  });
}

test('every URI stays within maxChars, and no batch could take the next account', () => {
  const big = Array.from({ length: 40 }, (_, i) => ({
    issuer: i % 2 ? `서비스 ${i}` : `Service number ${i}`,
    label: `someone.with.a.long.name+${'x'.repeat(i % 7)}@example.com`,
    secret: secretOf([10, 20, 32, 64][i % 4], i),
    algorithm: ['SHA1', 'SHA256', 'SHA512'][i % 3],
    digits: i % 2 ? 8 : 6,
  }));
  for (const maxChars of [700, 400, 1000, 2000]) {
    const batches = migrationBatches(big, { batchId: 5, maxChars });
    assert.ok(batches.every((b) => b.uri.length <= maxChars), `maxChars ${maxChars}`);
    assert.ok(batches.some((b) => b.count > 1), `maxChars ${maxChars}`);
    checkGreedy(batches, maxChars, 10);
    assert.deepEqual(decodeAll(batches, 5).map(strip), big.map(expectedEntry));
  }
  // maxChars, not maxPerBatch, is what limits these at 700.
  assert.ok(migrationBatches(big, { batchId: 5 }).every((b) => b.count < 10));
});

test('an account too long for maxChars goes alone, and nothing joins it', () => {
  const huge = { issuer: 'Huge', label: 'h'.repeat(800), secret: secretOf(64, 9) };
  const list = [MIX[0], MIX[1], huge, MIX[2], MIX[3]];
  const batches = migrationBatches(list, { batchId: 3 });
  assert.deepEqual(batches.map((b) => b.count), [2, 1, 2]);
  assert.ok(batches[1].uri.length > 700);
  assert.ok(batches[0].uri.length <= 700 && batches[2].uri.length <= 700);
  assert.deepEqual(decodeAll(batches, 3).map(strip), list.map(expectedEntry));
  // With a tiny maxChars every account is alone.
  const alone = migrationBatches(MIX, { batchId: 3, maxChars: 1 });
  assert.deepEqual(alone.map((b) => b.count), MIX.map(() => 1));
  assert.deepEqual(decodeAll(alone, 3).map(strip), MIX.map(expectedEntry));
});

test('batch size and index past 127 take two-byte varints', () => {
  const many = Array.from({ length: 300 }, (_, i) => ({ issuer: 'I', label: `u${i}`, secret: secretOf(10, i) }));
  const batches = migrationBatches(many, { batchId: 0x7fffffff, maxPerBatch: 2 });
  assert.equal(batches.length, 150);
  assert.deepEqual(decodeAll(batches, 0x7fffffff).map((e) => e.name), many.map((a) => a.label));
  checkGreedy(batches, 700, 2);
});

test('the default batch id is a random positive 31-bit integer', (t) => {
  for (let i = 0; i < 20; i++) decodeAll(migrationBatches(MIX, { maxChars: 200 }));
  const ids = new Set(Array.from({ length: 20 }, () => decodeUri(migrationBatches([MIX[0]])[0].uri).batchId));
  assert.ok(ids.size > 1, 'ids vary');
  // A draw that would give 0 is drawn again; the top bit is dropped.
  const words = [1, 0xffffffff];
  t.mock.method(crypto, 'getRandomValues', (array) => {
    array[0] = words.shift();
    return array;
  });
  assert.equal(decodeUri(migrationBatches([MIX[0]])[0].uri).batchId, 0x7fffffff);
  assert.equal(words.length, 0);
});

test('migrationIssue names what the format cannot carry', () => {
  const base = { issuer: 'Example', label: 'alice', secret: 'JBSWY3DPEHPK3PXP' };
  assert.equal(migrationIssue(base), null);
  assert.equal(migrationIssue({ ...base, digits: 8, algorithm: 'SHA512', period: 30 }), null);
  assert.equal(migrationIssue({ ...base, digits: '6', period: '30' }), null);
  assert.equal(migrationIssue({ ...base, period: 60 }), 'period');
  assert.equal(migrationIssue({ ...base, period: 15 }), 'period');
  assert.equal(migrationIssue({ ...base, digits: 7 }), 'digits');
  assert.equal(migrationIssue({ ...base, digits: 7, period: 60 }), 'period');
  for (const account of MIX) assert.equal(migrationIssue(account), null);
  // Invalid accounts throw as normalize does.
  assert.throws(() => migrationIssue({ ...base, secret: '' }), /Missing secret/);
  assert.throws(() => migrationIssue({ ...base, secret: 'not base32!' }), /Invalid secret/);
  assert.throws(() => migrationIssue({ ...base, digits: 9 }), /Invalid digits/);
  assert.throws(() => migrationIssue(null), TypeError);
});

test('migrationBatches rejects what it cannot export', () => {
  const ok = { issuer: 'Example', label: 'alice', secret: 'JBSWY3DPEHPK3PXP' };
  assert.throws(() => migrationBatches([]), TypeError);
  assert.throws(() => migrationBatches(), TypeError);
  assert.throws(() => migrationBatches(ok), TypeError);
  assert.throws(() => migrationBatches([ok, { ...ok, period: 60 }]), { name: 'TypeError', message: /Account 2 .*\(period\)/ });
  assert.throws(() => migrationBatches([{ ...ok, digits: 7 }, ok]), { name: 'TypeError', message: /Account 1 .*\(digits\)/ });
  assert.throws(() => migrationBatches([ok, { ...ok, secret: '' }]), /Missing secret/);
  for (const batchId of [0, -1, 0x80000000, 1.5, '5', null, NaN]) {
    assert.throws(() => migrationBatches([ok], { batchId }), TypeError, String(batchId));
  }
  for (const value of [0, -1, 1.5, '700', null, Infinity]) {
    assert.throws(() => migrationBatches([ok], { maxChars: value }), TypeError, `maxChars ${value}`);
    assert.throws(() => migrationBatches([ok], { maxPerBatch: value }), TypeError, `maxPerBatch ${value}`);
  }
});
