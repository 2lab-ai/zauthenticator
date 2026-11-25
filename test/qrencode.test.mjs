import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { encodeQR, QREncodeError } from '../extension/lib/qrencode.js';
import { format } from '../extension/lib/otpauth.js';
import { migrationBatches } from '../extension/lib/migration.js';

// The vendored builds run as classic scripts, as popup.html loads them: `var qrcode` and jsQR's
// UMD wrapper then define globalThis.qrcode and globalThis.jsQR. (createRequire would not do:
// package.json says "type": "module", so Node reads vendor/*.js as ES modules, and neither file
// exports anything that way.)
for (const name of ['qrcode.js', 'jsQR.js']) {
  const file = new URL(`../extension/vendor/${name}`, import.meta.url);
  vm.runInThisContext(fs.readFileSync(file, 'utf8'), { filename: file.pathname });
}
const { qrcode, jsQR } = globalThis;

// Draws the modules as RGBA pixels, `scale` px per module, with a 4-module white margin.
function render({ size, modules }, scale = 4, margin = 4) {
  const width = (size + 2 * margin) * scale;
  const data = new Uint8ClampedArray(width * width * 4).fill(255);
  for (let row = 0; row < size; row++) {
    for (let col = 0; col < size; col++) {
      if (!modules[row * size + col]) continue;
      for (let y = 0; y < scale; y++) {
        for (let x = 0; x < scale; x++) {
          const i = (((row + margin) * scale + y) * width + (col + margin) * scale + x) * 4;
          data[i] = data[i + 1] = data[i + 2] = 0;
        }
      }
    }
  }
  return { data, width, height: width };
}

function scan(qr) {
  const { data, width, height } = render(qr);
  return jsQR(data, width, height)?.data ?? null;
}

// The same text through qrcode-generator directly: its default stringToBytes keeps the low byte of
// each character, so a string of the UTF-8 bytes as Latin-1 characters gives it those bytes.
function reference(text, ecc) {
  const current = qrcode.stringToBytes;
  qrcode.stringToBytes = qrcode.stringToBytesFuncs.default;
  try {
    const qr = qrcode(0, ecc);
    qr.addData(Buffer.from(text, 'utf8').toString('latin1'), 'Byte');
    qr.make();
    return qr;
  } finally {
    qrcode.stringToBytes = current;
  }
}

function assertSameAsReference(text, ecc, { size, modules }) {
  const ref = reference(text, ecc);
  assert.equal(size, ref.getModuleCount());
  assert.equal(modules.length, size * size);
  for (let row = 0; row < size; row++) {
    for (let col = 0; col < size; col++) {
      if (modules[row * size + col] !== (ref.isDark(row, col) ? 1 : 0)) assert.fail(`module ${row},${col} differs`);
    }
  }
}

// Printable ASCII in a fixed, varied order (byte mode, not numeric or alphanumeric).
const printable = (length) => Array.from({ length }, (_, i) => String.fromCharCode(33 + ((i * 37) % 94))).join('');

const otpauthUri = format({ issuer: '네이버 (Naver)', label: '홍길동@example.com', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA256', digits: 8 });
const accounts = Array.from({ length: 20 }, (_, i) => ({
  issuer: `Issuer ${i}`,
  label: `user${i}@example.com`,
  secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', // 30 bytes
}));
const migrationUri = migrationBatches(accounts, { batchId: 123456789 })[0].uri;

test('encodeQR output scans back to the same text with jsQR', () => {
  assert.ok(otpauthUri.includes('%EB%84%A4')); // the Korean issuer, percent-encoded by format()
  assert.ok(migrationUri.length > 600 && migrationUri.length <= 700, `${migrationUri.length}`);
  const inputs = [
    'hello',
    otpauthUri,
    '안녕하세요 👋 zauthenticator', // raw UTF-8: Hangul and a surrogate pair
    migrationUri,
    printable(2000),
  ];
  for (const text of inputs) {
    const qr = encodeQR(text);
    assertSameAsReference(text, 'M', qr);
    assert.equal(scan(qr), text, `${text.length} chars`);
  }
});

test('encodeQR picks the smallest version for each error correction level', () => {
  // Byte-mode capacity of version 1 is 17/14/11/7 bytes at L/M/Q/H.
  for (const [ecc, fits] of [['L', 17], ['M', 14], ['Q', 11], ['H', 7]]) {
    assert.equal(encodeQR('x'.repeat(fits), { ecc }).size, 21, ecc);
    assert.equal(encodeQR('x'.repeat(fits + 1), { ecc }).size, 25, ecc);
    const text = printable(300);
    const qr = encodeQR(text, { ecc });
    assertSameAsReference(text, ecc, qr);
    assert.equal(scan(qr), text, ecc);
  }
  assert.equal(encodeQR('x'.repeat(14)).size, 21); // M by default
  // A 700-character URI needs version 21 (101 modules) at M.
  assert.equal(encodeQR('x'.repeat(700)).size, 101);
});

test('encodeQR counts UTF-8 bytes and refuses text past version 40', () => {
  for (const [ecc, max] of [['L', 2953], ['M', 2331], ['Q', 1663], ['H', 1273]]) {
    assert.equal(encodeQR('a'.repeat(max), { ecc }).size, 177, ecc);
    assert.throws(() => encodeQR('a'.repeat(max + 1), { ecc }), (err) => err instanceof QREncodeError && err.code === 'too-long', ecc);
  }
  // 777 Hangul syllables are 2331 bytes; one more is too long although it is far fewer characters.
  assert.equal(encodeQR('가'.repeat(777)).size, 177);
  assert.throws(() => encodeQR('가'.repeat(778)), { name: 'QREncodeError', code: 'too-long' });
});

test('encodeQR leaves qrcode.stringToBytes as it found it', () => {
  const original = qrcode.stringToBytes;
  assert.equal(original, qrcode.stringToBytesFuncs.default);
  encodeQR('한국어');
  assert.equal(qrcode.stringToBytes, original);
  assert.throws(() => encodeQR('a'.repeat(3000)), { code: 'too-long' });
  assert.equal(qrcode.stringToBytes, original);
  // Even when another caller has switched it to UTF-8, the bytes are the same and it is restored.
  qrcode.stringToBytes = qrcode.stringToBytesFuncs['UTF-8'];
  try {
    const qr = encodeQR('한국어 text');
    assertSameAsReference('한국어 text', 'M', qr);
    assert.equal(qrcode.stringToBytes, qrcode.stringToBytesFuncs['UTF-8']);
  } finally {
    qrcode.stringToBytes = original;
  }
});

test('encodeQR without the vendored encoder throws encoder-missing', () => {
  // A top-level var of a classic script cannot be deleted, so the global is overwritten instead.
  globalThis.qrcode = undefined;
  try {
    assert.throws(() => encodeQR('hello'), (err) => err instanceof QREncodeError && err.code === 'encoder-missing');
    globalThis.qrcode = {};
    assert.throws(() => encodeQR('hello'), { code: 'encoder-missing' });
  } finally {
    globalThis.qrcode = qrcode;
  }
  assert.equal(encodeQR('hello').size, 21);
});

test('encodeQR rejects a non-string text and an unknown level', () => {
  for (const text of [undefined, null, 42, ['a']]) assert.throws(() => encodeQR(text), TypeError);
  for (const ecc of ['m', 'X', '', 1, null, 'toString']) assert.throws(() => encodeQR('a', { ecc }), TypeError, String(ecc));
});

test('every Google Authenticator export batch scans back to its URI', () => {
  const many = Array.from({ length: 45 }, (_, i) => ({
    issuer: i % 3 === 0 ? '카카오' : `Service ${i}`,
    label: `account-${i}@example.com`,
    secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
    algorithm: ['SHA1', 'SHA256', 'SHA512'][i % 3],
    digits: i % 2 ? 8 : 6,
  }));
  const batches = migrationBatches(many);
  assert.ok(batches.length > 1);
  for (const { uri } of batches) {
    assert.ok(uri.length <= 700);
    const qr = encodeQR(uri);
    assert.ok(qr.size <= 101, `${qr.size} modules`);
    assert.equal(scan(qr), uri);
  }
});
