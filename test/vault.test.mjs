import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_ITERATIONS, VaultError, create, unlock, seal, open } from '../extension/lib/vault.js';
import * as vault from '../extension/lib/vault.js';
import { createHash } from 'node:crypto';

const FAST = { iterations: 1000 };
const PASS = 'correct horse battery';
const DATA = {
  accounts: [{
    id: 'a1', issuer: 'Example', label: 'alice', secret: 'JBSWY3DPEHPK3PXP',
    algorithm: 'SHA1', digits: 6, period: 30, createdAt: 1700000000000,
  }],
};

const isVaultError = (code) => (err) => {
  assert.ok(err instanceof VaultError, `expected VaultError, got ${err}`);
  assert.equal(err.code, code, err.message);
  return true;
};

const flipFirstByte = (b64) => {
  const bytes = Buffer.from(b64, 'base64');
  bytes[0] ^= 1;
  return bytes.toString('base64');
};

test('create then unlock round-trips the data and returns the same key', async () => {
  const { record, rawKey } = await create(PASS, DATA, FAST);
  assert.ok(rawKey instanceof Uint8Array && rawKey.length === 32);
  const unlocked = await unlock(record, PASS);
  assert.deepEqual(unlocked.data, DATA);
  assert.deepEqual(unlocked.rawKey, rawKey);
});

test('record has the documented shape and no plaintext', async () => {
  const { record } = await create(PASS, DATA, FAST);
  assert.deepEqual(Object.keys(record), ['v', 'kdf', 'iv', 'ct']);
  assert.equal(record.v, 1);
  assert.deepEqual(Object.keys(record.kdf), ['name', 'hash', 'iterations', 'salt']);
  assert.equal(record.kdf.name, 'PBKDF2');
  assert.equal(record.kdf.hash, 'SHA-256');
  assert.equal(record.kdf.iterations, 1000);
  assert.equal(Buffer.from(record.kdf.salt, 'base64').length, 16);
  assert.equal(Buffer.from(record.iv, 'base64').length, 12);
  const stored = JSON.stringify(record);
  for (const needle of ['JBSWY3DPEHPK3PXP', 'alice', 'Example', PASS]) {
    assert.ok(!stored.includes(needle), needle);
  }
  assert.deepEqual(JSON.parse(stored), record);
});

test('create uses DEFAULT_ITERATIONS (600000) when no option is given', async () => {
  assert.equal(DEFAULT_ITERATIONS, 600000);
  const { record, rawKey } = await create(PASS, DATA);
  assert.equal(record.kdf.iterations, 600000);
  const unlocked = await unlock(record, PASS);
  assert.deepEqual(unlocked.data, DATA);
  assert.deepEqual(unlocked.rawKey, rawKey);
});

test('seal then open with the same key, keeping the KDF header', async () => {
  const { record, rawKey } = await create(PASS, DATA, FAST);
  const next = { accounts: [...DATA.accounts, { ...DATA.accounts[0], id: 'a2', label: 'bob' }] };
  const sealed = await seal(rawKey, record, next);
  assert.deepEqual(sealed.kdf, record.kdf);
  assert.deepEqual(await open(rawKey, sealed), next);
  assert.deepEqual((await unlock(sealed, PASS)).data, next);
});

test('two seals of the same data use different IVs and ciphertexts', async () => {
  const { record, rawKey } = await create(PASS, DATA, FAST);
  const a = await seal(rawKey, record, DATA);
  const b = await seal(rawKey, record, DATA);
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.ct, b.ct);
  assert.notEqual(a.iv, record.iv);
});

test('two vaults with the same passphrase get different salts and keys', async () => {
  const a = await create(PASS, DATA, FAST);
  const b = await create(PASS, DATA, FAST);
  assert.notEqual(a.record.kdf.salt, b.record.kdf.salt);
  assert.notDeepEqual(a.rawKey, b.rawKey);
});

test('wrong passphrase rejects with bad-passphrase', async () => {
  const { record } = await create(PASS, DATA, FAST);
  await assert.rejects(unlock(record, 'correct horse battery!'), isVaultError('bad-passphrase'));
  await assert.rejects(unlock(record, ''), isVaultError('bad-passphrase'));
  await assert.rejects(unlock(record, undefined), isVaultError('bad-passphrase'));
});

test('tampered ciphertext or IV rejects', async () => {
  const { record, rawKey } = await create(PASS, DATA, FAST);
  for (const field of ['ct', 'iv']) {
    const tampered = { ...record, [field]: flipFirstByte(record[field]) };
    await assert.rejects(unlock(tampered, PASS), isVaultError('bad-passphrase'), field);
    await assert.rejects(open(rawKey, tampered), isVaultError('corrupt'), field);
  }
});

test('records still open after storage reorders their keys', async () => {
  const { record, rawKey } = await create(PASS, DATA, FAST);
  const { salt, iterations, hash, name } = record.kdf;
  const reordered = JSON.parse(JSON.stringify({
    ct: record.ct, iv: record.iv, kdf: { salt, iterations, hash, name }, v: record.v,
  }));
  assert.deepEqual((await unlock(reordered, PASS)).data, DATA);
  assert.deepEqual(await open(rawKey, reordered), DATA);
  assert.deepEqual(await open(rawKey, await seal(rawKey, reordered, DATA)), DATA);
});

test('tampered kdf.iterations or salt rejects in unlock', async () => {
  const { record } = await create(PASS, DATA, FAST);
  const iterations = { ...record, kdf: { ...record.kdf, iterations: 999 } };
  await assert.rejects(unlock(iterations, PASS), isVaultError('bad-passphrase'));
  const salt = { ...record, kdf: { ...record.kdf, salt: flipFirstByte(record.kdf.salt) } };
  await assert.rejects(unlock(salt, PASS), isVaultError('bad-passphrase'));
});

test('header is bound as AES-GCM additional data: tampered kdf rejects in open', async () => {
  // open() never derives a key, so only the AAD binding can catch an edited header.
  const { record, rawKey } = await create(PASS, DATA, FAST);
  const iterations = { ...record, kdf: { ...record.kdf, iterations: 2000 } };
  await assert.rejects(open(rawKey, iterations), isVaultError('corrupt'));
  const salt = { ...record, kdf: { ...record.kdf, salt: flipFirstByte(record.kdf.salt) } };
  await assert.rejects(open(rawKey, salt), isVaultError('corrupt'));
  assert.deepEqual(await open(rawKey, record), DATA);
});

test('open with a key from another vault rejects with corrupt', async () => {
  const a = await create(PASS, DATA, FAST);
  const b = await create(PASS, DATA, FAST);
  await assert.rejects(open(b.rawKey, a.record), isVaultError('corrupt'));
});

test('create rejects passphrases shorter than 8 characters', async () => {
  for (const passphrase of ['', '1234567', '🔐🔐🔐🔐🔐🔐🔐', undefined]) {
    await assert.rejects(create(passphrase, DATA, FAST), isVaultError('weak-passphrase'), String(passphrase));
  }
  const { record } = await create('12345678', DATA, FAST);
  assert.deepEqual((await unlock(record, '12345678')).data, DATA);
});

test('malformed records reject with corrupt', async () => {
  const { record, rawKey } = await create(PASS, DATA, FAST);
  const cases = {
    'not an object': null,
    'missing version': { ...record, v: undefined },
    'missing kdf': { ...record, kdf: undefined },
    'fractional iterations': { ...record, kdf: { ...record.kdf, iterations: 1.5 } },
    'string iterations': { ...record, kdf: { ...record.kdf, iterations: '1000' } },
    'short salt': { ...record, kdf: { ...record.kdf, salt: Buffer.alloc(8).toString('base64') } },
    'bad base64 salt': { ...record, kdf: { ...record.kdf, salt: '***' } },
    'missing iv': { ...record, iv: undefined },
    'short iv': { ...record, iv: Buffer.alloc(8).toString('base64') },
    'short ct': { ...record, ct: Buffer.alloc(8).toString('base64') },
    'bad base64 ct': { ...record, ct: 'not base64!' },
  };
  for (const [name, bad] of Object.entries(cases)) {
    await assert.rejects(unlock(bad, PASS), isVaultError('corrupt'), `unlock: ${name}`);
    await assert.rejects(open(rawKey, bad), isVaultError('corrupt'), `open: ${name}`);
  }
});

test('unknown versions, KDFs and huge iteration counts reject with unsupported', async () => {
  const { record } = await create(PASS, DATA, FAST);
  const cases = {
    'version 3': { ...record, v: 3 },
    'scrypt': { ...record, kdf: { ...record.kdf, name: 'scrypt' } },
    'SHA-1': { ...record, kdf: { ...record.kdf, hash: 'SHA-1' } },
    'iterations 1e9': { ...record, kdf: { ...record.kdf, iterations: 1e9 } },
  };
  for (const [name, bad] of Object.entries(cases)) {
    await assert.rejects(unlock(bad, PASS), isVaultError('unsupported'), name);
  }
});

test('seal and open reject a key that is not 32 bytes', async () => {
  const { record } = await create(PASS, DATA, FAST);
  for (const key of [new Uint8Array(16), 'key', null]) {
    await assert.rejects(seal(key, record, DATA), isVaultError('corrupt'));
    await assert.rejects(open(key, record), isVaultError('corrupt'));
  }
});

test('seal rejects data that is not JSON-serializable', async () => {
  const { record, rawKey } = await create(PASS, DATA, FAST);
  await assert.rejects(seal(rawKey, record, undefined), TypeError);
});

test('passphrases are NFC-normalized: composed and decomposed forms unlock the same vault', async () => {
  const composed = 'Café crème brûlée';
  const decomposed = 'Café crème brûlée';
  assert.notEqual(composed, decomposed);
  assert.equal(decomposed.normalize('NFC'), composed);

  const a = await create(composed, DATA, FAST);
  const fromNfd = await unlock(a.record, decomposed);
  assert.deepEqual(fromNfd.data, DATA);
  assert.deepEqual(fromNfd.rawKey, a.rawKey);

  const b = await create(decomposed, DATA, FAST);
  const fromNfc = await unlock(b.record, composed);
  assert.deepEqual(fromNfc.data, DATA);
  assert.deepEqual(fromNfc.rawKey, b.rawKey);
});

test('the 8-character minimum counts the NFC form', async () => {
  // 7 composed characters, 14 code points when decomposed.
  const decomposed = 'é'.repeat(7);
  assert.equal([...decomposed].length, 14);
  await assert.rejects(create(decomposed, DATA, FAST), isVaultError('weak-passphrase'));
  const { record } = await create('é'.repeat(8), DATA, FAST);
  assert.deepEqual((await unlock(record, 'é'.repeat(8))).data, DATA);
});

// Counts PBKDF2 work: importKey(..., 'PBKDF2', ...) and deriveBits calls on WebCrypto.
function spyOnKdf(t) {
  const { subtle } = globalThis.crypto;
  const importKey = t.mock.method(subtle, 'importKey');
  const deriveBits = t.mock.method(subtle, 'deriveBits');
  return () => importKey.mock.calls.filter((call) => call.arguments[2] === 'PBKDF2').length
    + deriveBits.mock.calls.length;
}

const b64 = (length) => Buffer.alloc(length, 7).toString('base64');
const MiB = 1024 * 1024;

test('structural checks run before key derivation', async (t) => {
  const { record } = await create(PASS, DATA, FAST);
  const kdfCalls = spyOnKdf(t);

  // Positive control: the spy sees a good unlock derive the key.
  await unlock(record, PASS);
  assert.ok(kdfCalls() >= 2, `spy saw ${kdfCalls()} KDF calls on a good unlock`);
  t.mock.reset();
  const kdfCallsAfter = spyOnKdf(t);

  const corrupt = {
    'iv 11 bytes': { ...record, iv: b64(11) },
    'iv 13 bytes': { ...record, iv: b64(13) },
    'iv base64 too long': { ...record, iv: 'A'.repeat(1000) },
    'missing ct': { ...record, ct: undefined },
    'ct 15 bytes': { ...record, ct: b64(15) },
    'ct over 1 MiB': { ...record, ct: b64(MiB + 1) },
    'ct base64 too long': { ...record, ct: 'A'.repeat(3 * MiB) },
    'salt 15 bytes': { ...record, kdf: { ...record.kdf, salt: b64(15) } },
    'salt 65 bytes': { ...record, kdf: { ...record.kdf, salt: b64(65) } },
    'salt base64 too long': { ...record, kdf: { ...record.kdf, salt: 'A'.repeat(MiB) } },
    'iterations 0': { ...record, kdf: { ...record.kdf, iterations: 0 } },
    // At the iteration cap the count itself is accepted; the oversized ct still rejects first.
    'iterations 2,000,000 with ct over 1 MiB': {
      ...record, kdf: { ...record.kdf, iterations: 2000000 }, ct: b64(MiB + 1),
    },
  };
  for (const [name, bad] of Object.entries(corrupt)) {
    await assert.rejects(unlock(bad, PASS), isVaultError('corrupt'), name);
  }
  const unsupported = {
    'iterations 2,000,001': { ...record, kdf: { ...record.kdf, iterations: 2000001 } },
    'iterations 10,000,000': { ...record, kdf: { ...record.kdf, iterations: 10000000 } },
  };
  for (const [name, bad] of Object.entries(unsupported)) {
    await assert.rejects(unlock(bad, PASS), isVaultError('unsupported'), name);
  }
  assert.equal(kdfCallsAfter(), 0, 'no record above was passed to PBKDF2');
});

test('records at the size limits still pass the structural checks', async () => {
  const { record, rawKey } = await create(PASS, DATA, FAST);
  // A 64-byte salt and a 1 MiB ct are structurally valid; they fail only authentication.
  const salt64 = { ...record, kdf: { ...record.kdf, salt: b64(64) } };
  await assert.rejects(unlock(salt64, PASS), isVaultError('bad-passphrase'));
  const ct1MiB = { ...record, ct: b64(MiB) };
  await assert.rejects(unlock(ct1MiB, PASS), isVaultError('bad-passphrase'));
  await assert.rejects(open(rawKey, ct1MiB), isVaultError('corrupt'));
});

test('create and seal refuse data whose ciphertext would exceed 1 MiB', async () => {
  const { record, rawKey } = await create(PASS, DATA, FAST);
  const big = { accounts: [], pad: 'x'.repeat(MiB) };
  await assert.rejects(seal(rawKey, record, big), RangeError);
  await assert.rejects(create(PASS, big, FAST), RangeError);
  // Just under the limit seals and opens.
  const overhead = JSON.stringify({ accounts: [], pad: '' }).length + 16;
  const fits = { accounts: [], pad: 'x'.repeat(MiB - overhead) };
  assert.deepEqual(await open(rawKey, await seal(rawKey, record, fits)), fits);
});

test('create rejects iteration counts outside 1..2,000,000', async () => {
  await assert.rejects(create(PASS, DATA, { iterations: 2000001 }), isVaultError('unsupported'));
  await assert.rejects(create(PASS, DATA, { iterations: 0 }), isVaultError('corrupt'));
});

const CRED = Uint8Array.of(251, 255, 1);
const PRF = new Uint8Array(32).fill(3);
const PRF_SALT = new Uint8Array(32).fill(4);
const params = () => ({ cred: CRED, prfSalt: PRF_SALT, prf: PRF, label: 'Phone' });
const copy = (value) => JSON.parse(JSON.stringify(value));
async function enrolled() {
  const original = await create(PASS, DATA, FAST);
  const next = await vault.addPasskeySlot(original.record, PASS, params());
  return { ...next, original };
}

test('v1 migration produces independently unlockable v2 with fresh key and salt', async () => {
  const { record, rawKey, original } = await enrolled();
  assert.equal(record.v, 2);
  assert.notDeepEqual(rawKey, original.rawKey);
  assert.notEqual(record.slots[0].kdf.salt, original.record.kdf.salt);
  assert.equal(record.slots[0].kdf.iterations, original.record.kdf.iterations);
  assert.deepEqual(vault.identity(record), { v: 2, id: record.id });
  assert.deepEqual(vault.identity(original.record), { v: 1 });
  for (const result of [await unlock(copy(record), PASS), await vault.unlockWithPasskey(copy(record), PRF)]) {
    assert.deepEqual(result.data, DATA);
    assert.deepEqual(result.rawKey, rawKey);
  }
  const slot = vault.passkeySlot(record);
  assert.equal(slot.cred, '-_8B');
  assert.deepEqual(slot.credBytes, CRED);
  assert.deepEqual(slot.prfSalt, PRF_SALT);
  assert.equal(slot.label, 'Phone');
  assert.ok(Number.isInteger(slot.createdAt));
});

test('slot operations refuse incorrect credentials and preserve the live record', async () => {
  const { record, original } = await enrolled();
  const saved = copy(record);
  await assert.rejects(unlock(record, 'wrong'), isVaultError('bad-passphrase'));
  await assert.rejects(vault.unlockWithPasskey(record, new Uint8Array(32)), isVaultError('bad-passkey'));
  await assert.rejects(vault.unlockWithPasskey(record, new Uint8Array(31)), TypeError);
  await assert.rejects(vault.addPasskeySlot(original.record, 'wrong', params()), isVaultError('bad-passphrase'));
  await assert.rejects(vault.addPasskeySlot(record, PASS, params()), isVaultError('slot-exists'));
  assert.throws(() => vault.removePasskeySlot(record, 'not-cred'), isVaultError('no-passkey'));
  const removed = vault.removePasskeySlot(record, vault.passkeySlot(record).cred);
  assert.deepEqual(removed.slots, [record.slots[0]]);
  assert.deepEqual(removed.data, record.data);
  assert.equal(removed.id, record.id);
  assert.equal(vault.passkeySlot(removed), null);
  await assert.rejects(vault.unlockWithPasskey(removed, PRF), isVaultError('no-passkey'));
  const backup = vault.exportCopy(record);
  assert.deepEqual(backup, removed);
  backup.slots[0].kdf.iterations = 2;
  assert.deepEqual(record, saved);
  assert.deepEqual(vault.exportCopy(original.record), original.record);
  const added = await vault.addPasskeySlot(removed, PASS, params());
  assert.deepEqual(added.rawKey, (await unlock(removed, PASS)).rawKey);
});

test('v2 seal preserves slots and id, changes IV and canonical revision', async () => {
  const { record, rawKey, original } = await enrolled();
  const sealed = await seal(rawKey, record, { next: true });
  assert.deepEqual(sealed.slots, record.slots);
  assert.equal(sealed.id, record.id);
  assert.notEqual(sealed.data.iv, record.data.iv);
  assert.notEqual(await vault.revision(sealed), await vault.revision(record));
  assert.deepEqual((await unlock(sealed, PASS)).data, { next: true });
  assert.deepEqual((await vault.unlockWithPasskey(sealed, PRF)).data, { next: true });
  for (const r of [record, original.record]) {
    const reordered = JSON.parse(JSON.stringify(r, (key, value) => value && !Array.isArray(value) && typeof value === 'object'
      ? Object.fromEntries(Object.entries(value).reverse()) : value));
    assert.equal(await vault.revision(r), await vault.revision(reordered));
    assert.equal(await vault.revision(r), createHash('sha256').update(JSON.stringify(r)).digest('hex'));
  }
});

test('each v2 AAD field and ciphertext is authenticated', async () => {
  const { record, rawKey } = await enrolled();
  const mutate = (fn) => { const r = copy(record); fn(r); return r; };
  for (const fn of [
    (r) => { r.id = flipFirstByte(r.id); },
    (r) => { r.slots[0].kdf.iterations++; },
    (r) => { r.slots[0].kdf.salt = flipFirstByte(r.slots[0].kdf.salt); },
    (r) => { r.slots[0].iv = flipFirstByte(r.slots[0].iv); },
    (r) => { r.slots[0].wrapped = flipFirstByte(r.slots[0].wrapped); },
  ]) await assert.rejects(unlock(mutate(fn), PASS), isVaultError('bad-passphrase'));
  for (const fn of [
    (r) => { r.id = flipFirstByte(r.id); },
    (r) => { r.slots[1].cred = 'AQ'; },
    (r) => { r.slots[1].prfSalt = flipFirstByte(r.slots[1].prfSalt); },
    (r) => { r.slots[1].label += '!'; },
    (r) => { r.slots[1].createdAt++; },
    (r) => { r.slots[1].iv = flipFirstByte(r.slots[1].iv); },
    (r) => { r.slots[1].wrapped = flipFirstByte(r.slots[1].wrapped); },
  ]) await assert.rejects(vault.unlockWithPasskey(mutate(fn), PRF), isVaultError('bad-passkey'));
  for (const fn of [
    (r) => { r.id = flipFirstByte(r.id); },
    (r) => { r.data.iv = flipFirstByte(r.data.iv); },
    (r) => { r.data.ct = flipFirstByte(r.data.ct); },
  ]) await assert.rejects(open(rawKey, mutate(fn)), isVaultError('corrupt'));
});

test('v2 rejects unknown fields and structurally invalid AAD constants before KDF', async (t) => {
  const { record } = await enrolled();
  const calls = spyOnKdf(t);
  for (const change of [
    (r) => { r.extra = 1; }, (r) => { r.data.extra = 1; },
    (r) => { r.slots[0].extra = 1; }, (r) => { r.slots[0].kdf.extra = 1; },
    (r) => { r.slots[1].extra = 1; }, (r) => { r.slots[0].type = 'passkey'; },
    (r) => { r.slots[1].type = 'passphrase'; }, (r) => { r.slots[0].kdf.name = 'scrypt'; },
    (r) => { r.slots[0].kdf.hash = 'SHA-1'; }, (r) => { r.v = 3; },
  ]) {
    const bad = copy(record); change(bad);
    await assert.rejects(unlock(bad, PASS), VaultError);
  }
  assert.equal(calls(), 0);
});

test('v2 input bytes are snapshotted before asynchronous operations', async () => {
  const { record } = await create(PASS, DATA, FAST);
  const cred = Uint8Array.from(CRED);
  const prf = Uint8Array.from(PRF);
  const prfSalt = Uint8Array.from(PRF_SALT);
  const pending = vault.addPasskeySlot(record, PASS, { cred, prf, prfSalt, label: 'Phone' });
  cred.fill(0); prf.fill(0); prfSalt.fill(0);
  const next = await pending;
  assert.deepEqual(vault.passkeySlot(next.record).credBytes, CRED);
  assert.deepEqual(vault.passkeySlot(next.record).prfSalt, PRF_SALT);
  assert.deepEqual((await vault.unlockWithPasskey(next.record, PRF)).data, DATA);
});

test('v2 malformed records and bounds reject before any KDF', async (t) => {
  const { record } = await enrolled();
  const calls = spyOnKdf(t);
  const cases = [
    (r) => { r.id = b64(15); }, (r) => { r.data.iv = b64(13); },
    (r) => { r.data.ct = b64(15); }, (r) => { r.data.ct = b64(MiB + 1); },
    (r) => { r.slots = []; }, (r) => { r.slots = [r.slots[1]]; },
    (r) => { r.slots.push(copy(r.slots[0])); }, (r) => { r.slots.push(copy(r.slots[1])); },
    (r) => { r.slots[1].type = 'other'; }, (r) => { r.slots[0].kdf.salt = b64(15); },
    (r) => { r.slots[0].kdf.salt = b64(65); }, (r) => { r.slots[0].kdf.iterations = 0; },
    (r) => { r.slots[1].cred = ''; }, (r) => { r.slots[1].cred = 'AB'; },
    (r) => { r.slots[1].cred = 'AQ=='; }, (r) => { r.slots[1].cred = Buffer.alloc(1024).toString('base64url'); },
    (r) => { r.slots[1].prfSalt = b64(31); }, (r) => { r.slots[1].label = 'x'.repeat(65); },
    (r) => { r.slots[1].createdAt = 1.5; }, (r) => { r.slots[1].iv = b64(11); },
    (r) => { r.slots[1].wrapped = b64(47); },
  ];
  for (const change of cases) {
    const bad = copy(record); change(bad);
    await assert.rejects(unlock(bad, PASS), VaultError);
  }
  assert.equal(calls(), 0);
});
