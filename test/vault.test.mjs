import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_ITERATIONS, VaultError, create, unlock, seal, open } from '../extension/lib/vault.js';

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
    'version 2': { ...record, v: 2 },
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
