// Passphrase vault: PBKDF2-SHA-256 -> 256-bit key -> AES-256-GCM over JSON.
//
// Record (plain JSON, safe to store):
//   { v: 1, kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations, salt }, iv, ct }
// salt (16 bytes), iv (12 bytes) and ct (ciphertext || 16-byte tag) are standard base64.
// Key = PBKDF2(UTF-8(NFC(passphrase)), salt, iterations, SHA-256, 32 bytes). The passphrase is
// Unicode NFC-normalized first (in create() and unlock()), so composed and decomposed input of
// the same text, which keyboards and platforms produce differently, opens the same vault.
// Normalization was added before the first release, so no vault keyed on the raw string exists.
// Plaintext = UTF-8(JSON.stringify(data)).
// AES-GCM additional data = UTF-8 of
//   {"v":1,"kdf":{"name":"PBKDF2","hash":"SHA-256","iterations":<n>,"salt":"<b64>"}}
// (exactly this key order, no whitespace), so editing the header breaks decryption.
//
// v2 keeps the payload under a random DEK and wraps it in passphrase and optional passkey slots.
// Each slot and the payload authenticate their canonical v2 metadata as AES-GCM additional data.
//
// Records are checked for shape before any key is derived, so a hostile or damaged record
// (for example an imported backup) cannot make unlock() run PBKDF2 or decode huge strings:
// salt 16..64 bytes, iv exactly 12 bytes, ct 16 bytes..1 MiB, iterations 1..2,000,000.
// create() and seal() refuse data whose ct would exceed 1 MiB, so they never write a record
// that unlock() and open() would reject.

/** PBKDF2-SHA-256 iteration count used by create() when none is given. */
export const DEFAULT_ITERATIONS = 600000;

const VERSION = 1;
const SALT_BYTES = 16;
const MAX_SALT_BYTES = 64;
const IV_BYTES = 12;
const KEY_BYTES = 32;
const TAG_BYTES = 16;
const MAX_CT_BYTES = 1024 * 1024;
const MIN_PASSPHRASE_LENGTH = 8;
const MAX_ITERATIONS = 2000000;

const subtle = () => globalThis.crypto.subtle;
const utf8 = new TextEncoder();

/**
 * Error with a machine-readable `code`:
 * - 'bad-passphrase'  unlock(): the passphrase does not decrypt the record (wrong passphrase,
 *                     or ct/iv/header tampered; AES-GCM cannot tell these apart)
 * - 'weak-passphrase' create(): passphrase shorter than 8 characters
 * - 'corrupt'         malformed record or key; open() with a key that does not authenticate
 *                     the record (tampered ct/iv/header, or a key from another vault)
 * - 'unsupported'     unknown version, KDF, hash, or an iteration count above 2,000,000
 * - 'bad-passkey'     passkey slot does not authenticate with the PRF
 * - 'no-passkey'      no matching passkey slot
 * - 'slot-exists'     a passkey is already enrolled
 */
export class VaultError extends Error {
  /**
   * @param {'bad-passphrase'|'weak-passphrase'|'corrupt'|'unsupported'|'bad-passkey'|'no-passkey'|'slot-exists'} code
   * @param {string} message
   */
  constructor(code, message) {
    super(message);
    this.name = 'VaultError';
    this.code = code;
  }
}

function toBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

// Standard base64 of at most maxBytes bytes is at most this many characters.
const base64Length = (maxBytes) => Math.ceil(maxBytes / 3) * 4;

function fromBase64(value, what, minBytes, maxBytes) {
  if (typeof value !== 'string' || value === '') throw new VaultError('corrupt', `Missing ${what}`);
  if (value.length > base64Length(maxBytes)) throw new VaultError('corrupt', `${what} is too long`);
  let binary;
  try {
    binary = atob(value);
  } catch {
    throw new VaultError('corrupt', `Invalid base64 in ${what}`);
  }
  if (binary.length < minBytes) throw new VaultError('corrupt', `${what} is too short`);
  if (binary.length > maxBytes) throw new VaultError('corrupt', `${what} is too long`);
  return Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
}

function checkIterations(iterations) {
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new VaultError('corrupt', `Invalid iteration count: ${iterations}`);
  }
  if (iterations > MAX_ITERATIONS) {
    throw new VaultError('unsupported', `Iteration count above ${MAX_ITERATIONS}: ${iterations}`);
  }
}

function checkKey(rawKey) {
  if (!(rawKey instanceof Uint8Array) || rawKey.length !== KEY_BYTES) {
    throw new VaultError('corrupt', `Key must be a ${KEY_BYTES}-byte Uint8Array`);
  }
}

/** Validates the record header and returns its decoded parts plus the canonical AAD. */
function readHeader(record) {
  if (record == null || typeof record !== 'object') throw new VaultError('corrupt', 'Record is not an object');
  if (record.v !== VERSION) {
    if (typeof record.v === 'number') throw new VaultError('unsupported', `Unsupported vault version ${record.v}`);
    throw new VaultError('corrupt', 'Missing vault version');
  }
  const { kdf } = record;
  if (kdf == null || typeof kdf !== 'object') throw new VaultError('corrupt', 'Missing kdf');
  if (kdf.name !== 'PBKDF2' || kdf.hash !== 'SHA-256') {
    throw new VaultError('unsupported', `Unsupported KDF ${kdf.name}/${kdf.hash}`);
  }
  checkIterations(kdf.iterations);
  const salt = fromBase64(kdf.salt, 'kdf.salt', SALT_BYTES, MAX_SALT_BYTES);

  const header = { name: 'PBKDF2', hash: 'SHA-256', iterations: kdf.iterations, salt: kdf.salt };
  const aad = utf8.encode(JSON.stringify({ v: VERSION, kdf: header }));
  return { header, salt, aad };
}

/** Validates the whole record (header, iv, ct) without any key: run before deriving one. */
function readRecord(record) {
  if (record?.v === 2) return readV2(record);
  const parts = readHeader(record);
  const iv = fromBase64(record.iv, 'iv', IV_BYTES, IV_BYTES);
  const ct = fromBase64(record.ct, 'ct', TAG_BYTES, MAX_CT_BYTES);
  return { ...parts, iv, ct };
}

// passphrase is already NFC-normalized.
async function deriveKey(passphrase, salt, iterations) {
  const base = await subtle().importKey('raw', utf8.encode(passphrase), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle().deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, KEY_BYTES * 8,
  );
  return new Uint8Array(bits);
}

function aesKey(rawKey, usage) {
  return subtle().importKey('raw', rawKey, 'AES-GCM', false, [usage]);
}

async function encrypt(rawKey, header, aad, data) {
  const json = JSON.stringify(data);
  if (typeof json !== 'string') throw new TypeError('Vault data must be JSON-serializable');
  const plain = utf8.encode(json);
  if (plain.length + TAG_BYTES > MAX_CT_BYTES) {
    throw new RangeError(`Vault data must be at most ${MAX_CT_BYTES - TAG_BYTES} bytes as JSON`);
  }
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = await subtle().encrypt(
    { name: 'AES-GCM', iv, additionalData: aad }, await aesKey(rawKey, 'encrypt'), plain,
  );
  return { v: VERSION, kdf: { ...header }, iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)) };
}

/** Returns the parsed data, or null when AES-GCM authentication fails. */
async function decrypt(rawKey, { iv, ct, aad }) {
  let plain;
  try {
    plain = await subtle().decrypt(
      { name: 'AES-GCM', iv, additionalData: aad }, await aesKey(rawKey, 'decrypt'), ct,
    );
  } catch {
    return null;
  }
  try {
    return { data: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plain)) };
  } catch {
    throw new VaultError('corrupt', 'Decrypted payload is not valid JSON');
  }
}

/**
 * Create a new vault sealed under a passphrase.
 *
 * @param {string} passphrase at least 8 characters after NFC normalization (else VaultError
 *   'weak-passphrase')
 * @param {*} data JSON-serializable payload, at most 1 MiB - 16 bytes as UTF-8 JSON
 * @param {{iterations?: number}} [options] PBKDF2 iterations 1..2,000,000, default DEFAULT_ITERATIONS
 * @returns {Promise<{record: object, rawKey: Uint8Array}>}
 * @throws {TypeError|RangeError} data that is not JSON-serializable or too large
 */
export async function create(passphrase, data, { iterations = DEFAULT_ITERATIONS } = {}) {
  const normalized = typeof passphrase === 'string' ? passphrase.normalize('NFC') : '';
  if ([...normalized].length < MIN_PASSPHRASE_LENGTH) {
    throw new VaultError('weak-passphrase', `Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
  }
  checkIterations(iterations);
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const { header, aad } = readHeader({
    v: VERSION,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: toBase64(salt) },
  });
  const rawKey = await deriveKey(normalized, salt, iterations);
  return { record: await encrypt(rawKey, header, aad, data), rawKey };
}

/**
 * Derive the key from a passphrase and decrypt the record.
 *
 * The record is fully checked (see the header comment) before the key is derived.
 *
 * @param {object} record
 * @param {string} passphrase NFC-normalized before use
 * @returns {Promise<{data: *, rawKey: Uint8Array}>}
 * @throws {VaultError} 'bad-passphrase' when decryption fails; 'corrupt'/'unsupported' for bad records
 */
export async function unlock(record, passphrase) {
  const parts = readRecord(record);
  if (typeof passphrase !== 'string' || passphrase === '') {
    throw new VaultError('bad-passphrase', 'Wrong passphrase');
  }
  if (record.v === 2) {
    const rawKey = await unwrapPassphrase(record, parts, passphrase);
    const data = await openRecord(rawKey, record);
    return { data, rawKey };
  }
  const rawKey = await deriveKey(passphrase.normalize('NFC'), parts.salt, parts.header.iterations);
  const result = await decrypt(rawKey, parts);
  if (!result) throw new VaultError('bad-passphrase', 'Wrong passphrase');
  return { data: result.data, rawKey };
}

/**
 * Encrypt new data under an already-derived key, keeping the record's KDF parameters.
 *
 * The caller is trusted to pass the key that belongs to `record`; it is not re-verified.
 *
 * @param {Uint8Array} rawKey 32-byte key from create() or unlock()
 * @param {object} record existing record (its v/kdf are reused)
 * @param {*} data JSON-serializable payload, at most 1 MiB - 16 bytes as UTF-8 JSON
 * @returns {Promise<object>} new record with a fresh 12-byte IV
 * @throws {TypeError|RangeError} data that is not JSON-serializable or too large
 */
export async function seal(rawKey, record, data) {
  checkKey(rawKey);
  if (record?.v === 2) {
    const parts = readRecord(record);
    const encrypted = await encrypt(rawKey, null, parts.aad, data);
    return { v: 2, id: record.id, data: { iv: encrypted.iv, ct: encrypted.ct }, slots: clone(record.slots) };
  }
  const { header, aad } = readHeader(record);
  return encrypt(rawKey, header, aad, data);
}

/**
 * Decrypt a record with an already-derived key.
 *
 * @param {Uint8Array} rawKey 32-byte key from create() or unlock()
 * @param {object} record
 * @returns {Promise<*>} the data
 * @throws {VaultError} 'corrupt' when the key does not authenticate the record (tampered
 *   ct/iv/header, or a key from another vault) or the record is malformed
 */
async function openRecord(rawKey, record) {
  checkKey(rawKey);
  const result = await decrypt(rawKey, readRecord(record));
  if (!result) throw new VaultError('corrupt', 'Record does not decrypt with this key');
  return result.data;
}

export { openRecord as open };

const clone = (value) => JSON.parse(JSON.stringify(value));
const random = (length) => globalThis.crypto.getRandomValues(new Uint8Array(length));
const toBase64Url = (bytes) => toBase64(bytes).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');

function fromBase64Url(value, what, min, max) {
  if (typeof value !== 'string' || value.length > Math.ceil(max * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new VaultError('corrupt', `Invalid ${what}`);
  }
  const decoded = fromBase64(value.replaceAll('-', '+').replaceAll('_', '/'), what, min, max);
  if (toBase64Url(decoded) !== value) throw new VaultError('corrupt', `Noncanonical ${what}`);
  return decoded;
}

function fields(value, keys, what) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) {
    throw new VaultError('corrupt', `Invalid ${what}`);
  }
}

function v2Base64(value, what, min, max) {
  const bytes = fromBase64(value, what, min, max);
  if (toBase64(bytes) !== value) throw new VaultError('corrupt', `Noncanonical ${what}`);
  return bytes;
}

function readV2(record) {
  fields(record, ['v', 'id', 'data', 'slots'], 'record');
  v2Base64(record.id, 'id', 16, 16);
  fields(record.data, ['iv', 'ct'], 'data');
  const iv = v2Base64(record.data.iv, 'data.iv', IV_BYTES, IV_BYTES);
  const ct = v2Base64(record.data.ct, 'data.ct', TAG_BYTES, MAX_CT_BYTES);
  if (!Array.isArray(record.slots) || record.slots.length < 1 || record.slots.length > 2) {
    throw new VaultError('corrupt', 'Invalid slots');
  }
  const p = record.slots[0];
  fields(p, ['type', 'kdf', 'iv', 'wrapped'], 'passphrase slot');
  if (p.type !== 'passphrase') throw new VaultError('corrupt', 'Missing passphrase slot');
  fields(p.kdf, ['name', 'hash', 'iterations', 'salt'], 'kdf');
  if (p.kdf.name !== 'PBKDF2' || p.kdf.hash !== 'SHA-256') throw new VaultError('unsupported', 'Unsupported KDF');
  checkIterations(p.kdf.iterations);
  const salt = v2Base64(p.kdf.salt, 'kdf.salt', SALT_BYTES, MAX_SALT_BYTES);
  const kdf = { name: p.kdf.name, hash: p.kdf.hash, iterations: p.kdf.iterations, salt: p.kdf.salt };
  const passphrase = { type: 'passphrase', kdf, iv: p.iv, wrapped: p.wrapped };
  v2Base64(p.iv, 'slot.iv', IV_BYTES, IV_BYTES);
  v2Base64(p.wrapped, 'slot.wrapped', 48, 48);
  const slots = [passphrase];
  let credBytes, prfSalt;
  if (record.slots.length === 2) {
    const s = record.slots[1];
    fields(s, ['type', 'cred', 'prfSalt', 'label', 'createdAt', 'iv', 'wrapped'], 'passkey slot');
    if (s.type !== 'passkey') throw new VaultError('corrupt', 'Invalid slot type');
    credBytes = fromBase64Url(s.cred, 'cred', 1, 1023);
    prfSalt = v2Base64(s.prfSalt, 'prfSalt', 32, 32);
    if (typeof s.label !== 'string' || s.label.length > 64 || !Number.isInteger(s.createdAt)) {
      throw new VaultError('corrupt', 'Invalid passkey metadata');
    }
    v2Base64(s.iv, 'slot.iv', IV_BYTES, IV_BYTES);
    v2Base64(s.wrapped, 'slot.wrapped', 48, 48);
    slots.push({ type: 'passkey', cred: s.cred, prfSalt: s.prfSalt, label: s.label,
      createdAt: s.createdAt, iv: s.iv, wrapped: s.wrapped });
  }
  return { iv, ct, salt, credBytes, prfSalt, slots,
    aad: utf8.encode(JSON.stringify({ v: 2, id: record.id })),
    canonical: { v: 2, id: record.id, data: { iv: record.data.iv, ct: record.data.ct }, slots } };
}

function slotAAD(id, slot) {
  if (slot.type === 'passphrase') {
    return utf8.encode(JSON.stringify({ v: 2, id, type: slot.type, kdf: slot.kdf }));
  }
  return utf8.encode(JSON.stringify({ v: 2, id, type: slot.type, cred: slot.cred,
    prfSalt: slot.prfSalt, label: slot.label, createdAt: slot.createdAt }));
}

async function wrap(key, id, slot, rawKey) {
  const iv = random(IV_BYTES);
  const wrapped = await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: slotAAD(id, slot) },
    await aesKey(key, 'encrypt'), rawKey);
  return { ...slot, iv: toBase64(iv), wrapped: toBase64(new Uint8Array(wrapped)) };
}

async function unwrap(key, id, slot, error) {
  try {
    const raw = await subtle().decrypt({ name: 'AES-GCM', iv: fromBase64(slot.iv, 'iv', 12, 12),
      additionalData: slotAAD(id, slot) }, await aesKey(key, 'decrypt'),
    fromBase64(slot.wrapped, 'wrapped', 48, 48));
    return new Uint8Array(raw);
  } catch {
    throw new VaultError(error, 'Slot does not decrypt');
  }
}

async function unwrapPassphrase(record, parts, passphrase) {
  const slot = parts.slots[0];
  const key = await deriveKey(passphrase.normalize('NFC'), parts.salt, slot.kdf.iterations);
  return unwrap(key, record.id, slot, 'bad-passphrase');
}

function checkPrf(prf) {
  if (!(prf instanceof Uint8Array) || prf.length !== 32) throw new TypeError('PRF must be a 32-byte Uint8Array');
}

async function prfKey(prf) {
  const key = await subtle().importKey('raw', prf, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle().deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(),
    info: utf8.encode('zauthenticator vault v2 passkey kek') }, key, 256));
}

export function identity(record) {
  readRecord(record);
  return record.v === 2 ? { v: 2, id: record.id } : { v: 1 };
}

export async function revision(record) {
  const parts = readRecord(record);
  const canonical = record.v === 2 ? parts.canonical
    : { v: 1, kdf: parts.header, iv: record.iv, ct: record.ct };
  const digest = new Uint8Array(await subtle().digest('SHA-256', utf8.encode(JSON.stringify(canonical))));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function passkeySlot(record) {
  const parts = readRecord(record);
  if (record.v === 1 || parts.slots.length === 1) return null;
  const { cred, label, createdAt } = parts.slots[1];
  return { cred, credBytes: parts.credBytes, prfSalt: parts.prfSalt, label, createdAt };
}

export async function unlockWithPasskey(record, prf) {
  const parts = readRecord(record);
  checkPrf(prf);
  if (record.v === 1 || parts.slots.length === 1) throw new VaultError('no-passkey', 'No passkey slot');
  const rawKey = await unwrap(await prfKey(prf), record.id, parts.slots[1], 'bad-passkey');
  return { data: await openRecord(rawKey, record), rawKey };
}

export function removePasskeySlot(record, cred) {
  const parts = readRecord(record);
  if (record.v === 1 || parts.slots.length === 1 || parts.slots[1].cred !== cred) {
    throw new VaultError('no-passkey', 'No matching passkey slot');
  }
  const result = clone(parts.canonical);
  result.slots.pop();
  return result;
}

export function exportCopy(record) {
  const parts = readRecord(record);
  if (record.v === 1) return clone(record);
  const result = clone(parts.canonical);
  result.slots.length = 1;
  return result;
}

export async function addPasskeySlot(record, passphrase, { cred, prfSalt, prf, label }) {
  readRecord(record);
  record = clone(record);
  if (!(cred instanceof Uint8Array) || cred.length < 1 || cred.length > 1023) throw new TypeError('Invalid credential');
  if (!(prfSalt instanceof Uint8Array) || prfSalt.length !== 32) throw new TypeError('Invalid PRF salt');
  checkPrf(prf);
  if (typeof label !== 'string' || label.length > 64) throw new TypeError('Invalid label');
  cred = Uint8Array.from(cred);
  prfSalt = Uint8Array.from(prfSalt);
  prf = Uint8Array.from(prf);
  if (passkeySlot(record)) throw new VaultError('slot-exists', 'Passkey slot already exists');
  const source = await unlock(record, passphrase);
  let rawKey = source.rawKey;
  let next;
  if (record.v === 1) {
    rawKey = random(KEY_BYTES);
    const id = toBase64(random(16));
    const salt = random(SALT_BYTES);
    const kdf = { name: 'PBKDF2', hash: 'SHA-256', iterations: record.kdf.iterations, salt: toBase64(salt) };
    const kek = await deriveKey(passphrase.normalize('NFC'), salt, kdf.iterations);
    const slot = await wrap(kek, id, { type: 'passphrase', kdf }, rawKey);
    const encrypted = await encrypt(rawKey, null, utf8.encode(JSON.stringify({ v: 2, id })), source.data);
    next = { v: 2, id, data: { iv: encrypted.iv, ct: encrypted.ct }, slots: [slot] };
  } else {
    next = clone(record);
  }
  const passkey = { type: 'passkey', cred: toBase64Url(cred), prfSalt: toBase64(prfSalt), label, createdAt: Date.now() };
  next.slots.push(await wrap(await prfKey(prf), next.id, passkey, rawKey));
  next = clone(next);
  const fromPassphrase = await unlock(next, passphrase);
  const fromPasskey = await unlockWithPasskey(next, prf);
  if (toBase64(fromPassphrase.rawKey) !== toBase64(rawKey) || toBase64(fromPasskey.rawKey) !== toBase64(rawKey)
      || JSON.stringify(fromPassphrase.data) !== JSON.stringify(source.data)) {
    throw new VaultError('corrupt', 'Slot verification failed');
  }
  return { record: next, rawKey };
}
