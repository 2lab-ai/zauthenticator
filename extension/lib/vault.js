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
 */
export class VaultError extends Error {
  /**
   * @param {'bad-passphrase'|'weak-passphrase'|'corrupt'|'unsupported'} code
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
export async function open(rawKey, record) {
  checkKey(rawKey);
  const result = await decrypt(rawKey, readRecord(record));
  if (!result) throw new VaultError('corrupt', 'Record does not decrypt with this key');
  return result.data;
}
