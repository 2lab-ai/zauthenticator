// Passphrase vault: PBKDF2-SHA-256 -> 256-bit key -> AES-256-GCM over JSON.
//
// Record (plain JSON, safe to store):
//   { v: 1, kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations, salt }, iv, ct }
// salt (16 bytes), iv (12 bytes) and ct (ciphertext || 16-byte tag) are standard base64.
// Key = PBKDF2(UTF-8(passphrase), salt, iterations, SHA-256, 32 bytes).
// Plaintext = UTF-8(JSON.stringify(data)).
// AES-GCM additional data = UTF-8 of
//   {"v":1,"kdf":{"name":"PBKDF2","hash":"SHA-256","iterations":<n>,"salt":"<b64>"}}
// (exactly this key order, no whitespace), so editing the header breaks decryption.

export const DEFAULT_ITERATIONS = 600000;

const VERSION = 1;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const KEY_BYTES = 32;
const TAG_BYTES = 16;
const MIN_PASSPHRASE_LENGTH = 8;
const MAX_ITERATIONS = 10000000;

const subtle = () => globalThis.crypto.subtle;
const utf8 = new TextEncoder();

/**
 * Error with a machine-readable `code`:
 * - 'bad-passphrase'  unlock(): the passphrase does not decrypt the record (wrong passphrase,
 *                     or ct/iv/header tampered; AES-GCM cannot tell these apart)
 * - 'weak-passphrase' create(): passphrase shorter than 8 characters
 * - 'corrupt'         malformed record or key; open() with a key that does not authenticate
 *                     the record (tampered ct/iv/header, or a key from another vault)
 * - 'unsupported'     unknown version, KDF, hash, or an iteration count above 10,000,000
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

function fromBase64(value, what) {
  if (typeof value !== 'string' || value === '') throw new VaultError('corrupt', `Missing ${what}`);
  let binary;
  try {
    binary = atob(value);
  } catch {
    throw new VaultError('corrupt', `Invalid base64 in ${what}`);
  }
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
  const salt = fromBase64(kdf.salt, 'kdf.salt');
  if (salt.length < SALT_BYTES) throw new VaultError('corrupt', 'Salt too short');

  const header = { name: 'PBKDF2', hash: 'SHA-256', iterations: kdf.iterations, salt: kdf.salt };
  const aad = utf8.encode(JSON.stringify({ v: VERSION, kdf: header }));
  return { header, salt, aad };
}

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
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = await subtle().encrypt(
    { name: 'AES-GCM', iv, additionalData: aad }, await aesKey(rawKey, 'encrypt'), utf8.encode(json),
  );
  return { v: VERSION, kdf: { ...header }, iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)) };
}

/** Returns the parsed data, or null when AES-GCM authentication fails. */
async function decrypt(rawKey, record, aad) {
  const iv = fromBase64(record.iv, 'iv');
  const ct = fromBase64(record.ct, 'ct');
  if (iv.length !== IV_BYTES) throw new VaultError('corrupt', `IV must be ${IV_BYTES} bytes`);
  if (ct.length < TAG_BYTES) throw new VaultError('corrupt', 'Ciphertext too short');

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
 * @param {string} passphrase at least 8 characters (else VaultError 'weak-passphrase')
 * @param {*} data JSON-serializable payload
 * @param {{iterations?: number}} [options] PBKDF2 iterations, default DEFAULT_ITERATIONS
 * @returns {Promise<{record: object, rawKey: Uint8Array}>}
 */
export async function create(passphrase, data, { iterations = DEFAULT_ITERATIONS } = {}) {
  if (typeof passphrase !== 'string' || [...passphrase].length < MIN_PASSPHRASE_LENGTH) {
    throw new VaultError('weak-passphrase', `Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
  }
  checkIterations(iterations);
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const { header, aad } = readHeader({
    v: VERSION,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: toBase64(salt) },
  });
  const rawKey = await deriveKey(passphrase, salt, iterations);
  return { record: await encrypt(rawKey, header, aad, data), rawKey };
}

/**
 * Derive the key from a passphrase and decrypt the record.
 *
 * @param {object} record
 * @param {string} passphrase
 * @returns {Promise<{data: *, rawKey: Uint8Array}>}
 * @throws {VaultError} 'bad-passphrase' when decryption fails; 'corrupt'/'unsupported' for bad records
 */
export async function unlock(record, passphrase) {
  const { header, salt, aad } = readHeader(record);
  if (typeof passphrase !== 'string' || passphrase === '') {
    throw new VaultError('bad-passphrase', 'Wrong passphrase');
  }
  const rawKey = await deriveKey(passphrase, salt, header.iterations);
  const result = await decrypt(rawKey, record, aad);
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
 * @param {*} data JSON-serializable payload
 * @returns {Promise<object>} new record with a fresh 12-byte IV
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
  const { aad } = readHeader(record);
  const result = await decrypt(rawKey, record, aad);
  if (!result) throw new VaultError('corrupt', 'Record does not decrypt with this key');
  return result.data;
}
