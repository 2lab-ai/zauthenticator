// Independent reference implementations for the e2e tests, on node:crypto only:
// extension/lib is deliberately not imported, so a bug there cannot hide in the check.
//   base32ToBytes   RFC 4648 base32
//   referenceTotp   RFC 4226/6238 HOTP/TOTP
//   decryptRecord   the vault record format of the extension/lib/vault.js header comment (v1, v2)
//   openDataWithDek the v2 payload under a given data key (no slot involved)
//   encryptRecordV2 a v2 record with a passphrase slot and a passkey slot, for import fixtures

import { createCipheriv, createDecipheriv, createHmac, hkdfSync, pbkdf2, pbkdf2Sync, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';

export function base32ToBytes(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const out = [];
  let bits = 0;
  let value = 0;
  for (const ch of input.replace(/=+$/, '').toUpperCase()) {
    const index = alphabet.indexOf(ch);
    if (index < 0) throw new Error(`bad base32 character ${ch}`);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
      value &= (1 << bits) - 1;
    }
  }
  return Buffer.from(out);
}

export function referenceTotp(key, nowMs, { algorithm, digits, period }) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(nowMs / 1000 / period)));
  const mac = createHmac(algorithm, key).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

const pbkdf2Async = promisify(pbkdf2);
const GCM_TAG_BYTES = 16;
// Derived keys by passphrase, salt and iterations: a vault keeps its KDF parameters across
// seals, so a test that opens the stored record again and again derives its key once.
const derivedKeys = new Map();

function deriveKey(passphrase, salt, iterations) {
  const id = JSON.stringify([passphrase, salt, iterations]);
  if (!derivedKeys.has(id)) {
    derivedKeys.set(id, pbkdf2Async(Buffer.from(passphrase.normalize('NFC'), 'utf8'), Buffer.from(salt, 'base64'), iterations, 32, 'sha256'));
  }
  return derivedKeys.get(id);
}

// Key = PBKDF2-SHA-256(UTF-8(NFC(passphrase)), salt, iterations, 32 bytes); AES-256-GCM with the
// 12-byte iv; additional data = the header JSON in exactly the documented key order; ct ends
// with the 16-byte tag. → the decrypted data object; throws when the record does not open.
function decryptGcm(key, iv, ct, aad) {
  const sealed = Buffer.from(ct, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
  decipher.setAAD(Buffer.from(JSON.stringify(aad), 'utf8'));
  decipher.setAuthTag(sealed.subarray(sealed.length - GCM_TAG_BYTES));
  return Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - GCM_TAG_BYTES)), decipher.final()]);
}

function encryptGcm(key, aad, plain) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(JSON.stringify(aad), 'utf8'));
  const ct = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  return { iv: iv.toString('base64'), ct: ct.toString('base64') };
}

const PASSKEY_KEK_INFO = Buffer.from('zauthenticator vault v2 passkey kek');

// Independently unwraps the selected v2 slot and authenticates both the slot and data AAD.
// The optional PRF is the authenticator's actual output, not a substitute for WebAuthn.
export async function decryptRecord(record, passphrase, prf = null) {
  const { v } = record ?? {};
  if (v === 2) {
    const slot = record.slots.find((s) => s.type === (prf ? 'passkey' : 'passphrase'));
    if (!slot) throw new Error('missing slot');
    let key;
    let aad;
    if (prf) {
      if (prf.length !== 32) throw new Error('invalid PRF');
      key = Buffer.from(hkdfSync('sha256', prf, Buffer.alloc(0), PASSKEY_KEK_INFO, 32));
      aad = { v: 2, id: record.id, type: 'passkey', cred: slot.cred, prfSalt: slot.prfSalt, label: slot.label, createdAt: slot.createdAt };
    } else {
      const { name, hash, iterations, salt } = slot.kdf;
      if (name !== 'PBKDF2' || hash !== 'SHA-256') throw new Error('invalid KDF');
      key = await deriveKey(passphrase, salt, iterations);
      aad = { v: 2, id: record.id, type: 'passphrase', kdf: { name, hash, iterations, salt } };
    }
    const dek = decryptGcm(key, slot.iv, slot.wrapped, aad);
    return JSON.parse(decryptGcm(dek, record.data.iv, record.data.ct, { v: 2, id: record.id }).toString('utf8'));
  }
  const { kdf, iv, ct } = record ?? {};
  if (v !== 1 || kdf?.name !== 'PBKDF2' || kdf?.hash !== 'SHA-256' || !Number.isInteger(kdf?.iterations) || typeof kdf?.salt !== 'string') {
    throw new Error(`not a v1 PBKDF2/SHA-256 record: ${JSON.stringify({ v, kdf })}`);
  }
  const key = await deriveKey(passphrase, kdf.salt, kdf.iterations);
  return JSON.parse(decryptGcm(key, iv, ct, { v: 1, kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: kdf.iterations, salt: kdf.salt } }).toString('utf8'));
}

// The v2 payload opened with `dek` alone: data AAD {"v":2,"id":<id>}. Throws when `dek` is not
// the record's data key.
export function openDataWithDek(record, dek) {
  return JSON.parse(decryptGcm(dek, record.data.iv, record.data.ct, { v: 2, id: record.id }).toString('utf8'));
}

// A v2 record of its own (fresh id, data key, salts and passkey slot) holding `data`: the
// passphrase slot wraps the data key under PBKDF2-SHA-256(passphrase), the passkey slot under
// HKDF-SHA-256(`prf`), each with its canonical slot AAD. Built from the format, not from
// extension/lib. → { record, prf, dek }
export function encryptRecordV2(data, passphrase, { iterations = 1000, prf = randomBytes(32), label = 'Other device', createdAt = Date.now() } = {}) {
  const id = randomBytes(16).toString('base64');
  const dek = randomBytes(32);
  const kdf = { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: randomBytes(16).toString('base64') };
  const kek = pbkdf2Sync(Buffer.from(passphrase.normalize('NFC'), 'utf8'), Buffer.from(kdf.salt, 'base64'), iterations, 32, 'sha256');
  const wrappedByPassphrase = encryptGcm(kek, { v: 2, id, type: 'passphrase', kdf }, dek);
  const passkey = { type: 'passkey', cred: randomBytes(16).toString('base64url'), prfSalt: randomBytes(32).toString('base64'), label, createdAt };
  const prfKek = Buffer.from(hkdfSync('sha256', prf, Buffer.alloc(0), PASSKEY_KEK_INFO, 32));
  const wrappedByPasskey = encryptGcm(prfKek, { v: 2, id, ...passkey }, dek);
  const sealed = encryptGcm(dek, { v: 2, id }, Buffer.from(JSON.stringify(data), 'utf8'));
  const record = {
    v: 2,
    id,
    data: { iv: sealed.iv, ct: sealed.ct },
    slots: [
      { type: 'passphrase', kdf, iv: wrappedByPassphrase.iv, wrapped: wrappedByPassphrase.ct },
      { ...passkey, iv: wrappedByPasskey.iv, wrapped: wrappedByPasskey.ct },
    ],
  };
  return { record, prf, dek };
}
