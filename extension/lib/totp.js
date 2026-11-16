// HOTP (RFC 4226) and TOTP (RFC 6238) over WebCrypto HMAC.

import { decode as base32Decode } from './base32.js';

const HASHES = new Map([['SHA1', 'SHA-1'], ['SHA256', 'SHA-256'], ['SHA512', 'SHA-512']]);
const MAX_COUNTER = (1n << 64n) - 1n;

function hashFor(algorithm) {
  const hash = HASHES.get(algorithm);
  if (!hash) throw new Error(`Unsupported algorithm: ${algorithm}`);
  return hash;
}

function checkDigits(digits) {
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) {
    throw new RangeError(`Digits must be 6, 7 or 8 (got ${digits})`);
  }
}

function checkPeriod(period) {
  if (!Number.isInteger(period) || period < 1 || period > 300) {
    throw new RangeError(`Period must be an integer from 1 to 300 seconds (got ${period})`);
  }
}

function toCounter(counter) {
  const value = typeof counter === 'bigint' ? counter
    : Number.isSafeInteger(counter) ? BigInt(counter)
    : null;
  if (value === null || value < 0n || value > MAX_COUNTER) {
    throw new RangeError(`Counter must be an integer from 0 to 2^64-1 (got ${counter})`);
  }
  return value;
}

function counterSeconds(nowMs) {
  if (!Number.isFinite(nowMs) || nowMs < 0) {
    throw new RangeError(`Time must be a non-negative number of milliseconds (got ${nowMs})`);
  }
  return Math.floor(nowMs / 1000);
}

/**
 * RFC 4226 HOTP value for one counter.
 *
 * @param {Uint8Array} keyBytes shared secret, at least one byte
 * @param {number|bigint} counter 0..2^64-1, encoded as an 8-byte big-endian value
 * @param {{algorithm?: 'SHA1'|'SHA256'|'SHA512', digits?: number}} [options]
 * @returns {Promise<string>} zero-padded code of `digits` length
 */
export async function hotp(keyBytes, counter, { algorithm = 'SHA1', digits = 6 } = {}) {
  if (!(keyBytes instanceof Uint8Array) || keyBytes.length === 0) {
    throw new TypeError('HOTP key must be a non-empty Uint8Array');
  }
  const hash = hashFor(algorithm);
  checkDigits(digits);

  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, toCounter(counter), false);

  const key = await globalThis.crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash }, false, ['sign'],
  );
  const mac = new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, message));

  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24)
    | (mac[offset + 1] << 16)
    | (mac[offset + 2] << 8)
    | mac[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

/**
 * RFC 6238 TOTP code for an account at a point in time.
 *
 * @param {{secret: string, algorithm?: 'SHA1'|'SHA256'|'SHA512', digits?: number, period?: number}} account
 *   `secret` is base32; missing options default to SHA1 / 6 digits / 30 seconds.
 * @param {number} [nowMs] Unix time in milliseconds
 * @returns {Promise<string>}
 */
export async function totp(account, nowMs = Date.now()) {
  const { secret, algorithm = 'SHA1', digits = 6, period = 30 } = account;
  checkPeriod(period);
  const counter = Math.floor(counterSeconds(nowMs) / period);
  return hotp(base32Decode(secret), counter, { algorithm, digits });
}

/**
 * Whole seconds until the current code expires.
 *
 * Returns `period` (not 0) at the exact start of a step.
 *
 * @param {number} period step length in seconds, integer 1..300
 * @param {number} [nowMs] Unix time in milliseconds
 * @returns {number} integer in 1..period
 */
export function remainingSeconds(period, nowMs = Date.now()) {
  checkPeriod(period);
  return period - (counterSeconds(nowMs) % period);
}
