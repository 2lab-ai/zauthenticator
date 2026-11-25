// Google Authenticator "Transfer accounts" export: otpauth-migration://offline?data=<payload>, where
// the payload is a protobuf MigrationPayload in standard base64, percent-encoded. Google
// Authenticator on a phone (Transfer accounts → Import accounts) scans these QR codes directly.
//
// The format has no period and only 6 or 8 digits, so an account with another period or with 7
// digits cannot go into it; migrationIssue says which. Many accounts are split into batches, one
// QR code each, small enough to scan from a screen.
//
// Schema (proto3), with the field numbers written here:
//   MigrationPayload: 1 otp_parameters (repeated OtpParameters), 2 version, 3 batch_size,
//     4 batch_index (0-based), 5 batch_id (the same on every batch of one export); all int32.
//   OtpParameters: 1 secret (bytes), 2 name (string), 3 issuer (string), 4 algorithm (enum),
//     5 digits (enum), 6 type (enum), 7 counter (int64, HOTP only, never written).

import { decode as base32Decode } from './base32.js';
import { normalize } from './otpauth.js';

const PREFIX = 'otpauth-migration://offline?data=';
const VERSION = 1;
const ALGORITHM = { SHA1: 1, SHA256: 2, SHA512: 3 };
const DIGITS = { 6: 1, 8: 2 }; // DigitCount SIX, EIGHT
const TYPE_TOTP = 2;
const MAX_BATCH_ID = 0x7fffffff;

// ---- protobuf writer: only what this format needs -------------------------------------------
// A field starts with the key (field number << 3 | wire type): wire type 0 is a varint, 2 is a
// length-delimited value. All numbers written here are non-negative and below 2^31, so an int32
// or enum value is a plain varint.

function varint(out, n) {
  while (n > 0x7f) {
    out.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  out.push(n);
}

function intField(out, field, n) {
  varint(out, field << 3);
  varint(out, n);
}

function bytesField(out, field, bytes) {
  varint(out, (field << 3) | 2);
  varint(out, bytes.length);
  for (const b of bytes) out.push(b);
}

const utf8 = (s) => new TextEncoder().encode(s);

// ----------------------------------------------------------------------------------------------

function issueOf({ period, digits }) {
  if (period !== 30) return 'period';
  if (!Object.hasOwn(DIGITS, digits)) return 'digits';
  return null;
}

/**
 * Whether an account can go into a Google Authenticator export.
 *
 * @param {object} account any object `normalize` accepts
 * @returns {null|'period'|'digits'} null when it can; 'period' when the period is not 30 seconds,
 *   else 'digits' when it has 7 digits
 * @throws {Error} when `normalize` rejects the account
 */
export function migrationIssue(account) {
  return issueOf(normalize(account));
}

// The encoded OtpParameters message of a normalized account. Empty strings are left out, as
// proto3 does; name is the label, or the issuer when the label is empty.
function otpParameters(account) {
  const out = [];
  bytesField(out, 1, base32Decode(account.secret));
  const name = account.label || account.issuer;
  if (name) bytesField(out, 2, utf8(name));
  if (account.issuer) bytesField(out, 3, utf8(account.issuer));
  intField(out, 4, ALGORITHM[account.algorithm]);
  intField(out, 5, DIGITS[account.digits]);
  intField(out, 6, TYPE_TOTP);
  return out;
}

function batchUri(entries, size, index, id) {
  const out = [];
  for (const entry of entries) bytesField(out, 1, entry);
  intField(out, 2, VERSION);
  intField(out, 3, size);
  intField(out, 4, index); // written even when 0; a reader takes a missing field as 0 anyway
  intField(out, 5, id);
  let binary = '';
  for (const b of out) binary += String.fromCharCode(b);
  return PREFIX + encodeURIComponent(btoa(binary));
}

// Greedy packing in order: a batch takes the next account while its URI stays within maxChars and
// it has fewer than maxPerBatch accounts. Its first account always goes in, even when that URI
// alone is longer than maxChars. Every URI is written with batch_size = size.
function pack(entries, size, id, maxChars, maxPerBatch) {
  const batches = [];
  let start = 0;
  while (start < entries.length) {
    const index = batches.length;
    let end = start + 1;
    let uri = batchUri(entries.slice(start, end), size, index, id);
    while (end < entries.length && end - start < maxPerBatch) {
      const longer = batchUri(entries.slice(start, end + 1), size, index, id);
      if (longer.length > maxChars) break;
      uri = longer;
      end++;
    }
    batches.push({ uri, count: end - start, index, size });
    start = end;
  }
  return batches;
}

function randomBatchId() {
  let id = 0;
  while (id === 0) id = crypto.getRandomValues(new Uint32Array(1))[0] >>> 1;
  return id;
}

function positiveInteger(value, name, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isInteger(value) || value < 1 || value > max) {
    throw new TypeError(`${name} must be an integer from 1 to ${max}`);
  }
  return value;
}

/**
 * Split accounts into Google Authenticator export URIs, one per QR code.
 *
 * Accounts are packed in the given order, as many to a batch as fit in maxChars characters and
 * maxPerBatch accounts. An account whose URI alone is longer than maxChars gets a batch of its own.
 * Every batch carries version 1, the number of batches, its 0-based index and the same batch id.
 *
 * @param {object[]} accounts objects `normalize` accepts, none with a migrationIssue
 * @param {{batchId?: number, maxChars?: number, maxPerBatch?: number}} [options] batchId: 1 to
 *   2^31 - 1, random by default
 * @returns {{uri: string, count: number, index: number, size: number}[]} count accounts in this
 *   batch, index 0-based, size = number of batches
 * @throws {TypeError} on an empty list, an account with a migrationIssue, or a bad option;
 *   {Error} when `normalize` rejects an account
 */
export function migrationBatches(accounts, { batchId, maxChars = 700, maxPerBatch = 10 } = {}) {
  if (!Array.isArray(accounts) || accounts.length === 0) throw new TypeError('No accounts to export');
  positiveInteger(maxChars, 'maxChars');
  positiveInteger(maxPerBatch, 'maxPerBatch');
  const id = batchId === undefined ? randomBatchId() : positiveInteger(batchId, 'batchId', MAX_BATCH_ID);

  const entries = accounts.map((input, i) => {
    const account = normalize(input);
    const issue = issueOf(account);
    if (issue) throw new TypeError(`Account ${i + 1} cannot be exported to Google Authenticator (${issue})`);
    return otpParameters(account);
  });

  // Every batch states the number of batches, which is known only after packing, and those bytes
  // change each URI's length a little. So pack again with the count found until it stays the
  // same; this settles in a round or two. If it ever kept changing, one account per batch is
  // always consistent, so that is the fallback.
  let size = 1;
  for (let round = 0; round < 8; round++) {
    const batches = pack(entries, size, id, maxChars, maxPerBatch);
    if (batches.length === size) return batches;
    size = batches.length;
  }
  return pack(entries, entries.length, id, maxChars, 1);
}
