// otpauth:// key URIs (the Google Authenticator "Key Uri Format"), TOTP only.

import { decode as base32Decode, encode as base32Encode } from './base32.js';

const DEFAULTS = { algorithm: 'SHA1', digits: 6, period: 30 };
const ALGORITHMS = new Set(['SHA1', 'SHA256', 'SHA512']);
const URI_PATTERN = /^otpauth:\/\/([^/?#]*)\/?([^?#]*)(?:\?([^#]*))?(?:#.*)?$/i;

/**
 * @typedef {object} Account
 * @property {string} issuer   may be empty
 * @property {string} label    account name, may be empty
 * @property {string} secret   uppercase base32, no spaces or padding
 * @property {'SHA1'|'SHA256'|'SHA512'} algorithm
 * @property {number} digits   6..8
 * @property {number} period   seconds, 1..300
 */

function text(value) {
  return value == null ? '' : String(value).trim();
}

function normalizeSecret(value) {
  const raw = text(value);
  if (raw === '') throw new Error('Missing secret');
  let bytes;
  try {
    bytes = base32Decode(raw);
  } catch (err) {
    throw new Error(`Invalid secret (${err.message})`);
  }
  return base32Encode(bytes);
}

function normalizeAlgorithm(value) {
  const raw = text(value);
  if (raw === '') return DEFAULTS.algorithm;
  const algorithm = raw.toUpperCase().replace('-', '');
  if (!ALGORITHMS.has(algorithm)) throw new Error(`Unsupported algorithm: ${raw}`);
  return algorithm;
}

function integerParam(value, name, min, max, fallback) {
  if (value == null || text(value) === '') return fallback;
  const raw = text(value);
  const n = typeof value === 'number' ? value : /^\d+$/.test(raw) ? Number(raw) : NaN;
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`Invalid ${name}: ${raw} (expected an integer from ${min} to ${max})`);
  }
  return n;
}

function decodeComponent(value, what) {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new Error(`Malformed percent-encoding in ${what}`);
  }
}

/**
 * Validate and canonicalize an account, e.g. from manual entry.
 *
 * Strings are trimmed; `digits` and `period` may be numbers or decimal strings; missing
 * algorithm/digits/period default to SHA1/6/30; algorithm names are case-insensitive and may
 * contain one hyphen ('sha-256'). Other properties are dropped.
 *
 * @param {{issuer?: string, label?: string, secret: string, algorithm?: string,
 *   digits?: number|string, period?: number|string}} input
 * @returns {Account}
 * @throws {Error} on a missing or invalid secret, or an unsupported algorithm/digits/period
 */
export function normalize(input) {
  if (input == null || typeof input !== 'object') throw new TypeError('Account must be an object');
  return {
    issuer: text(input.issuer),
    label: text(input.label),
    secret: normalizeSecret(input.secret),
    algorithm: normalizeAlgorithm(input.algorithm),
    digits: integerParam(input.digits, 'digits', 6, 8, DEFAULTS.digits),
    period: integerParam(input.period, 'period', 1, 300, DEFAULTS.period),
  };
}

function splitLabel(path, issuerParam) {
  const decoded = decodeComponent(path, 'label');
  if (issuerParam && decoded.startsWith(`${issuerParam}:`)) {
    return { prefix: issuerParam, label: decoded.slice(issuerParam.length + 1) };
  }
  const colon = decoded.indexOf(':');
  if (colon === -1) return { prefix: '', label: decoded };
  return { prefix: decoded.slice(0, colon), label: decoded.slice(colon + 1) };
}

// Parameters that set a field; a second copy is an error rather than silently ignored.
const SINGLE_PARAMS = new Set(['secret', 'issuer', 'algorithm', 'digits', 'period']);

// application/x-www-form-urlencoded, like URLSearchParams ('+' is a space), except that
// malformed percent-encoding is an error instead of being kept literally or replaced.
function parseQuery(query) {
  const params = new Map();
  for (const pair of query.split('&')) {
    if (pair === '') continue;
    const eq = pair.indexOf('=');
    const name = decodeComponent((eq === -1 ? pair : pair.slice(0, eq)).replaceAll('+', ' '), 'query');
    const value = decodeComponent((eq === -1 ? '' : pair.slice(eq + 1)).replaceAll('+', ' '), 'query');
    if (!SINGLE_PARAMS.has(name)) continue;
    if (params.has(name)) throw new Error(`Duplicate ${name} parameter`);
    params.set(name, value);
  }
  return params;
}

/**
 * Parse an `otpauth://totp/...` URI.
 *
 * The label is `Issuer:account` or `account` (percent-encoded; a literal or encoded colon
 * separates the prefix). The issuer is the `issuer` query parameter or the label prefix; when
 * both are present and non-empty they must be equal (after trimming), so a link cannot show one
 * issuer in its label and save another.
 *
 * The query is decoded like a form (`+` is a space). Malformed percent-encoding anywhere in the
 * label or query, and a repeated secret/issuer/algorithm/digits/period parameter, are errors.
 * Other parameters are ignored.
 *
 * @param {string} uri
 * @returns {Account}
 * @throws {Error} for HOTP URIs, other schemes, malformed encoding, duplicate or invalid
 *   parameters, or an issuer parameter that disagrees with the label prefix
 */
export function parse(uri) {
  if (typeof uri !== 'string') throw new TypeError('URI must be a string');
  const trimmed = uri.trim();
  if (/^otpauth-migration:/i.test(trimmed)) {
    throw new Error('Google Authenticator export (otpauth-migration://) is not supported');
  }
  const match = URI_PATTERN.exec(trimmed);
  if (!match) throw new Error('Not an otpauth:// URI');

  const [, type, path, query = ''] = match;
  if (type.toLowerCase() === 'hotp') throw new Error('HOTP is not supported');
  if (type.toLowerCase() !== 'totp') throw new Error(`Unsupported OTP type: ${type || '(none)'}`);

  const params = parseQuery(query);
  const issuerParam = text(params.get('issuer'));
  const { prefix, label } = splitLabel(path, issuerParam);
  if (issuerParam && text(prefix) && text(prefix) !== issuerParam) {
    throw new Error(`Issuer "${issuerParam}" does not match the label prefix "${text(prefix)}"`);
  }

  return normalize({
    issuer: issuerParam || prefix,
    label,
    secret: params.get('secret'),
    algorithm: params.get('algorithm'),
    digits: params.get('digits'),
    period: params.get('period'),
  });
}

/**
 * Build an `otpauth://totp/...` URI that `parse` maps back to the same account.
 *
 * Always writes every parameter, so other apps do not need to agree on defaults.
 *
 * @param {object} account any object `normalize` accepts
 * @returns {string}
 */
export function format(account) {
  const { issuer, label, secret, algorithm, digits, period } = normalize(account);
  // An empty prefix (leading ':') keeps a colon inside the label from being read as a separator.
  const path = issuer || label.includes(':')
    ? `${encodeURIComponent(issuer)}:${encodeURIComponent(label)}`
    : encodeURIComponent(label);

  const query = [['secret', secret]];
  if (issuer) query.push(['issuer', issuer]);
  query.push(['algorithm', algorithm], ['digits', String(digits)], ['period', String(period)]);
  const search = query.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
  return `otpauth://totp/${path}?${search}`;
}
