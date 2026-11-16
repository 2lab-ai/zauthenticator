// RFC 4648 section 6 base32 (alphabet A-Z 2-7).

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// Unpadded lengths whose final group can encode whole bytes (RFC 4648 section 6, cases 1-5).
const VALID_TAIL_LENGTHS = new Set([0, 2, 4, 5, 7]);

/**
 * Decode base32 text to bytes.
 *
 * Case-insensitive. Whitespace and '-' anywhere, and '=' padding at the end, are ignored.
 * Unused low bits of the final character are not checked.
 *
 * @param {string} str
 * @returns {Uint8Array}
 * @throws {Error} on empty input, characters outside the alphabet, or a length that cannot
 *   come from whole bytes.
 */
export function decode(str) {
  if (typeof str !== 'string') throw new TypeError('base32: input must be a string');
  const stripped = str.replace(/[\s-]+/g, '').replace(/=+$/, '');
  if (stripped.length === 0) throw new Error('base32: empty input');
  // Checked before toUpperCase(), which maps some non-ASCII letters (e.g. 'ß' -> 'SS') into the alphabet.
  const bad = stripped.match(/[^A-Za-z2-7]/u);
  if (bad) throw new Error(`base32: invalid character '${bad[0]}'`);
  const clean = stripped.toUpperCase();
  if (!VALID_TAIL_LENGTHS.has(clean.length % 8)) {
    throw new Error(`base32: invalid length ${clean.length}`);
  }

  const out = new Uint8Array(Math.floor((clean.length * 5) / 8));
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const ch of clean) {
    buffer = ((buffer << 5) | ALPHABET.indexOf(ch)) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (buffer >> bits) & 0xff;
    }
  }
  return out;
}

/**
 * Encode bytes as uppercase base32 without '=' padding.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function encode(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('base32: input must be a Uint8Array');
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = ((buffer << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(buffer >> bits) & 31];
    }
  }
  if (bits > 0) out += ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}
