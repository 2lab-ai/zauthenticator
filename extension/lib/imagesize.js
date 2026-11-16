// Image format and pixel size from the first bytes of a file, without decoding it.
//
// qr.js uses this to refuse decompression bombs (a few MB of PNG/GIF/JPEG can expand to
// billions of pixels) before the browser's decoder allocates them. Each reader reports the
// size the decoder will allocate, not just a header field:
// - PNG: IHDR, which must be the first chunk.
// - JPEG: the first SOFn frame header, found by walking segments by their length the way the
//   decoder reads markers (stray bytes and FF fill skipped; an EXIF thumbnail inside APP1 has its
//   own SOF and is skipped with its segment). No frame header before SOS/EOI = no size.
// - GIF: the logical screen grown to cover the first frame, as decoders do.
// - WebP: the VP8X canvas, or the VP8/VP8L bitstream size.
// - BMP: the info header (signed height, top-down when negative) or the 16-bit core header.

/**
 * @param {Uint8Array} bytes the start of the file (more bytes are needed for JPEG/GIF files
 *   with large metadata before the frame header)
 * @returns {null | {format: 'png'|'jpeg'|'gif'|'webp'|'bmp', width: number|null, height: number|null}}
 *   null when the bytes are not one of these formats; width and height are positive integers,
 *   or both null when the format is recognized but the size is not readable from these bytes
 *   (truncated or malformed header)
 */
export function imageSize(bytes) {
  for (const [format, matches, read] of READERS) {
    if (!matches(bytes)) continue;
    const size = read(bytes);
    const ok = size && Number.isSafeInteger(size.width) && Number.isSafeInteger(size.height)
      && size.width > 0 && size.height > 0;
    return ok ? { format, width: size.width, height: size.height } : { format, width: null, height: null };
  }
  return null;
}

const startsWith = (bytes, prefix, at = 0) =>
  bytes.length >= at + prefix.length && prefix.every((b, i) => bytes[at + i] === b);
const ascii = (s) => Array.from(s, (c) => c.charCodeAt(0));
const has = (bytes, at, length) => at >= 0 && at + length <= bytes.length;
const u16be = (b, at) => (b[at] << 8) | b[at + 1];
const u16le = (b, at) => b[at] | (b[at + 1] << 8);
const u24le = (b, at) => b[at] | (b[at + 1] << 8) | (b[at + 2] << 16);
const u32be = (b, at) => ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;
const u32le = (b, at) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;
const i32le = (b, at) => b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24);

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const IHDR = ascii('IHDR');
const GIF87A = ascii('GIF87a');
const GIF89A = ascii('GIF89a');
const RIFF = ascii('RIFF');
const WEBP = ascii('WEBP');
const BM = ascii('BM');

function readPng(b) {
  // Signature, then the IHDR chunk: length 13, type, width, height (big-endian).
  if (!has(b, 8, 16) || u32be(b, 8) !== 13 || !startsWith(b, IHDR, 12)) return null;
  return { width: u32be(b, 16), height: u32be(b, 20) };
}

// SOF0..SOF15 except DHT (C4), JPG (C8) and DAC (CC).
const isFrameMarker = (m) => m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc;
// Markers without a length field: TEM and RST0..RST7.
const isStandalone = (m) => m === 0x01 || (m >= 0xd0 && m <= 0xd7);

function readJpeg(b) {
  let at = 2; // after SOI (FF D8)
  for (;;) {
    // Next marker: skip any non-FF bytes, swallow FF fill bytes; FF 00 is not a marker.
    while (at < b.length && b[at] !== 0xff) at++;
    while (at < b.length && b[at] === 0xff) at++;
    if (at >= b.length) return null;
    const marker = b[at++];
    if (marker === 0x00 || isStandalone(marker)) continue;
    // SOS (image data starts), EOI, or a second SOI before any frame header: no size.
    if (marker === 0xda || marker === 0xd9 || marker === 0xd8) return null;
    if (!has(b, at, 2)) return null;
    const length = u16be(b, at);
    if (length < 2) return null;
    if (isFrameMarker(marker)) {
      // length, precision, height, width
      if (length < 8 || !has(b, at, 7)) return null;
      return { width: u16be(b, at + 5), height: u16be(b, at + 3) };
    }
    at += length;
  }
}

function readGif(b) {
  if (!has(b, 0, 13)) return null;
  let width = u16le(b, 6);
  let height = u16le(b, 8);
  const packed = b[10];
  let at = 13;
  if (packed & 0x80) at += 3 * (2 << (packed & 0x07)); // global color table
  for (;;) {
    if (!has(b, at, 1)) return null;
    const block = b[at];
    if (block === 0x2c) {
      // Image descriptor: left, top, width, height. Decoders grow the image to cover the
      // first frame when it does not fit in the logical screen.
      if (!has(b, at, 9)) return null;
      width = Math.max(width, u16le(b, at + 1) + u16le(b, at + 5));
      height = Math.max(height, u16le(b, at + 3) + u16le(b, at + 7));
      return { width, height };
    }
    if (block !== 0x21) return null; // trailer (0x3B) before any frame, or garbage
    // Extension: introducer, label, then data sub-blocks until a zero-length one.
    at += 2;
    for (;;) {
      if (!has(b, at, 1)) return null;
      const size = b[at];
      at += 1 + size;
      if (size === 0) break;
    }
  }
}

function readWebp(b) {
  // RIFF <size> WEBP, then the first chunk: fourcc, size, data at offset 20.
  if (!has(b, 12, 8)) return null;
  const chunk = String.fromCharCode(b[12], b[13], b[14], b[15]);
  const data = 20;
  if (chunk === 'VP8X') {
    // flags (1) + reserved (3), then canvas width - 1 and height - 1 (24-bit little-endian).
    if (!has(b, data, 10)) return null;
    return { width: u24le(b, data + 4) + 1, height: u24le(b, data + 7) + 1 };
  }
  if (chunk === 'VP8 ') {
    // Frame tag (3), start code 9D 01 2A, then 14-bit width and height (top 2 bits = scale).
    if (!has(b, data, 10) || b[data + 3] !== 0x9d || b[data + 4] !== 0x01 || b[data + 5] !== 0x2a) return null;
    return { width: u16le(b, data + 6) & 0x3fff, height: u16le(b, data + 8) & 0x3fff };
  }
  if (chunk === 'VP8L') {
    // Signature 0x2F, then 14-bit width - 1 and 14-bit height - 1.
    if (!has(b, data, 5) || b[data] !== 0x2f) return null;
    const bits = u32le(b, data + 1);
    return { width: (bits & 0x3fff) + 1, height: ((bits >>> 14) & 0x3fff) + 1 };
  }
  return null;
}

function readBmp(b) {
  if (!has(b, 14, 4)) return null;
  const headerSize = u32le(b, 14);
  if (headerSize === 12) {
    // BITMAPCOREHEADER: 16-bit unsigned width and height.
    if (!has(b, 18, 4)) return null;
    return { width: u16le(b, 18), height: u16le(b, 20) };
  }
  if (headerSize < 16 || !has(b, 18, 8)) return null;
  const width = i32le(b, 18);
  const height = i32le(b, 22);
  return width > 0 ? { width, height: Math.abs(height) } : null;
}

const READERS = [
  ['png', (b) => startsWith(b, PNG_SIGNATURE), readPng],
  ['jpeg', (b) => startsWith(b, [0xff, 0xd8]), readJpeg],
  ['gif', (b) => startsWith(b, GIF87A) || startsWith(b, GIF89A), readGif],
  ['webp', (b) => startsWith(b, RIFF) && startsWith(b, WEBP, 8), readWebp],
  ['bmp', (b) => startsWith(b, BM), readBmp],
];
