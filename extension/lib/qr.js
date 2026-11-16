// Image → QR text, using the vendored jsQR build (../vendor/jsQR.js, loaded by popup.html as a
// classic script, which defines globalThis.jsQR). Images are decoded locally from a Blob or a
// data: URL with createImageBitmap and drawn onto a canvas; nothing here touches the network.
//
// Size limits, all checked before the image is decoded:
// - at most MAX_IMAGE_BYTES of file (a data: URL is measured by its length first);
// - only PNG, JPEG, GIF, WebP and BMP are decoded: their headers are read (imagesize.js) and
//   images above MAX_IMAGE_PIXELS are refused; a recognized header whose size cannot be read is
//   refused too;
// - any other format (SVG, AVIF, ICO, ...) is refused before any decoder runs: its decoded size
//   cannot be read in advance, and the byte limit does not bound it;
// - larger images are decoded straight to a bitmap at most FULL_PASS_MAX per side, so no
//   full-resolution bitmap is kept; every canvas is at most FULL_PASS_MAX per side.

import { imageSize } from './imagesize.js';

/** Largest image file accepted, in bytes (20 MiB). */
export const MAX_IMAGE_BYTES = 20 * 1024 * 1024;
/** Largest image accepted, in pixels (50 megapixels). */
export const MAX_IMAGE_PIXELS = 50000000;

// Longest side for the first, cheap pass. Full-size tab screenshots on high-DPI screens are
// several megapixels; a QR code shown on a page is still well resolved after downscaling.
const FIRST_PASS_MAX = 1280;
// Longest side for the full-resolution pass, and of any decoded bitmap.
const FULL_PASS_MAX = 4096;
// Images smaller than this also get an upscaled pass: tiny QR images decode more reliably
// when each module covers a few pixels.
const SMALL_IMAGE_MAX = 480;
// Bytes read to find the size; JPEG/GIF files with more metadata than this are read whole.
const HEADER_BYTES = 64 * 1024;
// Longest data: URL accepted: base64 of MAX_IMAGE_BYTES plus room for the media type.
const MAX_DATA_URL_LENGTH = Math.ceil(MAX_IMAGE_BYTES / 3) * 4 + 1024;

export class QRError extends Error {
  // code ∈ 'no-qr' | 'bad-image' | 'too-large' | 'unsupported-format' | 'decoder-missing'
  constructor(code) {
    super(code);
    this.name = 'QRError';
    this.code = code;
  }
}

// source: Blob | File | 'data:image/...' URL string. Resolves to the decoded text of the
// first QR code found; rejects with QRError otherwise.
export async function decodeQR(source) {
  const decoder = globalThis.jsQR;
  if (typeof decoder !== 'function') throw new QRError('decoder-missing');

  const blob = typeof source === 'string' ? blobFromDataUrl(source) : source;
  if (!(blob instanceof Blob)) throw new QRError('bad-image');
  if (blob.size > MAX_IMAGE_BYTES) throw new QRError('too-large');

  const size = await readSize(blob);
  if (!size) throw new QRError('unsupported-format');
  if (size.width === null) throw new QRError('bad-image');
  if (size.width * size.height > MAX_IMAGE_PIXELS) throw new QRError('too-large');

  const image = await loadSniffed(blob, size);
  try {
    for (const scale of passScales(image.width, image.height)) {
      const width = Math.max(1, Math.round(image.width * scale));
      const height = Math.max(1, Math.round(image.height * scale));
      const text = scan(decoder, image.source, width, height, scale);
      if (text !== null) return text;
    }
  } finally {
    image.close();
  }
  throw new QRError('no-qr');
}

function passScales(width, height) {
  const longest = Math.max(width, height);
  const scales = [];
  if (longest > FIRST_PASS_MAX) scales.push(FIRST_PASS_MAX / longest);
  scales.push(Math.min(1, FULL_PASS_MAX / longest));
  if (longest < SMALL_IMAGE_MAX) scales.push(2);
  return scales;
}

function scan(decoder, source, width, height, scale) {
  const canvas = makeCanvas(width, height);
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  // Transparent pixels read as black; paint white first so a QR on a transparent PNG
  // keeps its light background.
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, width, height);
  // Smooth when shrinking, keep module edges sharp when enlarging.
  ctx.imageSmoothingEnabled = scale < 1;
  ctx.imageSmoothingQuality = 'high';
  ctx.drawImage(source, 0, 0, width, height);
  const { data } = ctx.getImageData(0, 0, width, height);
  const result = decoder(data, width, height, { inversionAttempts: 'attemptBoth' });
  return result && typeof result.data === 'string' && result.data !== '' ? result.data : null;
}

function makeCanvas(width, height) {
  if (typeof OffscreenCanvas === 'function') return new OffscreenCanvas(width, height);
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  return canvas;
}

// → imageSize() result for the file (null: not a format whose size it reads), reading more than
// the first bytes only when needed.
async function readSize(blob) {
  try {
    const size = imageSize(new Uint8Array(await blob.slice(0, HEADER_BYTES).arrayBuffer()));
    if (size && size.width === null && blob.size > HEADER_BYTES) {
      return imageSize(new Uint8Array(await blob.arrayBuffer()));
    }
    return size;
  } catch {
    throw new QRError('bad-image'); // the file could not be read
  }
}

// createImageBitmap options for an image of this header size: none up to FULL_PASS_MAX, else a
// bitmap at most FULL_PASS_MAX per side.
// Only the short side is given: the browser derives the other one from the image as it is
// displayed, so the result keeps its aspect ratio and stays in bounds even when EXIF orientation
// swaps width and height (then it is smaller than it could be). The short side is rounded down
// and aims one pixel below the limit, because the browser rounds the derived side up (Chromium
// was measured one pixel above the exact value).
// An image thinner than that ratio would need a short side below 1 px; both sides are given
// then (such an image cannot hold a QR code, so any distortion does not matter).
function resizeOptions(width, height) {
  const longest = Math.max(width, height);
  if (longest <= FULL_PASS_MAX) return undefined;
  const target = FULL_PASS_MAX - 1;
  const short = Math.floor((Math.min(width, height) * target) / longest);
  if (short < 1) {
    return width >= height
      ? { resizeWidth: target, resizeHeight: 1, resizeQuality: 'high' }
      : { resizeWidth: 1, resizeHeight: target, resizeQuality: 'high' };
  }
  return width >= height
    ? { resizeHeight: short, resizeQuality: 'high' }
    : { resizeWidth: short, resizeQuality: 'high' };
}

// A sniffed format (known size within the limits), decoded straight to a bitmap of bounded
// size. No <img> fallback: it would decode at full resolution.
async function loadSniffed(blob, { width, height }) {
  const options = resizeOptions(width, height);
  let bitmap;
  try {
    bitmap = await (options ? createImageBitmap(blob, options) : createImageBitmap(blob));
  } catch {
    throw new QRError('bad-image');
  }
  return checked({ source: bitmap, width: bitmap.width, height: bitmap.height, close: () => bitmap.close() });
}

// Refuses an empty or oversized decoded image (releasing it) before any canvas is made.
function checked(image) {
  const { width, height } = image;
  let code = null;
  if (!width || !height) code = 'bad-image';
  else if (width * height > MAX_IMAGE_PIXELS) code = 'too-large';
  if (code === null) return image;
  image.close();
  throw new QRError(code);
}

function blobFromDataUrl(url) {
  if (url.length > MAX_DATA_URL_LENGTH) throw new QRError('too-large');
  const match = /^data:([^;,]*)((?:;[^;,]*)*?),(.*)$/s.exec(url);
  if (!match) throw new QRError('bad-image');
  const type = match[1] || 'application/octet-stream';
  const isBase64 = /;base64$/i.test(match[2]);
  let bytes;
  try {
    if (isBase64) {
      const binary = atob(match[3]);
      bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    } else {
      bytes = new TextEncoder().encode(decodeURIComponent(match[3]));
    }
  } catch {
    throw new QRError('bad-image');
  }
  if (bytes.length > MAX_IMAGE_BYTES) throw new QRError('too-large');
  return new Blob([bytes], { type });
}
