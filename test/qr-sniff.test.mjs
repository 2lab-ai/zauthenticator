import { test } from 'node:test';
import assert from 'node:assert/strict';
import { imageSize } from '../extension/lib/imagesize.js';
import { decodeQR, QRError, MAX_IMAGE_BYTES, MAX_IMAGE_PIXELS } from '../extension/lib/qr.js';

// ---- synthetic headers -----------------------------------------------------------------------

const ascii = (s) => Array.from(s, (c) => c.charCodeAt(0));
const u16be = (n) => [(n >>> 8) & 0xff, n & 0xff];
const u16le = (n) => [n & 0xff, (n >>> 8) & 0xff];
const u24le = (n) => [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff];
const u32be = (n) => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
const u32le = (n) => [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
const bytes = (...parts) => Uint8Array.from(parts.flat());

const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const png = (width, height) => bytes(PNG_SIG, u32be(13), ascii('IHDR'), u32be(width), u32be(height), [8, 6, 0, 0, 0], [0, 0, 0, 0]);

// JPEG segment: FF <marker> <length incl. itself> <body>.
const segment = (marker, body) => [0xff, marker, ...u16be(body.length + 2), ...body];
const sof = (marker, width, height) => segment(marker, [8, ...u16be(height), ...u16be(width), 1, 1, 0x11, 0]);
const app0 = segment(0xe0, [...ascii('JFIF'), 0, 1, 1, 0, 0, 1, 0, 1, 0, 0]);
const dqt = segment(0xdb, [0, ...new Array(64).fill(1)]);
const sos = segment(0xda, [1, 1, 0, 0, 0x3f, 0]);
const SOI = [0xff, 0xd8];

const gif = (version, screenW, screenH, blocks = []) =>
  bytes(ascii(version), u16le(screenW), u16le(screenH), [0, 0, 0], blocks);
const imageDescriptor = (left, top, width, height) => [0x2c, ...u16le(left), ...u16le(top), ...u16le(width), ...u16le(height), 0];

const riff = (fourcc, data) => bytes(ascii('RIFF'), u32le(4 + 8 + data.length), ascii('WEBP'), ascii(fourcc), u32le(data.length), data);

const bmp = (dibSize, dims) => bytes(ascii('BM'), u32le(0), u32le(0), u32le(54), u32le(dibSize), dims, new Array(16).fill(0));

test('imageSize reads PNG IHDR', () => {
  assert.deepEqual(imageSize(png(640, 480)), { format: 'png', width: 640, height: 480 });
  assert.deepEqual(imageSize(png(100000, 100000)), { format: 'png', width: 100000, height: 100000 });
  // Signature only, zero dimension, or a first chunk that is not IHDR: known format, no size.
  const unreadable = { format: 'png', width: null, height: null };
  assert.deepEqual(imageSize(bytes(PNG_SIG)), unreadable);
  assert.deepEqual(imageSize(png(0, 480)), unreadable);
  assert.deepEqual(imageSize(bytes(PNG_SIG, u32be(13), ascii('IDAT'), u32be(640), u32be(480), [8, 6, 0, 0, 0])), unreadable);
});

test('imageSize walks JPEG segments to the frame header', () => {
  const plain = bytes(SOI, app0, dqt, sof(0xc0, 1920, 1080), sos);
  assert.deepEqual(imageSize(plain), { format: 'jpeg', width: 1920, height: 1080 });
  for (const marker of [0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]) {
    assert.deepEqual(imageSize(bytes(SOI, sof(marker, 30, 20), sos)), { format: 'jpeg', width: 30, height: 20 }, marker.toString(16));
  }
});

test('imageSize skips JPEG frame headers that are not the image frame', () => {
  // An EXIF thumbnail is a whole JPEG inside APP1; its SOF must not be taken for the image's.
  const thumbnail = [...SOI, ...sof(0xc0, 160, 120), 0xff, 0xd9];
  const app1 = segment(0xe1, [...ascii('Exif'), 0, 0, ...thumbnail]);
  assert.deepEqual(imageSize(bytes(SOI, app1, sof(0xc0, 9000, 9000), sos)), { format: 'jpeg', width: 9000, height: 9000 });
  // DHT (C4), JPG (C8) and DAC (CC) share the SOF marker range but are not frame headers.
  const lookalikes = [0xc4, 0xc8, 0xcc].map((m) => segment(m, [8, ...u16be(1), ...u16be(1), 1, 1, 0x11, 0]));
  assert.deepEqual(imageSize(bytes(SOI, ...lookalikes, sof(0xc2, 8000, 7000), sos)), { format: 'jpeg', width: 8000, height: 7000 });
});

test('imageSize reads JPEG markers the way the decoder does: fill bytes, stray bytes, standalone markers', () => {
  const fill = bytes(SOI, app0, [0xff, 0xff, 0xff], sof(0xc0, 50, 40), sos);
  assert.deepEqual(imageSize(fill), { format: 'jpeg', width: 50, height: 40 });
  // Bytes between segments are skipped up to the next FF (FF 00 is not a marker).
  const stray = bytes(SOI, app0, [0x00, 0x12, 0xff, 0x00, 0x34], sof(0xc0, 60, 70), sos);
  assert.deepEqual(imageSize(stray), { format: 'jpeg', width: 60, height: 70 });
  const standalone = bytes(SOI, [0xff, 0x01, 0xff, 0xd0], sof(0xc0, 80, 90), sos);
  assert.deepEqual(imageSize(standalone), { format: 'jpeg', width: 80, height: 90 });
});

test('imageSize reports no JPEG size when the frame header is missing or unusable', () => {
  const unreadable = { format: 'jpeg', width: null, height: null };
  assert.deepEqual(imageSize(bytes(SOI, app0, sos, sof(0xc0, 50, 40))), unreadable, 'SOS before SOF');
  assert.deepEqual(imageSize(bytes(SOI, app0, [0xff, 0xd9], sof(0xc0, 50, 40))), unreadable, 'EOI before SOF');
  assert.deepEqual(imageSize(bytes(SOI, app0)), unreadable, 'truncated before SOF');
  assert.deepEqual(imageSize(bytes(SOI, app0, sof(0xc0, 50, 40)).slice(0, -6)), unreadable, 'truncated SOF');
  assert.deepEqual(imageSize(bytes(SOI, sof(0xc0, 50, 0), sos)), unreadable, 'height 0 (DNL)');
  assert.deepEqual(imageSize(bytes(SOI, [0xff, 0xd8], sof(0xc0, 50, 40))), unreadable, 'second SOI');
  assert.deepEqual(imageSize(bytes(SOI, [0xff, 0xe0, 0x00, 0x01], sof(0xc0, 50, 40))), unreadable, 'segment length < 2');
});

test('imageSize finds a JPEG frame header far past the first bytes', () => {
  // Large metadata segments can push SOF well beyond a small header read.
  const big = segment(0xe2, new Array(65000).fill(0x20));
  const file = bytes(SOI, big, big, sof(0xc0, 12000, 9000), sos);
  assert.ok(file.length > 64 * 1024);
  assert.deepEqual(imageSize(file), { format: 'jpeg', width: 12000, height: 9000 });
  assert.deepEqual(imageSize(file.subarray(0, 64 * 1024)), { format: 'jpeg', width: null, height: null });
});

test('imageSize reads GIF and grows it to the first frame', () => {
  assert.deepEqual(imageSize(gif('GIF89a', 320, 200, imageDescriptor(0, 0, 320, 200))), { format: 'gif', width: 320, height: 200 });
  assert.deepEqual(imageSize(gif('GIF87a', 10, 10, imageDescriptor(0, 0, 10, 10))), { format: 'gif', width: 10, height: 10 });
  // A 1x1 logical screen with a huge first frame decodes at the frame's extent.
  assert.deepEqual(imageSize(gif('GIF89a', 1, 1, imageDescriptor(5, 7, 60000, 50000))), { format: 'gif', width: 60005, height: 50007 });
  // Global color table and extension blocks before the image descriptor.
  const withBlocks = bytes(
    ascii('GIF89a'), u16le(4), u16le(4), [0x81, 0, 0], new Array(12).fill(0),
    [0x21, 0xf9, 4, 0, 0, 0, 0, 0], [0x21, 0xff, 11, ...ascii('NETSCAPE2.0'), 3, 1, 0, 0, 0],
    imageDescriptor(0, 0, 40000, 40000),
  );
  assert.deepEqual(imageSize(withBlocks), { format: 'gif', width: 40000, height: 40000 });
  const unreadable = { format: 'gif', width: null, height: null };
  assert.deepEqual(imageSize(gif('GIF89a', 4, 4, [0x3b])), unreadable, 'trailer before any frame');
  assert.deepEqual(imageSize(gif('GIF89a', 4, 4)), unreadable, 'truncated before the first frame');
  assert.deepEqual(imageSize(gif('GIF89a', 4, 4, [0x99])), unreadable, 'unknown block');
});

test('imageSize reads WebP VP8, VP8L and VP8X', () => {
  const vp8 = [0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a, ...u16le(1024 | 0x4000), ...u16le(768 | 0x8000), 0, 0];
  assert.deepEqual(imageSize(riff('VP8 ', vp8)), { format: 'webp', width: 1024, height: 768 });
  const bits = (5000 - 1) | ((3000 - 1) << 14);
  assert.deepEqual(imageSize(riff('VP8L', [0x2f, ...u32le(bits), 0])), { format: 'webp', width: 5000, height: 3000 });
  const vp8x = [0x10, 0, 0, 0, ...u24le(16383), ...u24le(9999), 0, 0];
  assert.deepEqual(imageSize(riff('VP8X', vp8x)), { format: 'webp', width: 16384, height: 10000 });
  const unreadable = { format: 'webp', width: null, height: null };
  assert.deepEqual(imageSize(riff('VP8 ', [0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0, 4, 0, 3])), unreadable, 'VP8 without start code');
  assert.deepEqual(imageSize(riff('VP8L', [0x00, ...u32le(bits)])), unreadable, 'VP8L without signature');
  assert.deepEqual(imageSize(riff('ALPH', [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])), unreadable, 'unknown first chunk');
  assert.deepEqual(imageSize(riff('VP8X', [0, 0, 0])), unreadable, 'truncated VP8X');
  assert.equal(imageSize(bytes(ascii('RIFF'), u32le(4), ascii('WAVE'), ascii('fmt '))), null, 'RIFF but not WebP');
});

test('imageSize reads BMP info and core headers', () => {
  assert.deepEqual(imageSize(bmp(40, [...u32le(800), ...u32le(600)])), { format: 'bmp', width: 800, height: 600 });
  // Negative height = top-down rows.
  assert.deepEqual(imageSize(bmp(124, [...u32le(800), ...u32le(-600 >>> 0)])), { format: 'bmp', width: 800, height: 600 });
  assert.deepEqual(imageSize(bmp(12, [...u16le(300), ...u16le(200)])), { format: 'bmp', width: 300, height: 200 });
  const unreadable = { format: 'bmp', width: null, height: null };
  assert.deepEqual(imageSize(bmp(40, [...u32le(-800 >>> 0), ...u32le(600)])), unreadable, 'negative width');
  assert.deepEqual(imageSize(bmp(40, [...u32le(800), ...u32le(0)])), unreadable, 'zero height');
  assert.deepEqual(imageSize(bytes(ascii('BM'), u32le(0))), unreadable, 'truncated');
});

test('imageSize returns null for formats it does not know', () => {
  for (const sample of [
    bytes(ascii('<svg xmlns="x" width="100000" height="100000"/>')),
    bytes([0, 0, 1, 0, 1, 0]),
    bytes([0, 0, 0, 0x1c, ...ascii('ftypavif')]),
    bytes([]),
    bytes([0xff]),
  ]) {
    assert.equal(imageSize(sample), null);
  }
});

// ---- decodeQR bounds (stubbed browser APIs) -------------------------------------------------

const OTPAUTH = 'otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP';

// Models createImageBitmap's resize: with one of resizeWidth/resizeHeight the other side keeps
// the image's aspect ratio, rounded up the worst way Chromium was seen to round it (one pixel
// above the exact value: 769 for an exact 768).
const derived = (exact) => Math.floor(exact) + 1;
async function browserBitmap(blob, options = {}) {
  const size = imageSize(new Uint8Array(await blob.arrayBuffer()));
  const width = size?.width ?? 100;
  const height = size?.height ?? 100;
  if (options.resizeWidth && options.resizeHeight) return { width: options.resizeWidth, height: options.resizeHeight };
  if (options.resizeWidth) return { width: options.resizeWidth, height: derived((options.resizeWidth * height) / width) };
  if (options.resizeHeight) return { width: derived((options.resizeHeight * width) / height), height: options.resizeHeight };
  return { width, height };
}

// Replaces the browser globals decodeQR uses and records every call.
function stubBrowser(t, { bitmap = browserBitmap, decoded = OTPAUTH, img = null } = {}) {
  const calls = { createImageBitmap: [], bitmaps: [], canvases: [], closed: 0, images: 0, atob: 0 };
  const saved = {};
  const set = (name, value) => {
    saved[name] = Object.getOwnPropertyDescriptor(globalThis, name);
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
  };
  set('jsQR', (data, width, height) => (decoded && width >= 1 && height >= 1 ? { data: decoded } : null));
  set('createImageBitmap', async (blob, options) => {
    calls.createImageBitmap.push(options === undefined ? [blob] : [blob, options]);
    const size = await bitmap(blob, options);
    if (size instanceof Error) throw size;
    calls.bitmaps.push([size.width, size.height]);
    return { ...size, close: () => calls.closed++ };
  });
  set('OffscreenCanvas', class {
    constructor(width, height) {
      calls.canvases.push([width, height]);
      this.width = width;
      this.height = height;
    }
    getContext() {
      return { fillRect() {}, drawImage() {}, getImageData: (x, y, w, h) => ({ data: new Uint8ClampedArray(4 * w * h > 64 ? 64 : 4 * w * h) }) };
    }
  });
  set('Image', class {
    constructor() {
      calls.images++;
    }
    async decode() {
      if (!img) throw new Error('cannot decode');
      Object.assign(this, img);
    }
  });
  const realAtob = globalThis.atob;
  set('atob', (s) => {
    calls.atob++;
    return realAtob(s);
  });
  t.after(() => {
    for (const [name, descriptor] of Object.entries(saved)) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  });
  return calls;
}

const isQRError = (code) => (err) => {
  assert.ok(err instanceof QRError, `expected QRError, got ${err}`);
  assert.equal(err.code, code);
  return true;
};

test('the limits are 20 MiB and 50 megapixels', () => {
  assert.equal(MAX_IMAGE_BYTES, 20 * 1024 * 1024);
  assert.equal(MAX_IMAGE_PIXELS, 50000000);
});

test('decodeQR rejects a Blob over 20 MiB before decoding', async (t) => {
  const calls = stubBrowser(t);
  const big = new Blob([png(100, 100), new Uint8Array(MAX_IMAGE_BYTES)]);
  await assert.rejects(decodeQR(big), isQRError('too-large'));
  assert.equal(calls.createImageBitmap.length, 0);
  assert.equal(calls.images, 0);
});

test('decodeQR rejects headers above 50 megapixels before decoding', async (t) => {
  const calls = stubBrowser(t);
  for (const header of [
    png(7072, 7072),
    png(100000, 100000),
    bytes(SOI, app0, sof(0xc0, 10000, 5001), sos),
    gif('GIF89a', 1, 1, imageDescriptor(0, 0, 65535, 65535)),
    riff('VP8X', [0, 0, 0, 0, ...u24le(16383), ...u24le(16383), 0, 0]),
    bmp(40, [...u32le(20000), ...u32le(-20000 >>> 0)]),
  ]) {
    await assert.rejects(decodeQR(new Blob([header])), isQRError('too-large'));
  }
  assert.equal(calls.createImageBitmap.length, 0);
  assert.equal(calls.images, 0);
});

test('decodeQR finds a JPEG frame header beyond the first read', async (t) => {
  const calls = stubBrowser(t);
  const big = segment(0xe2, new Array(65000).fill(0x20));
  const file = bytes(SOI, big, big, sof(0xc0, 12000, 9000), sos);
  await assert.rejects(decodeQR(new Blob([file])), isQRError('too-large'));
  assert.equal(calls.createImageBitmap.length, 0);
});

test('decodeQR rejects a known format whose size cannot be read, without decoding', async (t) => {
  const calls = stubBrowser(t);
  for (const header of [bytes(PNG_SIG), bytes(SOI, app0, sos), gif('GIF89a', 4, 4, [0x3b])]) {
    await assert.rejects(decodeQR(new Blob([header])), isQRError('bad-image'));
  }
  assert.equal(calls.createImageBitmap.length, 0);
  assert.equal(calls.images, 0);
});

test('decodeQR asks for a resized bitmap with the longest side at most 4096', async (t) => {
  const calls = stubBrowser(t);
  const landscape = new Blob([png(8000, 4000)]);
  assert.equal(await decodeQR(landscape), OTPAUTH);
  const portrait = new Blob([bytes(SOI, app0, sof(0xc0, 3000, 7000), sos)]);
  assert.equal(await decodeQR(portrait), OTPAUTH);
  const atLimit = new Blob([png(7071, 7071)]);
  assert.equal(await decodeQR(atLimit), OTPAUTH);
  assert.deepEqual(calls.createImageBitmap, [
    // Only the short side is given (rounded down, aiming at 4095); the browser keeps the aspect
    // ratio of the image as it is oriented, so the bound holds whether or not EXIF rotation swaps
    // the sides.
    [landscape, { resizeHeight: 2047, resizeQuality: 'high' }],
    [portrait, { resizeWidth: 1755, resizeQuality: 'high' }],
    [atLimit, { resizeHeight: 4095, resizeQuality: 'high' }],
  ]);
  for (const [w, h] of calls.canvases) assert.ok(w <= 4096 && h <= 4096, `canvas ${w}x${h}`);
  assert.equal(calls.closed, 3);
});

test('decoded bitmaps stay within 4096 per side for ratios that do not divide evenly', async (t) => {
  const calls = stubBrowser(t, { decoded: null });
  const sizes = [[3000, 6999], [6999, 3000], [100, 39000], [39000, 100], [4097, 4096], [4097, 1], [1, 50000000], [12345, 4049]];
  for (const [w, h] of sizes) {
    await assert.rejects(decodeQR(new Blob([png(w, h)])), isQRError('no-qr'), `${w}x${h}`);
  }
  assert.equal(calls.bitmaps.length, sizes.length);
  for (const [[w, h], [bw, bh]] of sizes.map((size, i) => [size, calls.bitmaps[i]])) {
    assert.ok(bw >= 1 && bh >= 1 && bw <= 4096 && bh <= 4096, `${w}x${h} decoded to ${bw}x${bh}`);
  }
  // Thinner than 4095:1: both sides are given.
  assert.deepEqual(calls.createImageBitmap[6][1], { resizeWidth: 1, resizeHeight: 4095, resizeQuality: 'high' });
  for (const [w, h] of calls.canvases) assert.ok(w <= 4096 && h <= 4096, `canvas ${w}x${h}`);
});

test('decodeQR decodes small images at their own size', async (t) => {
  const calls = stubBrowser(t, { decoded: null });
  const blob = new Blob([png(800, 600)]);
  await assert.rejects(decodeQR(blob), isQRError('no-qr'));
  assert.deepEqual(calls.createImageBitmap, [[blob]]);
  assert.deepEqual(calls.canvases, [[800, 600]]);
  assert.equal(calls.closed, 1);
});

test('decodeQR does not fall back to <img> for a sniffed format the bitmap decoder rejects', async (t) => {
  const calls = stubBrowser(t, { bitmap: () => new Error('decode failed'), img: { naturalWidth: 10, naturalHeight: 10 } });
  await assert.rejects(decodeQR(new Blob([png(100, 100)])), isQRError('bad-image'));
  assert.equal(calls.createImageBitmap.length, 1);
  assert.equal(calls.images, 0);
});

test('decodeQR releases a decoded bitmap that is empty or above 50 megapixels, before any canvas', async (t) => {
  // A browser that decodes to another size than the header says: the bitmap is still checked.
  const sizes = [{ width: 10000, height: 10000 }, { width: 0, height: 0 }];
  const calls = stubBrowser(t, { bitmap: () => sizes.shift() });
  await assert.rejects(decodeQR(new Blob([png(100, 100)])), isQRError('too-large'));
  await assert.rejects(decodeQR(new Blob([png(100, 100)])), isQRError('bad-image'));
  assert.equal(calls.createImageBitmap.length, 2);
  assert.equal(calls.closed, 2);
  assert.equal(calls.canvases.length, 0);
});

// Formats imageSize does not read have no size to check before decoding (the byte limit does not
// bound the decoded size), so no decoder may see them. The stubbed decoders would succeed here,
// and a PNG afterwards shows the createImageBitmap spy records calls.
const SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="100000" height="100000"/>';

test('decodeQR refuses an SVG before any decoder runs', async (t) => {
  const calls = stubBrowser(t, { img: { naturalWidth: 100, naturalHeight: 100 } });
  await assert.rejects(decodeQR(new Blob([SVG], { type: 'image/svg+xml' })), isQRError('unsupported-format'));
  assert.equal(calls.createImageBitmap.length, 0);
  assert.equal(calls.images, 0);
  const png100 = new Blob([png(100, 100)]);
  assert.equal(await decodeQR(png100), OTPAUTH);
  assert.deepEqual(calls.createImageBitmap, [[png100]]);
  assert.equal(calls.images, 0);
});

test('decodeQR refuses an SVG the bitmap decoder rejects, without trying <img>', async (t) => {
  const calls = stubBrowser(t, { bitmap: () => new Error('unsupported'), img: { naturalWidth: 100, naturalHeight: 100 } });
  await assert.rejects(decodeQR(new Blob([SVG], { type: 'image/svg+xml' })), isQRError('unsupported-format'));
  await assert.rejects(decodeQR(`data:image/svg+xml,${encodeURIComponent(SVG)}`), isQRError('unsupported-format'));
  assert.equal(calls.createImageBitmap.length, 0);
  assert.equal(calls.images, 0);
  new Image(); // the Image spy counts constructions
  assert.equal(calls.images, 1);
});

test('decodeQR refuses unknown bytes before any decoder runs', async (t) => {
  const calls = stubBrowser(t, { img: { naturalWidth: 100, naturalHeight: 100 } });
  for (const sample of [
    bytes([0, 0, 0, 0x1c, ...ascii('ftypavif'), 0, 0, 0, 0]), // AVIF
    bytes([0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0]), // ICO
    bytes(ascii('RIFF'), u32le(4), ascii('WAVE'), ascii('fmt ')), // RIFF, not WebP
    bytes(ascii('not an image at all')),
  ]) {
    await assert.rejects(decodeQR(new Blob([sample])), isQRError('unsupported-format'));
  }
  assert.equal(calls.createImageBitmap.length, 0);
  assert.equal(calls.images, 0);
  const png100 = new Blob([png(100, 100)]);
  assert.equal(await decodeQR(png100), OTPAUTH);
  assert.deepEqual(calls.createImageBitmap, [[png100]]);
});

test('decodeQR rejects an oversized data: URL before decoding its base64', async (t) => {
  const calls = stubBrowser(t);
  const base64 = Buffer.from(png(10, 10)).toString('base64');
  const padding = 'A'.repeat(Math.ceil((MAX_IMAGE_BYTES * 4) / 3) + 8192);
  await assert.rejects(decodeQR(`data:image/png;base64,${base64}${padding}`), isQRError('too-large'));
  await assert.rejects(decodeQR(`data:image/svg+xml,${'%20'.repeat(MAX_IMAGE_BYTES)}`), isQRError('too-large'));
  assert.equal(calls.atob, 0);
  assert.equal(calls.createImageBitmap.length, 0);
});

test('decodeQR checks the exact decoded size of a data: URL', async (t) => {
  const calls = stubBrowser(t);
  // Short enough to pass the length check, but decodes to more than 20 MiB.
  const base64 = 'A'.repeat(Math.ceil(MAX_IMAGE_BYTES / 3) * 4 + 400);
  await assert.rejects(decodeQR(`data:image/png;base64,${base64}`), isQRError('too-large'));
  assert.equal(calls.createImageBitmap.length, 0);
});

test('decodeQR still decodes a normal data: URL', async (t) => {
  const calls = stubBrowser(t);
  const url = `data:image/png;base64,${Buffer.from(png(640, 480)).toString('base64')}`;
  assert.equal(await decodeQR(url), OTPAUTH);
  assert.equal(calls.atob, 1, 'the atob spy sees a normal base64 data: URL');
  assert.equal(calls.createImageBitmap.length, 1);
  assert.equal(calls.createImageBitmap[0][0].size, png(640, 480).length);
  await assert.rejects(decodeQR('data:image/png;base64,***'), isQRError('bad-image'));
  await assert.rejects(decodeQR('not a data url'), isQRError('bad-image'));
});

test('decodeQR keeps its other error codes', async (t) => {
  stubBrowser(t);
  await assert.rejects(decodeQR(42), isQRError('bad-image'));
  delete globalThis.jsQR;
  await assert.rejects(decodeQR(new Blob([png(10, 10)])), isQRError('decoder-missing'));
});
