#!/usr/bin/env node
// Renders the extension icons and the store graphics from the SVG masters in store/assets/src/
// with Playwright's headless Chromium (devDependency; run `npm ci` first), then prints each
// output's pixel size, PNG colour type and sha256.
//
//   node scripts/build-store-assets.mjs                 # write into this repository
//   node scripts/build-store-assets.mjs --out <dir>     # write the same tree under <dir> instead
//   node scripts/build-store-assets.mjs --src <dir>     # read the masters from <dir>
//
// Outputs (paths relative to the output root):
//   extension/icons/16.png 32.png   icon-16.svg (z only), icon-32.svg (z + simplified ring), each
//                                   on its own pixel grid
//   extension/icons/48.png          icon.svg full bleed (96-unit grid, so 48 px is pixel-aligned)
//   extension/icons/128.png         same bytes as store/assets/chrome-icon-128.png
//   store/assets/chrome-icon-128.png        icon.svg as 96x96 art with 16 px transparent padding
//   store/assets/edge-logo-300.png          edge-logo-300.svg
//   store/assets/promo-small-440x280.png    tile-440x280.svg, 24-bit RGB (no alpha)
//   store/assets/promo-marquee-1400x560.png marquee-1400x560.svg, 24-bit RGB (no alpha)
//   store/assets/preview-contact-sheet.png  review sheet: icons on light/dark toolbar strips,
//                                           8x pixel zooms, store icon, logo and tiles
//
// How: each SVG is loaded as an image into a blank page, drawn onto a canvas of the exact output
// size and read back with getImageData; this script then encodes the PNG itself (sRGB chunk,
// RGBA for icons and the logo, RGB for the promo tiles), so the bytes depend only on the pixels
// and not on screenshot metadata or the display's colour profile. `<image href="x.svg">` in a
// master is replaced by the file's data: URL before drawing, so a master can be opened as-is in
// a browser. The page loads nothing from the network: every request is aborted.
//
// Fonts: the wordmark (store/assets/src/wordmark.svg) is drawn geometry, stroked paths with no
// font, so it does not depend on the fonts installed. The tagline in the tiles is SVG text set in
// the system UI font (system-ui, then -apple-system, Segoe UI, Inter, Roboto, Helvetica Neue,
// Arial), as are the contact sheet's labels, so their exact pixels depend on the machine that
// renders them; the icons and the logo contain no text.

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function parseArgs(argv) {
  const opts = { src: path.join(REPO_ROOT, 'store', 'assets', 'src'), out: REPO_ROOT };
  for (let i = 0; i < argv.length; i += 2) {
    const value = argv[i + 1];
    if (argv[i] === '--src' && value) opts.src = path.resolve(value);
    else if (argv[i] === '--out' && value) opts.out = path.resolve(value);
    else return null;
  }
  return opts;
}

// ---- PNG encoding -----------------------------------------------------------------------------

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const typed = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const out = Buffer.alloc(8 + data.length + 4);
  out.writeUInt32BE(data.length, 0);
  typed.copy(out, 4);
  out.writeUInt32BE(crc32(typed), 8 + data.length);
  return out;
}

function paeth(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  return pb <= pc ? b : c;
}

// rgba: width*height*4 bytes, straight (not premultiplied) alpha, as getImageData returns them.
// With alpha=false every pixel must be opaque; the alpha channel is dropped (colour type 2).
function encodePng(width, height, rgba, { alpha }) {
  const bpp = alpha ? 4 : 3;
  const stride = width * bpp;
  const raw = Buffer.alloc((stride + 1) * height);
  const line = Buffer.alloc(stride);
  let prev = Buffer.alloc(stride);
  const candidate = Buffer.alloc(stride);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const s = (y * width + x) * 4;
      if (!alpha && rgba[s + 3] !== 255) throw new Error(`pixel ${x},${y} is not opaque in an RGB output`);
      line[x * bpp] = rgba[s];
      line[x * bpp + 1] = rgba[s + 1];
      line[x * bpp + 2] = rgba[s + 2];
      if (alpha) line[x * bpp + 3] = rgba[s + 3];
    }
    // Adaptive filtering: the filter type with the smallest sum of absolute (signed) residuals.
    let bestType = 0;
    let bestScore = Infinity;
    let best = Buffer.from(line);
    for (let type = 0; type <= 4; type++) {
      let score = 0;
      for (let i = 0; i < stride; i++) {
        const left = i >= bpp ? line[i - bpp] : 0;
        const up = prev[i];
        const upLeft = i >= bpp ? prev[i - bpp] : 0;
        const predictor = [0, left, up, (left + up) >> 1, paeth(left, up, upLeft)][type];
        const v = (line[i] - predictor) & 0xff;
        candidate[i] = v;
        score += v < 128 ? v : 256 - v;
      }
      if (score < bestScore) {
        bestScore = score;
        bestType = type;
        best = Buffer.from(candidate);
      }
    }
    raw[y * (stride + 1)] = bestType;
    best.copy(raw, y * (stride + 1) + 1);
    prev = Buffer.from(line);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = alpha ? 6 : 2; // RGBA or RGB
  // compression, filter and interlace methods stay 0
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('sRGB', Buffer.from([0])), // perceptual rendering intent
    pngChunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

// ---- SVG masters ------------------------------------------------------------------------------

function readMaster(srcDir, name, seen = []) {
  if (seen.includes(name)) throw new Error(`${name} includes itself via ${seen.join(' -> ')}`);
  let text = fs.readFileSync(path.join(srcDir, name), 'utf8');
  // Inline every <image href="local.svg"> as a data: URL (an SVG drawn as an image may not load
  // other files). Only plain file names in the same folder are accepted.
  text = text.replace(/(<image\b[^>]*?\bhref=")([^"]+)(")/g, (whole, open, href, close) => {
    if (!/^[a-z0-9-]+\.svg$/.test(href)) throw new Error(`${name}: <image href="${href}"> is not a local .svg`);
    return open + svgDataUrl(readMaster(srcDir, href, [...seen, name])) + close;
  });
  return text;
}

function svgDataUrl(text) {
  return `data:image/svg+xml;base64,${Buffer.from(text, 'utf8').toString('base64')}`;
}

// Sets the root <svg> width/height so Chromium rasterises the vector at the drawn size.
function sized(text, width, height) {
  return text.replace(/<svg\b[^>]*>/, (tag) => {
    const bare = tag.replace(/\s(width|height)="[^"]*"/g, '');
    return bare.replace(/^<svg/, `<svg width="${width}" height="${height}"`);
  });
}

// ---- Rendering in the page --------------------------------------------------------------------

// Runs in the page: draws layers (data: URL images) onto a canvas and returns the RGBA bytes as
// base64. `smooth: false` draws with nearest-neighbour scaling (pixel zooms on the contact sheet).
async function pageRasterize({ width, height, fill, layers, labels }) {
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d', { colorSpace: 'srgb', willReadFrequently: true });
  for (const rect of fill ?? []) {
    ctx.fillStyle = rect.color;
    ctx.fillRect(rect.x, rect.y, rect.w, rect.h);
  }
  for (const layer of layers ?? []) {
    const img = new Image();
    img.src = layer.src;
    await img.decode();
    ctx.imageSmoothingEnabled = layer.smooth !== false;
    ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(img, layer.x, layer.y, layer.w, layer.h);
  }
  for (const label of labels ?? []) {
    ctx.font = label.font;
    ctx.fillStyle = label.color;
    ctx.textBaseline = 'alphabetic';
    ctx.fillText(label.text, label.x, label.y);
  }
  const data = ctx.getImageData(0, 0, width, height).data;
  let binary = '';
  for (let i = 0; i < data.length; i += 0x8000) {
    binary += String.fromCharCode.apply(null, data.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

async function rasterize(page, job) {
  const b64 = await page.evaluate(pageRasterize, job);
  const rgba = Buffer.from(b64, 'base64');
  if (rgba.length !== job.width * job.height * 4) throw new Error('canvas readback has the wrong size');
  return rgba;
}

function svgLayer(text, x, y, w, h) {
  return { src: svgDataUrl(sized(text, w, h)), x, y, w, h };
}

function pngLayer(png, x, y, w, h, smooth = true) {
  return { src: `data:image/png;base64,${png.toString('base64')}`, x, y, w, h, smooth };
}

// ---- Contact sheet ----------------------------------------------------------------------------

const SHEET_FONT = '500 13px system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif';

function contactSheet(png) {
  const W = 1200;
  const fill = [{ color: '#f4f4f6', x: 0, y: 0, w: W, h: 1240 }];
  const layers = [];
  const labels = [];
  const label = (text, x, y, color = '#3c3c46') => labels.push({ text, x, y, color, font: SHEET_FONT });

  // 1. Toolbar strips: 1x (16.png at 16 px) and 2x (32.png at 32 px, a 16 dp icon on a 2x
  //    display), next to the 48 and 128 icons, on Chrome-like light and dark toolbars.
  let y = 24;
  label('Toolbar strips: light #ffffff and dark #1f1f1f (1x = 16.png, 2x = 32.png at device pixels)', 24, y + 4);
  y += 18;
  for (const [bg, fg] of [['#ffffff', '#5f6368'], ['#1f1f1f', '#c4c7c5']]) {
    fill.push({ color: bg, x: 24, y, w: W - 48, h: 176 });
    const top = y + 36; // icons hang from this line, labels sit above it
    label('1x toolbar', 48, y + 24, fg);
    layers.push(pngLayer(png['extension/icons/16.png'], 48, top, 16, 16));
    // neighbouring 16 px toolbar glyph stand-ins, to judge visual weight
    for (let i = 0; i < 3; i++) fill.push({ color: fg, x: 76 + i * 24, y: top + 3, w: 10, h: 10 });
    label('2x toolbar', 168, y + 24, fg);
    layers.push(pngLayer(png['extension/icons/32.png'], 168, top, 32, 32));
    label('48', 270, y + 24, fg);
    layers.push(pngLayer(png['extension/icons/48.png'], 270, top, 48, 48));
    label('128 (= store icon)', 360, y + 24, fg);
    layers.push(pngLayer(png['extension/icons/128.png'], 360, top, 128, 128));
    label('Edge logo 300 at 128', 540, y + 24, fg);
    layers.push(pngLayer(png['store/assets/edge-logo-300.png'], 540, top, 128, 128));
    label('16.png scaled to 32', 720, y + 24, fg);
    layers.push(pngLayer(png['extension/icons/16.png'], 720, top, 32, 32));
    y += 188;
  }

  // 2. Pixel zooms (nearest neighbour) of the hand-tuned small icons and the 48.
  label('Pixel zooms, nearest neighbour: 16.png x8, 32.png x8, 48.png x3 (light and dark)', 24, y + 16);
  y += 30;
  for (const [i, bg] of ['#ffffff', '#1f1f1f'].entries()) {
    const x0 = 24 + i * 588;
    fill.push({ color: bg, x: x0, y, w: 564, h: 276 });
    layers.push(pngLayer(png['extension/icons/16.png'], x0 + 10, y + 10, 128, 128, false));
    layers.push(pngLayer(png['extension/icons/32.png'], x0 + 148, y + 10, 256, 256, false));
    layers.push(pngLayer(png['extension/icons/48.png'], x0 + 414, y + 10, 144, 144, false));
    layers.push(pngLayer(png['extension/icons/48.png'], x0 + 414, y + 160, 48, 48));
  }
  y += 290;

  // 3. Promo tiles: the small tile at 1:1, the marquee at 1:2.
  label('promo-small-440x280.png (1:1) and promo-marquee-1400x560.png (scaled 1:2)', 24, y + 16);
  y += 30;
  layers.push(pngLayer(png['store/assets/promo-small-440x280.png'], 24, y, 440, 280));
  layers.push(pngLayer(png['store/assets/promo-marquee-1400x560.png'], 476, y, 700, 280));
  y += 300;

  // 4. Store icon and logo at 1:1 on light and dark.
  label('chrome-icon-128.png and edge-logo-300.png (1:1) on light and dark', 24, y + 16);
  y += 30;
  fill.push({ color: '#ffffff', x: 24, y, w: 564, h: 316 });
  fill.push({ color: '#1f1f1f', x: 612, y, w: 564, h: 316 });
  for (const x0 of [24, 612]) {
    layers.push(pngLayer(png['store/assets/chrome-icon-128.png'], x0 + 40, y + 94, 128, 128));
    layers.push(pngLayer(png['store/assets/edge-logo-300.png'], x0 + 224, y + 8, 300, 300));
  }
  y += 330;
  fill[0].h = y;
  return { width: W, height: y, fill, layers, labels };
}

// ---- Main -------------------------------------------------------------------------------------

async function main(argv) {
  const opts = parseArgs(argv);
  if (!opts) {
    console.error('usage: build-store-assets.mjs [--src <masters dir>] [--out <output root>]');
    process.exitCode = 1;
    return;
  }
  let chromium;
  try {
    ({ chromium } = await import('playwright'));
  } catch {
    console.error('build-store-assets: playwright is not installed; run `npm ci` first');
    process.exitCode = 1;
    return;
  }

  const icon = readMaster(opts.src, 'icon.svg');
  const icon16 = readMaster(opts.src, 'icon-16.svg');
  const icon32 = readMaster(opts.src, 'icon-32.svg');
  const edgeLogo = readMaster(opts.src, 'edge-logo-300.svg');
  const tile = readMaster(opts.src, 'tile-440x280.svg');
  const marquee = readMaster(opts.src, 'marquee-1400x560.svg');

  // [output path, width, height, layers, alpha]
  const jobs = [
    ['extension/icons/16.png', 16, 16, [svgLayer(icon16, 0, 0, 16, 16)], true],
    ['extension/icons/32.png', 32, 32, [svgLayer(icon32, 0, 0, 32, 32)], true],
    ['extension/icons/48.png', 48, 48, [svgLayer(icon, 0, 0, 48, 48)], true],
    ['store/assets/chrome-icon-128.png', 128, 128, [svgLayer(icon, 16, 16, 96, 96)], true],
    ['store/assets/edge-logo-300.png', 300, 300, [svgLayer(edgeLogo, 0, 0, 300, 300)], true],
    ['store/assets/promo-small-440x280.png', 440, 280, [svgLayer(tile, 0, 0, 440, 280)], false],
    ['store/assets/promo-marquee-1400x560.png', 1400, 560, [svgLayer(marquee, 0, 0, 1400, 560)], false],
  ];

  const browser = await chromium.launch({ headless: true });
  const png = {};
  try {
    const context = await browser.newContext({ viewport: { width: 400, height: 300 }, deviceScaleFactor: 1 });
    await context.route('**/*', (route) => route.abort());
    const page = await context.newPage();
    await page.setContent('<!doctype html><meta charset="utf-8"><title>render</title>');
    for (const [rel, width, height, layers, alpha] of jobs) {
      png[rel] = encodePng(width, height, await rasterize(page, { width, height, layers }), { alpha });
    }
    png['extension/icons/128.png'] = png['store/assets/chrome-icon-128.png'];
    const sheet = contactSheet(png);
    png['store/assets/preview-contact-sheet.png'] = encodePng(sheet.width, sheet.height, await rasterize(page, sheet), {
      alpha: false,
    });
  } finally {
    await browser.close();
  }

  const order = [
    'extension/icons/16.png',
    'extension/icons/32.png',
    'extension/icons/48.png',
    'extension/icons/128.png',
    'store/assets/chrome-icon-128.png',
    'store/assets/edge-logo-300.png',
    'store/assets/promo-small-440x280.png',
    'store/assets/promo-marquee-1400x560.png',
    'store/assets/preview-contact-sheet.png',
  ];
  for (const rel of order) {
    const file = path.join(opts.out, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, png[rel]);
    const buf = png[rel];
    const kind = buf[25] === 6 ? 'RGBA' : 'RGB';
    const sha = createHash('sha256').update(buf).digest('hex');
    console.log(`${rel}  ${buf.readUInt32BE(16)}x${buf.readUInt32BE(20)} ${kind} sRGB  ${buf.length} bytes  sha256 ${sha}`);
  }
}

await main(process.argv.slice(2));
