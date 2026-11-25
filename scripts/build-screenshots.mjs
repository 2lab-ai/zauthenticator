#!/usr/bin/env node
// Builds the store screenshots and the README images from the real extension UI, with
// Playwright's Chromium (devDependency; run `npm ci` first), then prints each output's pixel size,
// PNG colour type and sha256.
//
//   node scripts/build-screenshots.mjs                 # write into this repository
//   node scripts/build-screenshots.mjs --out <dir>     # write the same tree under <dir> instead
//   node scripts/build-screenshots.mjs --headed        # show the browser while capturing
//
// Outputs (paths relative to the output root), each a 24-bit RGB PNG (no alpha) with an sRGB
// chunk:
//   store/assets/screenshots/1-codes.png     1280x800  the account list, one code in its last seconds
//   store/assets/screenshots/2-autofill.png  1280x800  a sign-in page whose code field auto-fill filled
//   store/assets/screenshots/3-bind.png      1280x800  the "Fill codes automatically?" window
//   store/assets/screenshots/4-add.png       1280x800  the Add account view, scrolled so no text is cut
//   store/assets/screenshots/5-settings.png  1280x800  Settings in two crops: the passkey section,
//                                                      and About with the version
//   docs/images/popup-list.png               the list capture at 2x, no frame
//   docs/images/popup-autofill-bind.png      the bind window capture at 2x
//   docs/images/popup-locked.png             the locked popup at 2x
//
// How:
// 1. The shipped extension (extension/, unchanged) in a fresh profile, channel 'chromium', light
//    colour scheme, deviceScaleFactor 2. The script creates a vault, adds made-up accounts with
//    random secrets, and captures the popup at 360 CSS px (the toolbar popup's width, popup.css
//    body) in the list, add, settings and locked states, and popup.html#bind at 400 CSS px, the
//    width of the window the service worker opens (lib/nav.js openOwnWindow).
//    A Playwright page is a tab, and in a tab chrome.tabs.getCurrent() returns one, so popup.js
//    draws its full-tab layout. An init script makes getCurrent() resolve to undefined, as it
//    does in the toolbar popup, so popup.js takes its toolbar-popup branch. The bind page keeps
//    the real getCurrent(): popup.js draws the window layout only in a tab.
//    Settings is far taller than the popup (about 1,270 CSS px in a scroll box of about 550), so
//    no scroll offset shows both its first group (the passkey section, which the toolbar popup
//    draws with its "Open in a tab" button) and its last (About and the version). It is captured
//    twice without the top bar: from the top of the view to midway down the gap after the passkey
//    section, and, scrolled to the end, from midway down the gap before About; the frame stacks
//    the two. The passkey section shows only when the browser reports WebAuthn PRF support; the
//    script stops if it stays hidden.
//    The bind offer and the two auto-fill sites are written through the page's own
//    popup/session.js (setPendingBind, addBinding, the calls the worker and the bind window
//    make): the shipped manifest grants no site access, and the browser's permission prompt
//    cannot be automated.
// 2. A test copy, for the auto-fill page only, built the way e2e/autofill.e2e.mjs builds it: a
//    copy of extension/ in os.tmpdir() whose service worker is e2e/fixtures/background.test.js
//    and whose host_permissions are the demo origin. A menu fill goes through
//    __zauthTest.handleMenuClick, Allow is clicked in the window that opens, and a fresh load of
//    https://login.example.com/2fa (store/assets/src/screens/demo-login.html, answered by
//    context.route; nothing leaves the machine) is filled by the registered auto-fill script.
//    The copy and the profiles are deleted at the end; none of it is written to the output.
// 3. Each screenshot is store/assets/src/screens/frame.html with the captures as data: URLs,
//    rendered at 1280x800, deviceScaleFactor 1, in a page whose network requests are all aborted.
//    Every capture is decoded here, checked opaque and written as RGB.
//
// The "last seconds" state (5 s or less, drawn as an inverted countdown) needs one row whose period
// ends while the others' do not. All 30 s codes roll over together, so that one account uses 30 s
// and the others 60 s, and the list is captured with 3-4 s left on it (the 60 s codes then show
// 33-34 s).
//
// Language: macOS Chromium ignores --lang (see e2e/harness.mjs); the script stops unless
// chrome.i18n.getMessage('lang') is 'en'. Text uses the system UI fonts, so exact pixels depend on
// the machine that renders them.

import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';
import { computeExtensionId, extensionWorker, openExtensionPage, realExtensionDir } from '../e2e/harness.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCREENS = path.join(REPO_ROOT, 'store', 'assets', 'src', 'screens');
const POPUP = 'popup/popup.html';
const PASSPHRASE = 'screenshot vault passphrase (sample data only)';
const DEMO_ORIGIN = 'https://login.example.com';
const DEMO_URL = `${DEMO_ORIGIN}/2fa`;
const DEMO_VIEWPORT = { width: 600, height: 470 };
// The bind window's width (lib/nav.js); the capture ends below its buttons.
const BIND_VIEWPORT = { width: 400, height: 572 };
// The popup in a screenshot is drawn at this size (360 CSS px -> 432 px; the popup's 600 px
// maximum height -> 720 px of the 800).
const POPUP_SCALE = 1.2;

// Made-up accounts. `expiring` marks the one 30 s account (see the header).
const ACCOUNTS = [
  { issuer: 'Acme Cloud', label: 'ops@acme.example', period: 60 },
  { issuer: 'Contoso Mail', label: 'jane@contoso.example', period: 30, expiring: true },
  { issuer: 'Example ID', label: 'j.doe@example.com', period: 60 },
  { issuer: 'Fabrikam Git', label: 'jdoe', period: 60 },
  { issuer: 'Northwind Bank', label: 'j.doe', period: 60, digits: 8 },
  { issuer: 'Tailspin VPN', label: 'jane', period: 60 },
];
const BIND_ISSUER = 'Example ID';
// The two auto-fill sites shown in Settings: [origin, issuer]. Short enough for the row (a
// longer origin, such as the demo site's, is cut with an ellipsis there).
const SITES = [
  ['https://bank.example', 'Northwind Bank'],
  ['https://vpn.example', 'Tailspin VPN'],
];

function parseArgs(argv) {
  const opts = { out: REPO_ROOT, headed: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--headed') opts.headed = true;
    else if (argv[i] === '--out' && argv[i + 1]) opts.out = path.resolve(argv[++i]);
    else return null;
  }
  return opts;
}

// ---- sample data ------------------------------------------------------------------------------

function base32(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

function otpauthUri(account) {
  const issuer = encodeURIComponent(account.issuer);
  const params = [`secret=${account.secret}`, `issuer=${issuer}`, `period=${account.period}`, `digits=${account.digits ?? 6}`];
  return `otpauth://totp/${issuer}:${encodeURIComponent(account.label)}?${params.join('&')}`;
}

// ---- PNG --------------------------------------------------------------------------------------

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

const predict = (type, left, up, upLeft) => [0, left, up, (left + up) >> 1, paeth(left, up, upLeft)][type];

// A PNG as Chromium's screenshots write it (8-bit RGB or RGBA, not interlaced).
// → { width, height, rgba }
function decodePng(buf) {
  if (buf.readUInt32BE(0) !== 0x89504e47) throw new Error('not a PNG');
  let header = null;
  const idat = [];
  for (let pos = 8; pos < buf.length; ) {
    const length = buf.readUInt32BE(pos);
    const type = buf.toString('ascii', pos + 4, pos + 8);
    const data = buf.subarray(pos + 8, pos + 8 + length);
    if (type === 'IHDR') header = { width: data.readUInt32BE(0), height: data.readUInt32BE(4), depth: data[8], color: data[9], interlace: data[12] };
    else if (type === 'IDAT') idat.push(data);
    else if (type === 'IEND') break;
    pos += 12 + length;
  }
  if (!header || header.depth !== 8 || header.interlace !== 0 || ![2, 6].includes(header.color)) {
    throw new Error(`unsupported PNG ${JSON.stringify(header)}`);
  }
  const { width, height } = header;
  const bpp = header.color === 6 ? 4 : 3;
  const stride = width * bpp;
  const raw = zlib.inflateSync(Buffer.concat(idat));
  const rgba = Buffer.alloc(width * height * 4);
  let prev = Buffer.alloc(stride);
  for (let y = 0; y < height; y++) {
    const type = raw[y * (stride + 1)];
    const line = Buffer.from(raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1)));
    for (let i = 0; i < stride; i++) {
      line[i] = (line[i] + predict(type, i >= bpp ? line[i - bpp] : 0, prev[i], i >= bpp ? prev[i - bpp] : 0)) & 0xff;
    }
    for (let x = 0; x < width; x++) {
      const d = (y * width + x) * 4;
      rgba[d] = line[x * bpp];
      rgba[d + 1] = line[x * bpp + 1];
      rgba[d + 2] = line[x * bpp + 2];
      rgba[d + 3] = bpp === 4 ? line[x * bpp + 3] : 255;
    }
    prev = line;
  }
  return { width, height, rgba };
}

// RGB PNG (colour type 2) with an sRGB chunk; every pixel must be opaque. Each row takes the
// filter with the smallest sum of absolute residuals.
function encodeRgbPng({ width, height, rgba }) {
  const stride = width * 3;
  const raw = Buffer.alloc((stride + 1) * height);
  let prev = Buffer.alloc(stride);
  const candidate = Buffer.alloc(stride);
  for (let y = 0; y < height; y++) {
    const line = Buffer.alloc(stride);
    for (let x = 0; x < width; x++) {
      const s = (y * width + x) * 4;
      if (rgba[s + 3] !== 255) throw new Error(`pixel ${x},${y} is not opaque`);
      line[x * 3] = rgba[s];
      line[x * 3 + 1] = rgba[s + 1];
      line[x * 3 + 2] = rgba[s + 2];
    }
    let bestType = 0;
    let bestScore = Infinity;
    let best = line;
    for (let type = 0; type <= 4; type++) {
      let score = 0;
      for (let i = 0; i < stride; i++) {
        const v = (line[i] - predict(type, i >= 3 ? line[i - 3] : 0, prev[i], i >= 3 ? prev[i - 3] : 0)) & 0xff;
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
    prev = line;
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // RGB
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('sRGB', Buffer.from([0])), // perceptual rendering intent
    pngChunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

const dataUrl = (png) => `data:image/png;base64,${png.toString('base64')}`;

// ---- browser helpers --------------------------------------------------------------------------

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function poll(probe, timeout = 15000, interval = 200) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const value = await probe();
    if (value) return value;
    if (Date.now() > deadline) return null;
    await sleep(interval);
  }
}

function contextOptions(extDir, headed, viewport) {
  return {
    headless: !headed,
    channel: 'chromium',
    locale: 'en-US',
    colorScheme: 'light',
    viewport,
    deviceScaleFactor: 2,
    args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`, '--lang=en-US'],
  };
}

// Runs in the popup page before popup.js: the toolbar popup has no Tab (see the header).
function toolbarPopup() {
  if (globalThis.chrome?.tabs) chrome.tabs.getCurrent = async () => undefined;
}

async function waitState(page, state, timeout = 30000) {
  await page.waitForSelector(`body[data-state="${state}"]`, { timeout });
}

// Opens popup.html in `page`, checks the message catalog is English, and creates the vault.
// → extension id
async function openAndCreateVault(context, page, extDir) {
  const { id } = await openExtensionPage(context, page, extDir, POPUP);
  const lang = await page.evaluate(() => chrome.i18n.getMessage('lang'));
  if (lang !== 'en') throw new Error(`the extension's message catalog is "${lang}", not "en" (set the system language to English)`);
  await waitState(page, 'setup');
  await page.fill('#setup-pass', PASSPHRASE);
  await page.fill('#setup-pass2', PASSPHRASE);
  await page.click('#setup-submit');
  await waitState(page, 'list');
  return id;
}

// Adds `accounts` through the Add view's otpauth:// box. → Map issuer → account id
async function addAccounts(page, accounts) {
  await page.click('#add-btn');
  await waitState(page, 'add');
  await page.fill('#add-uri', accounts.map(otpauthUri).join('\n'));
  await page.click('#add-uri-submit');
  await waitState(page, 'list');
  await page.waitForFunction((n) => document.querySelectorAll('.account').length === n, accounts.length, { timeout: 15000 });
  const rows = await page.evaluate(() => Array.from(document.querySelectorAll('.account'), (r) => [r.querySelector('.issuer')?.textContent ?? '', r.dataset.id]));
  return new Map(rows);
}

// Waits two frames, with the pointer parked over the brand (no hover style there).
async function settle(page) {
  await page.mouse.move(4, 4);
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}

// Runs in the page: what #main shows, in its scroll content's coordinates (CSS px). atoms are the
// boxes nothing may cut: one per line of every text node, and every input, textarea, select,
// button and svg icon. → { atoms: [[top, bottom], ...], view, max, scroll }
function mainLayout() {
  const main = document.querySelector('#main');
  const origin = main.getBoundingClientRect().top - main.scrollTop;
  const boxes = [];
  const walker = document.createTreeWalker(main, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    if (!node.textContent.trim()) continue;
    const range = document.createRange();
    range.selectNodeContents(node);
    for (const rect of range.getClientRects()) boxes.push({ rect, what: node.textContent.trim().slice(0, 40) });
  }
  for (const el of main.querySelectorAll('input, textarea, select, button, svg')) {
    boxes.push({ rect: el.getBoundingClientRect(), what: `<${el.localName}${el.id ? `#${el.id}` : ''}>` });
  }
  return {
    atoms: boxes
      .filter(({ rect }) => rect.width > 0 && rect.height > 0)
      .map(({ rect, what }) => ({ top: rect.top - origin, bottom: rect.bottom - origin, what })),
    view: main.clientHeight,
    max: main.scrollHeight - main.clientHeight,
    scroll: main.scrollTop,
    // The viewport y of the scroll content's top, so content offsets become clip coordinates.
    origin,
  };
}

// The atoms that horizontal lines at the content offsets `edges` cut: an atom across a line, or
// within EDGE_MARGIN of it.
const EDGE_MARGIN = 4;
function cutBy(layout, edges) {
  return layout.atoms.filter((a) => edges.some((e) => a.top < e + EDGE_MARGIN && a.bottom > e - EDGE_MARGIN));
}

// The atoms an edge of #main's visible part cuts at scroll offset s. The top edge counts only when
// scrolled, the bottom one only when more content lies below.
function cutAt(layout, s) {
  const edges = [];
  if (s > 0) edges.push(s);
  if (s < layout.max) edges.push(s + layout.view);
  return cutBy(layout, edges);
}

// Scrolls #main to a clean offset (no atom cut): the first one from `from` towards `towards`
// (+1 down, -1 up, in 1 px steps), or with `center` the middle of the run of clean offsets that
// starts there, so both edges sit mid-gap. → the offset
async function scrollClean(page, { from, towards, center = false, what }) {
  const layout = await page.evaluate(mainLayout);
  const clean = (s) => s >= 0 && s <= layout.max && cutAt(layout, s).length === 0;
  let first = Math.max(0, Math.min(layout.max, from));
  while (first >= 0 && first <= layout.max && !clean(first)) first += towards;
  if (!clean(first)) throw new Error(`${what}: no scroll offset leaves both edges clear`);
  let last = first;
  while (clean(last + towards)) last += towards;
  const offset = center ? Math.round((first + last) / 2) : first;
  await page.evaluate((s) => {
    document.querySelector('#main').scrollTop = s;
  }, offset);
  return offset;
}

// The page's <body> box (CSS px) as an opaque capture at the page's device scale. Throws when
// the top or bottom edge of #main's visible part cuts a line of text or a control.
// → { css: { width, height }, png }
async function captureBody(page, what) {
  await settle(page);
  const layout = await page.evaluate(mainLayout);
  const cut = cutAt(layout, layout.scroll);
  if (cut.length > 0) {
    const list = cut.map((a) => `${a.what} [${a.top.toFixed(1)}, ${a.bottom.toFixed(1)}]`).join('; ');
    throw new Error(`${what}: an edge of the popup cuts ${list} (scroll ${layout.scroll}, view ${layout.view})`);
  }
  const css = await page.evaluate(() => {
    const r = document.body.getBoundingClientRect();
    return { width: Math.round(r.width), height: Math.round(r.height) };
  });
  const shot = await page.screenshot({ clip: { x: 0, y: 0, ...css }, animations: 'disabled', caret: 'hide' });
  return { css, png: encodeRgbPng(decodePng(shot)) };
}

// Runs in the page: the box of `selector` in #main's scroll content coordinates (CSS px).
// → { top, bottom } or null when it is missing or not displayed
function contentBox(selector) {
  const main = document.querySelector('#main');
  const el = document.querySelector(selector);
  if (!el || el.getClientRects().length === 0) return null;
  const origin = main.getBoundingClientRect().top - main.scrollTop;
  const r = el.getBoundingClientRect();
  return { top: r.top - origin, bottom: r.bottom - origin };
}

// The Settings view in two crops (see the header): scrolled to the passkey section (below the v0.4
// passphrase section), from just above its title down to midway between it and the next group; scrolled to the end, from midway
// between the auto-fill sites and About down to the bottom of the body. Each cut line must lie in
// the visible part and cut no line of text or control. → { top, bottom }, each { css, png }
async function captureSettings(page) {
  const crop = async ({ scroll, above, below, keep, what }) => {
    await page.evaluate((s) => {
      const main = document.querySelector('#main');
      main.scrollTop = Math.min(s, main.scrollHeight - main.clientHeight);
    }, scroll);
    await settle(page);
    const layout = await page.evaluate(mainLayout);
    // With no atoms every cut line would pass the check below: fail closed instead.
    if (layout.atoms.length === 0) throw new Error(`${what}: #main reports no text or controls to check the cut against`);
    const a = await page.evaluate(contentBox, above);
    const b = await page.evaluate(contentBox, below);
    if (!a || !b) throw new Error(`${what}: ${!a ? above : below} is not displayed`);
    const cut = Math.round((a.bottom + b.top) / 2);
    if (cut < layout.scroll || cut > layout.scroll + layout.view) throw new Error(`${what}: the cut at ${cut} is outside the visible part (scroll ${layout.scroll}, view ${layout.view})`);
    const hit = cutBy(layout, [cut]);
    if (hit.length > 0) throw new Error(`${what}: the cut at ${cut} crosses ${hit.map((h) => h.what).join('; ')}`);
    const body = await page.evaluate(() => Math.round(document.body.getBoundingClientRect().height));
    const y = keep === 'above' ? Math.round(layout.origin + layout.scroll) : Math.round(layout.origin + cut);
    const end = keep === 'above' ? Math.round(layout.origin + cut) : body;
    const css = { width: 360, height: end - y };
    const shot = await page.screenshot({ clip: { x: 0, y, ...css }, animations: 'disabled', caret: 'hide' });
    return { css, png: encodeRgbPng(decodePng(shot)) };
  };
  // From v0.4 the passphrase section comes first: the top crop starts just above the passkey
  // section's title, so the frame still shows the passkey section with About below it.
  const passkeyBox = await page.evaluate(contentBox, '#passkey-section');
  if (!passkeyBox) throw new Error('settings top: #passkey-section is not displayed');
  const top = await crop({ scroll: Math.max(0, Math.round(passkeyBox.top) - 12), above: '#passkey-section', below: '[aria-labelledby="backup-title"]', keep: 'above', what: 'settings top' });
  const bottom = await crop({ scroll: Infinity, above: '[aria-labelledby="bindings-title"]', below: '[aria-labelledby="about-title"]', keep: 'below', what: 'settings bottom' });
  return { top, bottom };
}

// Throws when a text in `selectors` is cut off with an ellipsis (scrollWidth past its box).
async function assertNotClipped(page, selectors, what) {
  const clipped = await page.evaluate(
    (sels) =>
      sels.flatMap((sel) =>
        Array.from(document.querySelectorAll(sel))
          .filter((el) => el.getClientRects().length > 0 && el.scrollWidth > el.clientWidth)
          .map((el) => `${sel} "${el.textContent}"`),
      ),
    selectors,
  );
  if (clipped.length > 0) throw new Error(`${what}: text cut off: ${clipped.join(', ')}`);
}

const inWorker = async (context, id, fn, arg) => (await extensionWorker(context, id)).evaluate(fn, arg);

// Waits until the current period of a `period`-second code has at least `needMs` left.
async function waitForFreshPeriod(period, needMs) {
  const left = period * 1000 - (Date.now() % (period * 1000));
  if (left < needMs) await sleep(left + 300);
}

// ---- 1. the shipped extension -----------------------------------------------------------------

async function captureShipped(chromium, { headed, tmp, accounts }) {
  const extDir = realExtensionDir(path.join(REPO_ROOT, 'extension'));
  const profile = fs.mkdtempSync(path.join(tmp, 'profile-'));
  const context = await chromium.launchPersistentContext(profile, contextOptions(extDir, headed, { width: 360, height: 600 }));
  const shots = {};
  try {
    await context.route(/^(https?|wss?|ftp):/i, (route) => route.abort());
    const popup = await context.newPage();
    await popup.addInitScript(toolbarPopup);
    const id = await openAndCreateVault(context, popup, extDir);
    const layout = await popup.evaluate(() => ({ html: document.documentElement.className, width: document.body.getBoundingClientRect().width }));
    if (layout.html !== '' || layout.width !== 360) throw new Error(`popup page is not in its toolbar layout: ${JSON.stringify(layout)}`);
    const ids = await addAccounts(popup, accounts);
    const idOf = (issuer) => {
      const value = ids.get(issuer);
      if (!value) throw new Error(`no row for ${issuer} (rows: ${[...ids.keys()]})`);
      return value;
    };
    // The bind window, offering the demo site for the Example ID account (nothing bound yet).
    // popup/session.js is imported from the URL popup.js uses, so it is the same module instance.
    const offered = await popup.evaluate(async (offer) => (await import('/popup/session.js')).setPendingBind(offer), {
      origin: DEMO_ORIGIN,
      accountId: idOf(BIND_ISSUER),
    });
    if (offered !== true) throw new Error('setPendingBind stored no offer');
    const win = await context.newPage();
    await win.setViewportSize(BIND_VIEWPORT);
    await win.goto(`chrome-extension://${id}/${POPUP}#bind`);
    await waitState(win, 'bind');
    const bind = await win.evaluate(() => ({
      html: document.documentElement.className,
      origin: document.querySelector('#bind-origin').textContent,
      account: document.querySelector('#bind-account').textContent,
      replacesHidden: document.querySelector('#bind-replaces').hidden,
      allowHidden: document.querySelector('#bind-allow').hidden,
      error: document.querySelector('#bind-error').textContent,
    }));
    if (bind.html !== 'window' || bind.origin !== DEMO_ORIGIN || !bind.replacesHidden || bind.allowHidden || bind.error) {
      throw new Error(`bind window not as expected: ${JSON.stringify(bind)}`);
    }
    shots.bind = await captureWindow(win);
    await win.close();
    await popup.evaluate(async () => (await import('/popup/session.js')).clearPendingBind());

    // Add account.
    await popup.click('#add-btn');
    await waitState(popup, 'add');
    // The view is taller than the popup's 600 px; at the top its bottom edge cuts the Account
    // label. Scrolled down to the first offsets where both edges fall between blocks, mid-gap.
    await scrollClean(popup, { from: 0, towards: +1, center: true, what: 'add' });
    shots.add = await captureBody(popup, 'add');
    await popup.click('#add-cancel');
    await waitState(popup, 'list');

    // Settings with two auto-fill sites, in two crops: the passkey section, and About.
    for (const [origin, issuer] of SITES) {
      await popup.evaluate(async ([o, a]) => (await import('/popup/session.js')).addBinding(o, a), [origin, idOf(issuer)]);
    }
    await popup.click('#settings-btn');
    await waitState(popup, 'settings');
    await popup.waitForFunction((n) => document.querySelectorAll('#bindings .binding').length === n, SITES.length, { timeout: 15000 });
    // settings.js reveals the passkey section after an asynchronous support check; in the toolbar
    // popup it offers only to open Settings in a tab.
    const passkeyShown = await popup
      .waitForFunction(() => !document.querySelector('#passkey-section').hidden && !document.querySelector('#passkey-popup').hidden && document.querySelector('#passkey-tab').hidden, null, { timeout: 15000 })
      .then(() => true, () => false);
    if (!passkeyShown) throw new Error('settings: the passkey section is hidden (does this browser report WebAuthn PRF support?)');
    await assertNotClipped(popup, ['.binding-origin', '.binding-account'], 'settings');
    shots.settings = await captureSettings(popup);
    await popup.click('#settings-back');
    await waitState(popup, 'list');

    // The list with exactly one code in its last seconds: 26.3 s into a minute, the 30 s code has
    // 3.7 s left and the 60 s codes 33.7 s (at 56.3 s every code would have 3.7 s left).
    const expiringCount = () => popup.evaluate(() => document.querySelectorAll('.account.expiring').length);
    // The "Accounts added" notice from the Add view clears itself after a few seconds.
    await popup.waitForFunction(() => document.querySelector('#list-notice').textContent === '', null, { timeout: 30000 });
    for (let attempt = 0; ; attempt++) {
      const into = Date.now() % 60000;
      await sleep((26300 - into + 60000) % 60000);
      await sleep(250); // the list ticks 15 ms after each second
      const before = await expiringCount();
      await assertNotClipped(popup, ['.account .issuer', '.account .label'], 'list');
      const shot = await captureBody(popup, 'list');
      const after = await expiringCount();
      const notice = await popup.evaluate(() => document.querySelector('#list-notice').textContent);
      if (before === 1 && after === 1 && notice === '') {
        shots.list = shot;
        break;
      }
      if (attempt === 2) throw new Error(`expected one expiring row and no notice, saw ${before} then ${after} rows, notice "${notice}"`);
    }

    // Locked.
    await popup.click('#lock-btn');
    await waitState(popup, 'locked');
    shots.locked = await captureBody(popup, 'locked');
    return shots;
  } finally {
    await context.close();
  }
}

// The bind window's capture: its full width, from the top to 20 px below the buttons (the body
// fills the window, so the rest is empty). Throws if the content does not fit the window.
async function captureWindow(page) {
  await settle(page);
  const box = await page.evaluate(() => ({
    scroll: document.documentElement.scrollHeight,
    actions: Math.ceil(document.querySelector('.bind-actions').getBoundingClientRect().bottom),
  }));
  if (box.scroll > BIND_VIEWPORT.height) throw new Error(`bind window content ${box.scroll} px is taller than the window`);
  const css = { width: BIND_VIEWPORT.width, height: Math.min(BIND_VIEWPORT.height, box.actions + 20) };
  const shot = await page.screenshot({ clip: { x: 0, y: 0, ...css }, animations: 'disabled', caret: 'hide' });
  return { css, png: encodeRgbPng(decodePng(shot)) };
}

// ---- 2. the test copy, for the auto-fill page -------------------------------------------------

function buildTestCopy(tmp) {
  const root = realExtensionDir(fs.mkdtempSync(path.join(tmp, 'ext-')));
  fs.cpSync(path.join(REPO_ROOT, 'extension'), root, { recursive: true });
  fs.copyFileSync(path.join(REPO_ROOT, 'e2e', 'fixtures', 'background.test.js'), path.join(root, 'background.test.js'));
  const manifestPath = path.join(root, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  manifest.background = { ...manifest.background, service_worker: 'background.test.js' };
  manifest.host_permissions = [`${DEMO_ORIGIN}/*`];
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  return root;
}

async function captureAutofill(chromium, { headed, tmp, account }) {
  const copyDir = buildTestCopy(tmp);
  const profile = fs.mkdtempSync(path.join(tmp, 'profile-'));
  const context = await chromium.launchPersistentContext(profile, contextOptions(copyDir, headed, DEMO_VIEWPORT));
  const demoHtml = fs.readFileSync(path.join(SCREENS, 'demo-login.html'), 'utf8');
  try {
    // Routes run newest first: the demo origin is answered, every other remote request aborted.
    await context.route(/^(https?|wss?|ftp):/i, (route) => route.abort());
    await context.route(`${DEMO_ORIGIN}/**`, (route) => route.fulfill({ status: 200, contentType: 'text/html', body: demoHtml }));
    const popup = await context.newPage();
    const id = await openAndCreateVault(context, popup, copyDir);
    if (id !== computeExtensionId(copyDir)) throw new Error(`test copy id ${id} is not the computed one`);
    const accountId = (await addAccounts(popup, [account])).get(account.issuer);

    // A menu fill on the demo page, then Allow in the window it opens.
    const first = await context.newPage();
    await first.goto(DEMO_URL);
    await first.bringToFront();
    await first.focus('#otp');
    const tabId = await inWorker(context, id, (u) => chrome.tabs.query({}).then((tabs) => tabs.filter((t) => t.url === u).map((t) => t.id).pop()), DEMO_URL);
    await waitForFreshPeriod(account.period, 8000);
    const opened = context.waitForEvent('page', { predicate: (p) => p.url().startsWith(`chrome-extension://${id}/${POPUP}`), timeout: 15000 });
    await inWorker(
      context,
      id,
      ({ acct, url, tab }) => globalThis.__zauthTest.handleMenuClick({ menuItemId: `acct:${acct}`, editable: true, frameId: 0, pageUrl: url, frameUrl: url }, { id: tab, url }),
      { acct: accountId, url: DEMO_URL, tab: tabId },
    );
    const win = await opened;
    await waitState(win, 'bind', 15000);
    const closed = win.waitForEvent('close', { timeout: 15000 });
    await win.click('#bind-allow');
    await closed;
    const registered = await poll(() =>
      inWorker(context, id, (origin) => chrome.scripting.getRegisteredContentScripts().then((list) => list.some((s) => s.matches?.includes(`${origin}/*`))), DEMO_ORIGIN),
    );
    if (!registered) throw new Error(`no auto-fill script registered for ${DEMO_ORIGIN} after Allow`);
    await first.close();

    // A fresh load: the auto-fill script fills the field on its own.
    await waitForFreshPeriod(account.period, 12000);
    const page = await context.newPage();
    await page.goto(DEMO_URL);
    await page.bringToFront();
    await page.waitForFunction((n) => new RegExp(`^\\d{${n}}$`).test(document.querySelector('#otp')?.value ?? ''), account.digits ?? 6, { timeout: 15000 });
    await settle(page);
    const shot = await page.screenshot({ animations: 'disabled', caret: 'hide' });
    return { css: { ...DEMO_VIEWPORT }, png: encodeRgbPng(decodePng(shot)) };
  } finally {
    await context.close();
  }
}

// ---- 3. the frames ----------------------------------------------------------------------------

const escapeHtml = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

function img(shot, scale) {
  const width = Math.round(shot.css.width * scale);
  const height = Math.round(shot.css.height * scale);
  return `<img src="${dataUrl(shot.png)}" width="${width}" height="${height}" alt="">`;
}

const DOTS = '<span class="dot"></span><span class="dot"></span><span class="dot"></span>';
const LOCK = '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="10.5" width="14" height="9.5" rx="2.5"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5"/></svg>';

const popupStage = (shot) => `<div class="popup">${img(shot, POPUP_SCALE)}</div>`;
const stackStage = (...shots) => `<div class="stack">${shots.map(popupStage).join('')}</div>`;
const windowStage = (shot) => `<div class="window"><div class="bar">${DOTS}</div>${img(shot, POPUP_SCALE)}</div>`;
function browserStage(shot) {
  const url = new URL(DEMO_URL);
  const address = `<div class="address">${LOCK}<span><span class="host">${url.host}</span>${url.pathname}</span></div>`;
  return `<div class="browser"><div class="bar">${DOTS}${address}</div>${img(shot, 1)}</div>`;
}

function svgFile(name) {
  return `data:image/svg+xml;base64,${fs.readFileSync(path.join(REPO_ROOT, 'store', 'assets', 'src', name)).toString('base64')}`;
}

async function renderFrames(chromium, { headed, shots }) {
  const template = fs.readFileSync(path.join(SCREENS, 'frame.html'), 'utf8');
  const frames = [
    ['1-codes.png', 'Your 2FA codes, offline', 'Click a code to copy it.', popupStage(shots.list)],
    ['2-autofill.png', 'Fills the code for you', 'On sites you allowed, while unlocked.', browserStage(shots.demo)],
    ['3-bind.png', 'You choose each site', 'Auto-fill starts only after Allow.', windowStage(shots.bind)],
    ['4-add.png', 'Add from a QR or link', 'Or type the setup key yourself.', popupStage(shots.add)],
    ['5-settings.png', 'Unlock with a passkey', 'Optional. Your passphrase still works.', stackStage(shots.settings.top, shots.settings.bottom)],
  ];
  const browser = await chromium.launch({ headless: !headed, channel: 'chromium' });
  const out = {};
  try {
    const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1, colorScheme: 'dark' });
    await context.route('**/*', (route) => route.abort());
    const page = await context.newPage();
    for (const [file, headline, sub, stage] of frames) {
      const html = template
        .replace('{{ICON}}', svgFile('icon.svg'))
        .replace('{{WORDMARK}}', svgFile('wordmark.svg'))
        .replace('{{HEADLINE}}', escapeHtml(headline))
        .replace('{{SUBHEAD}}', escapeHtml(sub))
        .replace('{{STAGE}}', stage);
      await page.setContent(html, { waitUntil: 'load' });
      await page.evaluate(() => Promise.all([document.fonts.ready, ...Array.from(document.images, (i) => i.decode())]));
      // The subhead stays on one line inside the text column, and the capture inside the frame.
      const fit = await page.evaluate(() => {
        const sub = document.querySelector('.sub');
        const stage = document.querySelector('.stage > *').getBoundingClientRect();
        return {
          sub: Math.ceil(sub.scrollWidth) <= document.querySelector('.copy').clientWidth,
          h1Lines: Math.round(document.querySelector('h1').getBoundingClientRect().height / (54 * 1.08)),
          stage: stage.left >= 600 && stage.right <= 1280 - 32 && stage.top >= 32 && stage.bottom <= 800 - 32,
        };
      });
      if (!fit.sub || fit.h1Lines > 2 || !fit.stage) throw new Error(`${file}: layout does not fit ${JSON.stringify(fit)}`);
      const decoded = decodePng(await page.screenshot({ animations: 'disabled' }));
      if (decoded.width !== 1280 || decoded.height !== 800) throw new Error(`${file}: ${decoded.width}x${decoded.height}`);
      out[`store/assets/screenshots/${file}`] = encodeRgbPng(decoded);
    }
  } finally {
    await browser.close();
  }
  return out;
}

// ---- main -------------------------------------------------------------------------------------

async function main(argv) {
  const opts = parseArgs(argv);
  if (!opts) {
    console.error('usage: node scripts/build-screenshots.mjs [--out <dir>] [--headed]');
    process.exitCode = 1;
    return;
  }
  let chromium;
  try {
    ({ chromium } = await import('playwright'));
  } catch {
    console.error('build-screenshots: playwright is not installed; run `npm ci` first');
    process.exitCode = 1;
    return;
  }
  const accounts = ACCOUNTS.map((a) => ({ ...a, secret: base32(randomBytes(20)) }));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zauth-shots-'));
  let files;
  try {
    const shots = await captureShipped(chromium, { headed: opts.headed, tmp, accounts });
    shots.demo = await captureAutofill(chromium, { headed: opts.headed, tmp, account: accounts.find((a) => a.issuer === BIND_ISSUER) });
    files = await renderFrames(chromium, { headed: opts.headed, shots });
    files['docs/images/popup-list.png'] = shots.list.png;
    files['docs/images/popup-autofill-bind.png'] = shots.bind.png;
    files['docs/images/popup-locked.png'] = shots.locked.png;
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  for (const [rel, buf] of Object.entries(files)) {
    const file = path.join(opts.out, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, buf);
    const kind = buf[25] === 6 ? 'RGBA' : 'RGB';
    const sha = createHash('sha256').update(buf).digest('hex');
    console.log(`${rel}  ${buf.readUInt32BE(16)}x${buf.readUInt32BE(20)} ${kind} sRGB  ${buf.length} bytes  sha256 ${sha}`);
  }
}

await main(process.argv.slice(2));
