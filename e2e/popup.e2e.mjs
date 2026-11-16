// End-to-end run of the real extension (extension/) in Playwright's Chromium, driven through the
// popup DOM contract in .prd/02-architecture.md. Codes are compared with an independent TOTP
// implementation written below on node:crypto (extension/lib is deliberately not imported).
//
//   npm run e2e                          # headed (CI runs it under xvfb-run)
//   E2E_HEADLESS=1 npm run e2e           # new-headless Chromium
//   E2E_ARTIFACTS=<dir> npm run e2e      # screenshots go here (default test-results/)
//   E2E_EXTENSION=<dir> npm run e2e      # another unpacked copy, e.g. an unzipped release
//
// Part 1 is the single-page flow (setup, add, codes, lock, export, browser restart). Part 2 runs
// in a fresh profile with clipboard access: copy, two pages adding at once, lock from another
// page, idle auto-lock, copy after the period changed. Each part-2 step sets up its own
// preconditions and reports its own failure, so one broken behaviour does not hide the rest.
// The copy steps write TOTP codes of test secrets to the clipboard (the system one when headed).
//
// Prints `PASS|FAIL <name> <detail>` per assertion and exits 1 on any failure.

import { createHmac } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ARTIFACTS,
  HEADLESS,
  computeExtensionId,
  createReporter,
  ensureArtifactsDir,
  freshProfileDir,
  launch,
  openExtensionPage,
  probeFetch,
  realExtensionDir,
  watchConsole,
  watchNetwork,
  watchPages,
} from './harness.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const POPUP = 'popup/popup.html';
const PASSPHRASE = 'e2e correct horse battery staple';
const WRONG_PASSPHRASE = 'e2e wrong passphrase';
const IDLE_LOCK_MS = 15 * 60 * 1000;
// .prd/02-architecture.md, Round 2: session storage holds at most these keys.
const SESSION_KEYS_ALLOWED = ['vaultKey', 'lastActiveAt'];

const ACCOUNTS = [
  {
    name: 'sha1-6-30',
    uri: 'otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example',
    issuer: 'Example',
    label: 'alice@example.com',
    secret: 'JBSWY3DPEHPK3PXP',
    algorithm: 'sha1',
    digits: 6,
    period: 30,
  },
  {
    name: 'sha256-8-60',
    uri: 'otpauth://totp/Example256:bob@example.org?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=Example256&algorithm=SHA256&digits=8&period=60',
    issuer: 'Example256',
    label: 'bob@example.org',
    secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA',
    algorithm: 'sha256',
    digits: 8,
    period: 60,
  },
];

// Part 2: one account added from each of two pages at the same time.
const CONCURRENT_ACCOUNTS = [
  {
    name: 'sha512-6-30',
    uri: 'otpauth://totp/Example512:carol@example.net?secret=PJQXK5DIFVSTEZJNMNQXE33MFUYDAMBR&issuer=Example512&algorithm=SHA512',
    label: 'carol@example.net',
    secret: 'PJQXK5DIFVSTEZJNMNQXE33MFUYDAMBR',
  },
  {
    name: 'sha1-7-30',
    uri: 'otpauth://totp/ExampleSeven:dave@example.com?secret=PJQXK5DIFVSTEZJNMRQXMZJNGAYDAMBS&issuer=ExampleSeven&digits=7',
    label: 'dave@example.com',
    secret: 'PJQXK5DIFVSTEZJNMRQXMZJNGAYDAMBS',
  },
];

// Part 2: typed into the add view of one page, never submitted, must be cleared by a lock.
const TYPED = {
  uri: 'otpauth://totp/Typed:typed@example.com?secret=PJQXK5DIFVSTEZJNOR4XAZLEFUYDAMBT&issuer=Typed',
  secret: 'PJQXK5DIFVSTEZJNOR4XAZLEFUYDAMBT',
};

// ---- independent TOTP (RFC 4648 base32 + RFC 4226/6238 on node:crypto) ----------------------

function base32ToBytes(input) {
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

function referenceTotp(key, nowMs, { algorithm, digits, period }) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(nowMs / 1000 / period)));
  const mac = createHmac(algorithm, key).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

// The reference itself must be right: RFC 6238 Appendix B, T = 59 s, 8 digits.
function checkReference(rep) {
  const seed = (n) => Buffer.from('1234567890'.repeat(7).slice(0, n));
  const vectors = [
    ['sha1', seed(20), '94287082'],
    ['sha256', seed(32), '46119246'],
    ['sha512', seed(64), '90693936'],
  ];
  const got = vectors.map(([algorithm, key]) => referenceTotp(key, 59_000, { algorithm, digits: 8, period: 30 }));
  rep.check(
    'reference-totp-rfc6238',
    got.every((code, i) => code === vectors[i][2]),
    `T=59 sha1/sha256/sha512 -> ${got.join('/')}`,
  );
  const decoded = base32ToBytes(ACCOUNTS[1].secret).toString('latin1');
  rep.check('reference-base32', decoded === '12345678901234567890123456789012', `${ACCOUNTS[1].secret} -> ${decoded}`);
}

// ---- page helpers -----------------------------------------------------------------------------

async function waitState(page, state, timeout = 30000) {
  await page.waitForSelector(`body[data-state="${state}"]`, { timeout });
}

async function stateOf(page) {
  return page.evaluate(() => document.body?.dataset.state ?? '?').catch((err) => `unavailable (${err.message.split('\n')[0]})`);
}

async function readStorage(page) {
  return page.evaluate(async () => ({
    local: await chrome.storage.local.get(null),
    sync: await chrome.storage.sync.get(null),
    session: await chrome.storage.session.get(null),
  }));
}

// Every encoding of each secret that plaintext storage could plausibly use.
function secretForms() {
  return [...ACCOUNTS, ...CONCURRENT_ACCOUNTS, TYPED].flatMap(({ secret }) => {
    const raw = base32ToBytes(secret);
    return [
      secret,
      secret.toLowerCase(),
      raw.toString('hex'),
      raw.toString('hex').toUpperCase(),
      raw.toString('base64').replace(/=+$/, ''),
      raw.toString('base64url'),
      Array.from(raw).join(','),
      raw.toString('latin1'),
    ];
  });
}

function leakedForms(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  return secretForms().filter((form) => text.includes(form));
}

function isVaultRecord(r) {
  return Boolean(r) && typeof r === 'object' && 'v' in r && r.kdf && typeof r.iv === 'string' && typeof r.ct === 'string';
}

function checkStorage(rep, name, storage) {
  const leaks = leakedForms(storage);
  rep.check(
    name,
    leaks.length === 0 && Object.keys(storage.sync).length === 0,
    leaks.length
      ? `secret found in storage as ${JSON.stringify(leaks)}`
      : `local keys [${Object.keys(storage.local)}], sync keys [${Object.keys(storage.sync)}], session keys [${Object.keys(storage.session)}]; no secret form present`,
  );
}

// local holds exactly { vault }, sync nothing, session only keys from SESSION_KEYS_ALLOWED.
function checkStorageKeys(rep, name, storage) {
  const local = Object.keys(storage.local).sort();
  const sync = Object.keys(storage.sync);
  const session = Object.keys(storage.session).sort();
  const extra = session.filter((k) => !SESSION_KEYS_ALLOWED.includes(k));
  rep.check(
    name,
    local.length === 1 && local[0] === 'vault' && sync.length === 0 && extra.length === 0,
    `local [${local}] (exactly [vault]), sync [${sync}] (empty), session [${session}] (within [${SESSION_KEYS_ALLOWED}])`,
  );
}

async function rows(page) {
  return page.evaluate(() => ({
    now: Date.now(),
    rows: Array.from(document.querySelectorAll('.account'), (row) => ({
      id: row.dataset.id ?? '',
      issuer: row.querySelector('.issuer')?.textContent?.trim() ?? '',
      label: row.querySelector('.label')?.textContent?.trim() ?? '',
      code: row.querySelector('.code')?.dataset.code ?? '',
      remaining: row.querySelector('.remaining')?.textContent?.trim() ?? null,
    })),
  }));
}

async function labels(page) {
  return (await rows(page)).rows.map((r) => r.label);
}

async function waitForRows(page, count) {
  await page.waitForFunction((n) => document.querySelectorAll('.account').length === n, count, { timeout: 15000 });
}

// Reads the row's code and the page clock in one evaluate and compares with the reference at that
// instant. Within 1 s of a period boundary the reading is skipped and retried.
async function checkCode(rep, page, account, tag) {
  const key = base32ToBytes(account.secret);
  const periodMs = account.period * 1000;
  let last = 'no reading';
  for (let attempt = 1; attempt <= 6; attempt += 1) {
    const snap = await rows(page);
    const row = snap.rows.find((r) => r.label.includes(account.label));
    if (!row) {
      last = `no .account row with label ${account.label}: ${JSON.stringify(snap.rows)}`;
    } else {
      const into = snap.now % periodMs;
      if (into < 1000 || periodMs - into < 1000) {
        last = `page time ${snap.now} within 1 s of a ${account.period}s boundary`;
      } else {
        const expected = referenceTotp(key, snap.now, account);
        const at = new Date(snap.now).toISOString();
        if (row.code === expected) {
          rep.pass(
            `code-${account.name}${tag}`,
            `${row.code} == reference HMAC-${account.algorithm.toUpperCase()}/${account.digits}/${account.period}s at ${at} (issuer "${row.issuer}", label "${row.label}")`,
          );
          const seconds = Number.parseInt(row.remaining ?? '', 10);
          rep.check(
            `countdown-${account.name}${tag}`,
            row.remaining !== null && (Number.isNaN(seconds) || (seconds >= 1 && seconds <= account.period)),
            `.remaining ${JSON.stringify(row.remaining)} (expected about ${account.period - Math.floor(into / 1000)})`,
          );
          return;
        }
        last = `row ${JSON.stringify(row)} != reference ${expected} at ${at}`;
      }
    }
    await page.waitForTimeout(1200);
  }
  rep.fail(`code-${account.name}${tag}`, last);
}

async function addViaUri(page, uri, expectedRows) {
  await page.click('#add-btn');
  await waitState(page, 'add');
  await page.fill('#add-uri', uri);
  await page.click('#add-uri-submit');
  await waitState(page, 'list');
  await waitForRows(page, expectedRows);
}

async function unlock(page, timeout = 30000) {
  await page.fill('#unlock-pass', PASSPHRASE);
  await page.click('#unlock-submit');
  await waitState(page, 'list', timeout);
}

function findRecord(parsed) {
  if (isVaultRecord(parsed)) return { record: parsed, where: 'top level' };
  for (const [key, value] of Object.entries(parsed ?? {})) {
    if (isVaultRecord(value)) return { record: value, where: `.${key}` };
  }
  return null;
}

// Whatever the popup shows when a step dies: its state and any visible error text.
async function describePage(page) {
  try {
    return await page.evaluate(() => {
      const errors = ['#setup-error', '#unlock-error', '#add-error']
        .map((sel) => [sel, document.querySelector(sel)?.textContent?.trim()])
        .filter(([, text]) => text);
      return `state=${document.body?.dataset.state ?? '?'} errors=${JSON.stringify(Object.fromEntries(errors))}`;
    });
  } catch (err) {
    return `page unavailable: ${err.message}`;
  }
}

// The clipboard is shown only when it holds digits: if a copy failed it may still hold
// whatever was there before the run.
function shownClip(text) {
  if (text === null) return '(unreadable)';
  return /^\d{1,10}$/.test(text) ? text : `(non-digit content, ${text.length} chars)`;
}

// Clicks the row of `account` and reports what was copied. The value the page passed to
// navigator.clipboard.writeText() is recorded by a pass-through wrapper (the write still
// happens); navigator.clipboard.readText() must agree when the clipboard is readable. Without
// either, the row's data-code after the click is used. `afterClick` runs between the click and
// the read. → { at, text, source, consistent, clipboardText }
async function clickAndReadCopy(page, account, afterClick = async () => {}) {
  // writeText() needs a focused document; headed runs have several tabs.
  await page.bringToFront();
  await page.evaluate(() => {
    const clipboard = navigator.clipboard;
    if (!clipboard.zauthE2eWrapped) {
      const write = clipboard.writeText.bind(clipboard);
      clipboard.writeText = (text) => {
        globalThis.zauthE2eCopied = String(text);
        return write(text);
      };
      clipboard.zauthE2eWrapped = true;
    }
    globalThis.zauthE2eCopied = null;
  });
  await page.locator('.account', { hasText: account.label }).click();
  await afterClick();
  await page.waitForTimeout(200);
  const read = await page.evaluate(async (label) => {
    const at = Date.now();
    const row = Array.from(document.querySelectorAll('.account')).find((r) => r.querySelector('.label')?.textContent?.includes(label));
    const dataCode = row?.querySelector('.code')?.dataset.code ?? null;
    let clipboardText = null;
    let clipboardError = null;
    try {
      clipboardText = await navigator.clipboard.readText();
    } catch (err) {
      clipboardError = err.message;
    }
    return { at, written: globalThis.zauthE2eCopied, clipboardText, clipboardError, dataCode };
  }, account.label);
  const text = read.written ?? read.clipboardText ?? read.dataCode;
  const source =
    read.written !== null
      ? `writeText()${read.clipboardText !== null ? ' + readText()' : ` (clipboard not readable: ${read.clipboardError})`}`
      : read.clipboardText !== null
        ? 'readText() (no writeText() call seen)'
        : `row data-code (no writeText() call seen, clipboard not readable: ${read.clipboardError})`;
  const consistent = read.written === null || read.clipboardText === null || read.written === read.clipboardText;
  return { at: read.at, text, source, consistent, clipboardText: read.clipboardText };
}

// Copy at real time: the copied code equals the reference at that moment. Clicks well inside a
// period so the click and the read fall in the same one.
async function checkCopy(rep, page, account) {
  const key = base32ToBytes(account.secret);
  const periodMs = account.period * 1000;
  let last = 'no reading';
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    const before = await page.evaluate(() => Date.now());
    const into = before % periodMs;
    if (into < 500 || periodMs - into < 2500) {
      last = `page time ${before} too close to a ${account.period}s boundary`;
      await page.waitForTimeout(periodMs - into + 600);
      continue;
    }
    const read = await clickAndReadCopy(page, account);
    if (Math.floor(before / periodMs) !== Math.floor(read.at / periodMs)) {
      last = `click at ${before} and read at ${read.at} fell in different periods`;
      continue;
    }
    const expected = referenceTotp(key, read.at, account);
    rep.check(
      'copy',
      read.text === expected && read.consistent,
      `copied ${shownClip(read.text)} via ${read.source}${read.consistent ? '' : `, but the clipboard holds ${shownClip(read.clipboardText)}`}; reference ${expected} at ${new Date(read.at).toISOString()} (${account.name})`,
    );
    return;
  }
  rep.fail('copy', last);
}

// ---- run --------------------------------------------------------------------------------------

const rep = createReporter();
const extensionArg = path.resolve(process.env.E2E_EXTENSION || path.join(REPO_ROOT, 'extension'));
const manifestPath = path.join(extensionArg, 'manifest.json');
if (!fs.existsSync(manifestPath)) {
  rep.fail('extension-present', `${path.relative(process.cwd(), manifestPath)} not found`);
  rep.finish('e2e');
  process.exit();
}

const extDir = realExtensionDir(extensionArg);
const profile = freshProfileDir();
// The extension's origin as openExtensionPage resolved it (computed id or the chrome://extensions
// fallback), for the no-navigation check.
const ownOrigins = new Set();
const opens = async (ctx, p) => {
  const result = await openExtensionPage(ctx, p, extDir, POPUP);
  ownOrigins.add(`chrome-extension://${result.id}`);
  return result;
};
const pageWatchers = [];
ensureArtifactsDir();
console.log(`INFO mode ${HEADLESS ? "headless (channel 'chromium')" : 'headed'}; computed id ${computeExtensionId(extDir)}`);
checkReference(rep);

// ---- part 1: single-page flow -----------------------------------------------------------------

let context;
let page;
let step = 'launch';
try {
  context = await launch(extDir, profile);
  const net = watchNetwork(context);
  pageWatchers.push(watchPages(context));
  page = await context.newPage();
  const pageConsole = watchConsole(page);
  const opened = await opens(context, page);
  rep.pass('open-popup', `chrome-extension://${opened.id}/${POPUP} (id via ${opened.method})`);

  step = 'a-setup';
  await waitState(page, 'setup');
  await page.fill('#setup-pass', PASSPHRASE);
  await page.fill('#setup-pass2', PASSPHRASE);
  await page.click('#setup-submit');
  await waitState(page, 'list');
  rep.pass('setup', 'passphrase accepted, body[data-state=list]');
  let storage = await readStorage(page);
  rep.check(
    'vault-record',
    isVaultRecord(storage.local.vault),
    `chrome.storage.local.vault keys [${Object.keys(storage.local.vault ?? {})}]`,
  );
  checkStorage(rep, 'storage-ciphertext-only:after-setup', storage);
  checkStorageKeys(rep, 'storage-keys:after-setup', storage);

  step = 'b-add-sha1';
  await addViaUri(page, ACCOUNTS[0].uri, 1);
  rep.pass('add-uri-1', '.account row appeared');
  await checkCode(rep, page, ACCOUNTS[0], '');

  step = 'c-add-sha256';
  await addViaUri(page, ACCOUNTS[1].uri, 2);
  rep.pass('add-uri-2', 'second .account row appeared');
  await checkCode(rep, page, ACCOUNTS[1], '');
  storage = await readStorage(page);
  checkStorage(rep, 'storage-ciphertext-only:after-add', storage);
  checkStorageKeys(rep, 'storage-keys:after-add', storage);
  const listShot = path.join(ARTIFACTS, 'list.png');
  await page.screenshot({ path: listShot });
  rep.pass('screenshot-list', listShot);

  step = 'd-lock';
  await page.click('#lock-btn');
  await waitState(page, 'locked');
  storage = await readStorage(page);
  rep.check('lock', storage.session.vaultKey === undefined, `body[data-state=locked], session keys [${Object.keys(storage.session)}]`);
  const lockedShot = path.join(ARTIFACTS, 'locked.png');
  await page.screenshot({ path: lockedShot });
  rep.pass('screenshot-locked', lockedShot);
  await page.fill('#unlock-pass', WRONG_PASSPHRASE);
  await page.click('#unlock-submit');
  await page.locator('#unlock-error').waitFor({ state: 'visible', timeout: 30000 });
  await page.waitForFunction(() => document.querySelector('#unlock-error')?.textContent?.trim(), null, { timeout: 30000 });
  const wrongState = await page.evaluate(() => document.body.dataset.state);
  const wrongText = await page.locator('#unlock-error').textContent();
  rep.check('unlock-wrong-rejected', wrongState === 'locked', `state ${wrongState}, #unlock-error "${wrongText?.trim()}"`);
  await page.fill('#unlock-pass', PASSPHRASE);
  await page.click('#unlock-submit');
  await waitState(page, 'list');
  await waitForRows(page, 2);
  rep.pass('unlock-right', 'body[data-state=list] with 2 accounts');
  for (const account of ACCOUNTS) await checkCode(rep, page, account, ':after-unlock');
  checkStorageKeys(rep, 'storage-keys:after-unlock', await readStorage(page));

  step = 'e-network';
  const probe = await probeFetch(page);
  rep.check('fetch-blocked', probe.result.startsWith('blocked'), probe.result);
  console.log(`INFO csp-violation-events ${JSON.stringify(probe.violations)}`);
  const csp = pageConsole.filter((line) => /Content Security Policy/i.test(line));
  console.log(`INFO csp-console ${csp.length ? csp.join(' | ') : '(none)'}`);

  step = 'f-export';
  await page.click('#settings-btn');
  await waitState(page, 'settings');
  const [download] = await Promise.all([page.waitForEvent('download', { timeout: 15000 }), page.click('#export-btn')]);
  const exported = fs.readFileSync(await download.path(), 'utf8');
  let parsed = null;
  try {
    parsed = JSON.parse(exported);
  } catch {
    parsed = null;
  }
  const found = findRecord(parsed);
  rep.check(
    'export-record',
    Boolean(found),
    found
      ? `${download.suggestedFilename()}: vault record at ${found.where} (v=${found.record.v}, kdf ${found.record.kdf.name}/${found.record.kdf.iterations})`
      : `${download.suggestedFilename()} is not a vault record: ${exported.slice(0, 120)}`,
  );
  const exportLeaks = leakedForms(exported);
  rep.check('export-ciphertext-only', exportLeaks.length === 0, exportLeaks.length ? `secret in export as ${JSON.stringify(exportLeaks)}` : `${exported.length} bytes, no secret form present`);

  step = 'network-summary';
  rep.check('no-egress', net.egress().length === 0, `remote requests during run: ${JSON.stringify(net.egress())}`);
  rep.check('no-uncaught-errors', !pageConsole.some((l) => l.startsWith('pageerror:')), pageConsole.filter((l) => l.startsWith('pageerror:')).join(' | ') || 'none');
  await context.close();
  context = undefined;

  step = 'h-session-restart';
  context = await launch(extDir, profile);
  const net2 = watchNetwork(context);
  pageWatchers.push(watchPages(context));
  page = await context.newPage();
  await opens(context, page);
  await waitState(page, 'locked');
  rep.pass('session-restart-locked', 'new browser session opens locked');
  await page.fill('#unlock-pass', PASSPHRASE);
  await page.click('#unlock-submit');
  await waitState(page, 'list');
  await waitForRows(page, 2);
  rep.pass('session-restart-unlock', '2 accounts after unlock');
  rep.check('no-egress:restart', net2.egress().length === 0, `remote requests: ${JSON.stringify(net2.egress())}`);
  checkStorageKeys(rep, 'storage-keys:after-restart', await readStorage(page));
} catch (err) {
  const where = page ? await describePage(page) : 'no page';
  rep.fail(step, `${err.message.split('\n')[0]} [${where}]`);
  if (page) {
    const shot = path.join(ARTIFACTS, 'failure.png');
    await page.screenshot({ path: shot }).then(
      () => console.log(`INFO failure screenshot ${shot}`),
      () => {},
    );
  }
} finally {
  if (context) await context.close().catch(() => {});
  context = undefined;
  fs.rmSync(profile, { recursive: true, force: true });
}

// ---- part 2: several pages, idle lock, copy ---------------------------------------------------

const profile2 = freshProfileDir();
const livePages = new Set(); // pages to describe when a step fails
const consoles = [];

// Runs one step; an exception becomes a FAIL line for that step with every open page's state.
async function stepRun(name, fn) {
  try {
    await fn();
  } catch (err) {
    const where = await Promise.all([...livePages].map((p) => describePage(p)));
    rep.fail(name, `${err.message.split('\n')[0]} [${where.join(' / ') || 'no page'}]`);
  }
}

async function newPopupPage(ctx) {
  const p = await ctx.newPage();
  livePages.add(p);
  p.on('close', () => livePages.delete(p));
  consoles.push(watchConsole(p));
  await opens(ctx, p);
  return p;
}

let pageA;
let pageB;
let net3;
let pages3;
try {
  context = await launch(extDir, profile2);
  // Granted for every origin: Chromium refuses a grant scoped to a chrome-extension:// origin.
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  net3 = watchNetwork(context);
  pages3 = watchPages(context);
  pageWatchers.push(pages3);

  await stepRun('part2-setup', async () => {
    pageA = await newPopupPage(context);
    await waitState(pageA, 'setup', 15000);
    await pageA.fill('#setup-pass', PASSPHRASE);
    await pageA.fill('#setup-pass2', PASSPHRASE);
    await pageA.click('#setup-submit');
    await waitState(pageA, 'list');
    await addViaUri(pageA, ACCOUNTS[0].uri, 1);
  });

  await stepRun('copy', async () => {
    await waitState(pageA, 'list', 10000);
    await checkCopy(rep, pageA, ACCOUNTS[0]);
  });

  // Two pages of the same extension, each adding a different account at the same moment.
  // Without cross-page exclusion the later seal overwrites the earlier one. Two Playwright
  // clicks land milliseconds apart and overlapped in only some runs, so both pages are armed to
  // click their own submit button on one BroadcastChannel message: both submits start in the
  // same instant on every run.
  await stepRun('concurrent-add', async () => {
    pageB = await newPopupPage(context);
    await Promise.all([waitState(pageA, 'list', 10000), waitState(pageB, 'list', 10000)]);
    const prepare = async (p, account) => {
      await p.click('#add-btn');
      await waitState(p, 'add', 10000);
      await p.fill('#add-uri', account.uri);
      await p.evaluate(() => {
        const channel = new BroadcastChannel('zauth-e2e-submit');
        channel.onmessage = () => {
          channel.close();
          document.querySelector('#add-uri-submit').click();
        };
      });
    };
    await Promise.all([prepare(pageA, CONCURRENT_ACCOUNTS[0]), prepare(pageB, CONCURRENT_ACCOUNTS[1])]);
    // A channel object never receives its own message; the two armed objects both do.
    await pageA.evaluate(() => {
      const channel = new BroadcastChannel('zauth-e2e-submit');
      channel.postMessage('submit');
      channel.close();
    });
    const settled = await Promise.all(
      [pageA, pageB].map((p) => waitState(p, 'list', 15000).then(() => 'list', async () => describePage(p))),
    );
    await Promise.all([pageA.reload(), pageB.reload()]);
    await Promise.all([waitState(pageA, 'list', 15000), waitState(pageB, 'list', 15000)]);
    const want = CONCURRENT_ACCOUNTS.map((a) => a.label);
    await pageA
      .waitForFunction((w) => w.every((l) => document.body.textContent.includes(l)), want, { timeout: 5000 })
      .catch(() => {});
    const [inA, inB] = await Promise.all([labels(pageA), labels(pageB)]);
    const missing = want.filter((l) => !inA.includes(l) || !inB.includes(l));
    rep.check(
      'concurrent-add',
      missing.length === 0,
      `after both submits [${settled.join(', ')}] and a reload: page A [${inA.join(', ')}], page B [${inB.join(', ')}]${missing.length ? `; lost ${missing.join(', ')}` : ''}`,
    );
    checkStorage(rep, 'storage-ciphertext-only:part2', await readStorage(pageA));
  });

  // Page B has typed (not submitted) a URI and a secret; page A locks.
  await stepRun('cross-page-lock', async () => {
    if ((await stateOf(pageA)) !== 'list') throw new Error(`page A is ${await stateOf(pageA)}, not list`);
    if ((await stateOf(pageB)) === 'list') await pageB.click('#add-btn');
    await waitState(pageB, 'add', 10000);
    await pageB.fill('#add-uri', TYPED.uri);
    await pageB.fill('#manual-secret', TYPED.secret);
    await pageA.click('#lock-btn');
    await waitState(pageA, 'locked', 10000);
    const reached = await waitState(pageB, 'locked', 10000).then(
      () => true,
      () => false,
    );
    const b = await pageB.evaluate(() => ({
      state: document.body.dataset.state,
      uri: document.querySelector('#add-uri')?.value.length ?? -1,
      secret: document.querySelector('#manual-secret')?.value.length ?? -1,
    }));
    const session = Object.keys((await readStorage(pageA)).session);
    rep.check('cross-page-lock', reached && b.state === 'locked', `page B state ${b.state} after page A locked; session keys [${session}]`);
    rep.check(
      'lock-clears-inputs',
      b.uri === 0 && b.secret === 0,
      `page B #add-uri ${b.uri} chars, #manual-secret ${b.secret} chars after the lock (both must be 0)`,
    );
  });

  // lastActiveAt older than 15 minutes: opening a page locks before showing codes. A reload with
  // a fresh lastActiveAt is the control.
  await stepRun('idle-auto-lock', async () => {
    if (pageB) await pageB.close();
    pageB = undefined;
    if ((await stateOf(pageA)) === 'locked') await unlock(pageA);
    await waitState(pageA, 'list', 10000);
    checkStorageKeys(rep, 'storage-keys:part2-unlocked', await readStorage(pageA));
    await pageA.reload();
    const control = await waitState(pageA, 'list', 10000).then(
      () => 'list',
      async () => stateOf(pageA),
    );
    rep.check('idle-control-reload-stays-unlocked', control === 'list', `reload with recent activity: state ${control}`);
    const stale = await pageA.evaluate(async (age) => {
      const lastActiveAt = Date.now() - age;
      await chrome.storage.session.set({ lastActiveAt });
      return lastActiveAt;
    }, IDLE_LOCK_MS + 60 * 1000);
    await pageA.reload();
    const state = await waitState(pageA, 'locked', 10000).then(
      () => 'locked',
      async () => stateOf(pageA),
    );
    const session = Object.keys((await readStorage(pageA)).session);
    rep.check(
      'idle-auto-lock',
      state === 'locked',
      `lastActiveAt set to ${new Date(stale).toISOString()} (16 min ago), reload -> state ${state}; session keys [${session}]`,
    );
  });

  // Copy must compute the code at click time. The page clock is moved into the next period
  // with its timers paused, so the row still shows the previous period's code.
  await stepRun('copy-after-period-change', async () => {
    const account = ACCOUNTS[0];
    const key = base32ToBytes(account.secret);
    const periodMs = account.period * 1000;
    const pageC = await context.newPage();
    livePages.add(pageC);
    pageC.on('close', () => livePages.delete(pageC));
    consoles.push(watchConsole(pageC));
    // Playwright's clock belongs to the context; nothing after this step relies on timers.
    await pageC.clock.install({ time: Date.now() });
    await opens(context, pageC);
    await pageC.waitForSelector('body[data-state="locked"], body[data-state="list"]', { timeout: 10000 });
    if ((await stateOf(pageC)) === 'locked') await unlock(pageC);
    await pageC.locator('.account', { hasText: account.label }).waitFor({ timeout: 10000 });
    const before = await pageC.evaluate(() => Date.now());
    await pageC.clock.pauseAt(before + 200);
    const target = (Math.floor(before / periodMs) + 1) * periodMs + Math.floor(periodMs / 3);
    await pageC.clock.setSystemTime(target);
    const shownBefore = (await rows(pageC)).rows.find((r) => r.label.includes(account.label))?.code ?? '';
    // Paused timers still run when the clock is advanced: 1 s, well inside the new period, lets
    // a copy path that waits on a timer finish.
    const read = await clickAndReadCopy(pageC, account, () => pageC.clock.runFor(1000));
    const expected = referenceTotp(key, read.at, account);
    const previous = referenceTotp(key, before, account);
    rep.check(
      'copy-after-period-change',
      read.text === expected && read.consistent,
      `page clock moved to ${new Date(target).toISOString()} without a list tick (row showed ${shownBefore}): copied ${shownClip(read.text)} via ${read.source}${read.consistent ? '' : `, but the clipboard holds ${shownClip(read.clipboardText)}`}; reference now ${expected}, previous period ${previous}`,
    );
    await pageC.close();
  });

  rep.check('no-egress:part2', net3.egress().length === 0, `remote requests: ${JSON.stringify(net3.egress())}`);
  const errors = consoles.flat().filter((l) => l.startsWith('pageerror:'));
  rep.check('no-uncaught-errors:part2', errors.length === 0, errors.join(' | ') || 'none');
} catch (err) {
  rep.fail('part2', `${err.message.split('\n')[0]}`);
}

// Every page seen in every launch, including any the extension opened itself, stayed on the
// extension's own pages or about:blank.
const origins = ownOrigins.size ? [...ownOrigins] : [`chrome-extension://${computeExtensionId(extDir)}`];
const offenders = pageWatchers.flatMap((w) => w.offenders(origins));
const pageCount = pageWatchers.reduce((n, w) => n + w.count(), 0);
rep.check(
  'no-navigation',
  pageWatchers.length > 0 && offenders.length === 0,
  `${pageCount} pages in ${pageWatchers.length} launches; URLs outside ${origins.join(', ')} and about:blank: ${JSON.stringify(offenders)}`,
);

// Positive control, after the assertions above: a page opened by window.open() from another page
// is recorded with its URL (answered by a local route, nothing leaves the machine).
if (context && pages3) {
  try {
    const control = 'https://nav-control.invalid/';
    await context.route(`${control}**`, (route) => route.fulfill({ status: 200, contentType: 'text/html', body: '<p>control</p>' }));
    const plain = await context.newPage();
    await plain.goto('about:blank');
    const [popup] = await Promise.all([context.waitForEvent('page', { timeout: 10000 }), plain.evaluate((u) => void window.open(u), control)]);
    await popup.waitForLoadState('load', { timeout: 10000 }).catch(() => {});
    const seen = pages3.offenders(origins);
    rep.check('monitor-sees-pages', seen.some((u) => u.startsWith(control)), `window.open control recorded as ${JSON.stringify(seen)}`);
  } catch (err) {
    rep.fail('monitor-sees-pages', err.message.split('\n')[0]);
  }
}
if (context) await context.close().catch(() => {});
fs.rmSync(profile2, { recursive: true, force: true });
rep.finish('e2e');
