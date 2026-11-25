// End-to-end run of the real extension (extension/) in Playwright's Chromium, driven through the
// popup DOM contract in .prd/02-architecture.md. Codes are compared with an independent TOTP
// implementation on node:crypto in e2e/reference.mjs (extension/lib is deliberately not imported).
//
//   npm run e2e                          # headed (CI runs it under xvfb-run)
//   E2E_HEADLESS=1 npm run e2e           # new-headless Chromium
//   E2E_ARTIFACTS=<dir> npm run e2e      # screenshots go here (default test-results/)
//   E2E_EXTENSION=<dir> npm run e2e      # another unpacked copy, e.g. an unzipped release
//
// Part 1 is the single-page flow (setup, add, codes, lock, export, browser restart), ending with
// spec A8: delete an account and get it back by importing the backup exported before the
// restart. Part 2 runs in a fresh profile with clipboard access: copy, two pages adding at once,
// lock from another page, idle auto-lock, spec A9 (QR from an image file), copy after the period
// changed. Each part-2 step sets up its own preconditions and reports its own failure, so one
// broken behaviour does not hide the rest. Part 3 is auto-fill (.prd/03-autofill.md, S1-S4) on a
// test copy of the extension, in e2e/autofill.e2e.mjs. Part 4 is passkey unlock
// (.prd/04-passkey-unlock.md) with CDP virtual authenticators, in e2e/passkey.e2e.mjs. Every way
// the vault locks must leave chrome.storage.session holding only the non-secret 16-byte lockGen
// (lock-session-empty:* lines).
// Settings → About shows the manifest's version_name when it has one, else its version: part 1
// checks the extension under test, and after part 2 a copy whose manifest gains a version_name
// (as a packaged preview build carries) is checked the same way (about-version* lines).
// The copy steps write TOTP codes of test secrets to the clipboard (the system one when headed).
//
// Prints `PASS|FAIL <name> <detail>` per assertion and exits 1 on any failure.

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
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
import { runAutofill } from './autofill.e2e.mjs';
import { runPasskey } from './passkey.e2e.mjs';
import { base32ToBytes, decryptRecord, referenceTotp } from './reference.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const POPUP = 'popup/popup.html';
const PASSPHRASE = 'e2e correct horse battery staple';
const WRONG_PASSPHRASE = 'e2e wrong passphrase';
const IDLE_LOCK_MS = 15 * 60 * 1000;
// .prd/02-architecture.md, Round 2, amended by .prd/03-autofill.md ("Cross-unit contract"):
// session storage holds at most these keys; after a lock only lockGen remains.
const SESSION_KEYS_ALLOWED = ['vaultKey', 'lastActiveAt', 'unlockedUntil', 'pendingBind', 'lockGen'];

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

// Part 2 (A9): the account in the QR of e2e/fixtures/qr-otpauth-qrtest.png. Its label is not
// carol@example.net, so the label lookup in checkCode() cannot pick the part-2 Example512 row.
const QR_ACCOUNT = {
  name: 'qr-image',
  uri: 'otpauth://totp/QRTest:carol@qrtest.example?secret=GEZDGNBVGY3TQOJQ&issuer=QRTest',
  issuer: 'QRTest',
  label: 'carol@qrtest.example',
  secret: 'GEZDGNBVGY3TQOJQ',
  algorithm: 'sha1',
  digits: 6,
  period: 30,
};

// QR fixtures, generated once outside the repository with segno 1.6.6 (error level M, scale 4,
// border 4) and pinned here by sha256; a fixture with another hash fails the step.
//   qr-otpauth-qrtest.png  180x180 PNG, 430 bytes,
//     sha256 ed49e703f3c6a33cb7e459ba59fd33c9299328fd0674ed04ea15eba9d53406f9
//     `zbarimg --raw` (0.23.93) -> otpauth://totp/QRTest:carol@qrtest.example?secret=GEZDGNBVGY3TQOJQ&issuer=QRTest
//   qr-otpauth-svgtest.svg a QR as SVG, which the extension must refuse without decoding it,
//     sha256 41452449aa53cfbabdb5a1b0c8ccc02700e39d836ef8137ea5ab46b02eff913a
//     `zbarimg --raw` of a Chromium render -> otpauth://totp/SVGTest:svg@svgtest.example?secret=ON3GOLLGNF4HI5LSMUWWWZLZ&issuer=SVGTest
const FIXTURES = path.join(REPO_ROOT, 'e2e', 'fixtures');
const QR_PNG = {
  file: path.join(FIXTURES, 'qr-otpauth-qrtest.png'),
  mimeType: 'image/png',
  sha256: 'ed49e703f3c6a33cb7e459ba59fd33c9299328fd0674ed04ea15eba9d53406f9',
};
const QR_SVG = {
  file: path.join(FIXTURES, 'qr-otpauth-svgtest.svg'),
  mimeType: 'image/svg+xml',
  sha256: '41452449aa53cfbabdb5a1b0c8ccc02700e39d836ef8137ea5ab46b02eff913a',
  issuer: 'SVGTest',
};

// English UI text the A8 and A9 steps expect (extension/_locales/en/messages.json).
const MSG_EN = {
  imageFormat: 'Use a PNG, JPEG, GIF, WebP or BMP image.',
  imported: (added, duplicates) => `Backup imported. Accounts added: ${added}. Duplicates skipped: ${duplicates}.`,
};

// The UI text the A8 and A9 steps expect in the message catalog chrome.i18n resolves in `page`
// (launch() cannot pin it on macOS, where it follows the system language). With the en catalog
// it is the literal MSG_EN text, so a changed English message fails; with another catalog the
// same messages come from chrome.i18n.getMessage() in the page, composed as the import notice
// is ("<importDone> <addedCount> <skippedCount>", the last only for duplicates).
// → { catalog, imageFormat, imported(added, duplicates) → Promise<string> }
async function expectedText(page) {
  const catalog = await page.evaluate(() => chrome.i18n.getMessage('lang'));
  if (catalog === 'en') return { catalog, imageFormat: MSG_EN.imageFormat, imported: async (a, d) => MSG_EN.imported(a, d) };
  const imageFormat = await page.evaluate(() => chrome.i18n.getMessage('errImageFormat'));
  const imported = (added, duplicates) =>
    page.evaluate(
      ([a, d]) => {
        const parts = [chrome.i18n.getMessage('addedCount', [String(a)])];
        if (d > 0) parts.push(chrome.i18n.getMessage('skippedCount', [String(d)]));
        return `${chrome.i18n.getMessage('importDone')} ${parts.join(' ')}`;
      },
      [added, duplicates],
    );
  return { catalog, imageFormat, imported };
}

// ---- independent TOTP and vault decryption (e2e/reference.mjs, node:crypto only) ---------------

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

// → { accounts: [...] } or { error } for a record opened with PASSPHRASE.
async function openRecord(record) {
  try {
    const data = await decryptRecord(record, PASSPHRASE);
    if (!Array.isArray(data?.accounts)) return { error: `no accounts array in ${Object.keys(data ?? {})}` };
    return { accounts: data.accounts };
  } catch (err) {
    return { error: err.message };
  }
}

// Stored entries for `account` (same issuer, label and secret).
function entriesFor(accounts, account) {
  return (accounts ?? []).filter((a) => a?.issuer === account.issuer && a?.label === account.label && a?.secret === account.secret);
}

function describeEntries(opened) {
  return opened.accounts ? `[${opened.accounts.map((a) => `${a?.issuer}:${a?.label}`).join(', ')}]` : `does not open: ${opened.error}`;
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
  return [...ACCOUNTS, ...CONCURRENT_ACCOUNTS, TYPED, QR_ACCOUNT].flatMap(({ secret }) => {
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

// Writes a pending auto-fill offer into session storage, shaped as the worker writes one after a
// menu fill, so a lock that removed only the v0.1 keys cannot pass a lock-session-empty check.
// `extra` is written in the same call (e.g. a stale lastActiveAt or a wrong vaultKey).
// → the offer read back 300 ms later (null when something removed it meanwhile)
async function seedPendingBind(page, extra = {}) {
  return page.evaluate(async (more) => {
    const accountId = document.querySelector('.account')?.dataset.id || 'e2e-seed';
    await chrome.storage.session.set({ pendingBind: { origin: 'https://seed.test', accountId, at: Date.now() }, ...more });
    await new Promise((resolve) => setTimeout(resolve, 300));
    return (await chrome.storage.session.get('pendingBind')).pendingBind ?? null;
  }, extra);
}

function checkLockedEmpty(rep, name, how, seeded, session) {
  const keys = Object.keys(session);
  const gen = session.lockGen;
  const validGen = typeof gen === 'string' && /^[A-Za-z0-9+/]{22}==$/.test(gen) && Buffer.from(gen, 'base64').length === 16;
  rep.check(name, Boolean(seeded) && keys.length === 1 && keys[0] === 'lockGen' && validGen, `${how}; pendingBind seeded before: ${seeded ? 'yes' : 'NO (check not meaningful)'}; session keys after [${keys}] (only 16-byte lockGen)`);
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

// Imports `file` (a setInputFiles payload) with PASSPHRASE from the settings view and waits for
// the list to show `expectedNotice` in #list-notice. The notice clears itself after 5 s, so every
// text it shows from the submit on is recorded by an observer. Never throws on the outcome.
// → { listed, noticeOk, notices, importError }
async function importViaSettings(page, file, expectedNotice) {
  await page.click('#settings-btn');
  await waitState(page, 'settings');
  // Opening settings resets the import form, so the file and passphrase go in afterwards.
  await page.setInputFiles('#import-file', file);
  await page.fill('#import-pass', PASSPHRASE);
  await page.evaluate(() => {
    const el = document.querySelector('#list-notice');
    globalThis.zauthE2eNoticeObserver?.disconnect();
    globalThis.zauthE2eNotices = [];
    globalThis.zauthE2eNoticeObserver = new MutationObserver(() => {
      const text = el.textContent.trim();
      if (text) globalThis.zauthE2eNotices.push(text);
    });
    globalThis.zauthE2eNoticeObserver.observe(el, { childList: true, characterData: true, subtree: true });
  });
  await page.click('#import-submit');
  const listed = await waitState(page, 'list', 30000).then(
    () => true,
    () => false,
  );
  const noticeOk = await page
    .waitForFunction((want) => globalThis.zauthE2eNotices.includes(want), expectedNotice, { timeout: 10000, polling: 100 })
    .then(
      () => true,
      () => false,
    );
  const seen = await page.evaluate(() => {
    globalThis.zauthE2eNoticeObserver.disconnect();
    return {
      notices: globalThis.zauthE2eNotices,
      importError: document.querySelector('#import-error')?.textContent?.trim() ?? null,
    };
  });
  return { listed, noticeOk, ...seen };
}

// The version Settings → About must show for `manifest`: version_name (a preview build's label,
// which the browser's extensions card shows instead of version) when it is a non-empty string,
// else version.
function aboutVersionOf(manifest) {
  return typeof manifest.version_name === 'string' && manifest.version_name !== '' ? manifest.version_name : manifest.version;
}

// With settings open, #version must be the versionLabel message for `want` in the catalog
// chrome.i18n resolves in `page` (so the check holds in any UI language). Never throws on the
// outcome: an empty #version fails the check with what it showed.
async function checkAboutVersion(rep, page, name, want, source) {
  await page.waitForFunction(() => document.querySelector('#version')?.textContent?.trim(), null, { timeout: 10000 }).catch(() => {});
  const seen = await page.evaluate(
    (w) => ({
      shown: document.querySelector('#version')?.textContent?.trim() ?? null,
      expected: chrome.i18n.getMessage('versionLabel', [w]),
      catalog: chrome.i18n.getMessage('lang'),
    }),
    want,
  );
  rep.check(
    name,
    seen.shown === seen.expected && seen.expected.includes(want),
    `#version ${JSON.stringify(seen.shown)} (expected ${JSON.stringify(seen.expected)}, catalog ${seen.catalog}; ${source})`,
  );
}

// The bytes of a pinned fixture; throws when its sha256 is not the recorded one.
function fixtureBytes(fixture) {
  const bytes = fs.readFileSync(fixture.file);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  if (sha256 !== fixture.sha256) throw new Error(`${path.basename(fixture.file)} sha256 ${sha256}, expected ${fixture.sha256}`);
  return bytes;
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
const opens = async (ctx, p, pagePath = POPUP) => {
  const result = await openExtensionPage(ctx, p, extDir, pagePath);
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
  // getUILanguage() follows the launch's emulated locale; the "lang" message is the catalog
  // chrome.i18n.getMessage() actually resolves (the UI text the A8 and A9 steps read).
  const i18n = await page.evaluate(() => ({ ui: chrome.i18n.getUILanguage(), catalog: chrome.i18n.getMessage('lang') }));
  console.log(`INFO ui-language getUILanguage() ${i18n.ui}, message catalog ${i18n.catalog || '(none)'}`);

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
  const seededManual = await seedPendingBind(page);
  await page.click('#lock-btn');
  await waitState(page, 'locked');
  storage = await readStorage(page);
  rep.check('lock', storage.session.vaultKey === undefined, `body[data-state=locked], session keys [${Object.keys(storage.session)}]`);
  checkLockedEmpty(rep, 'lock-session-empty:manual', 'Lock button', seededManual, storage.session);
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
  const treeManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  await checkAboutVersion(
    rep,
    page,
    'about-version',
    aboutVersionOf(treeManifest),
    `extension under test: manifest version ${JSON.stringify(treeManifest.version)}, version_name ${JSON.stringify(treeManifest.version_name ?? null)}`,
  );
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

  // A8: the backup exported in the previous browser session -> delete an account in the list
  // -> import that backup in settings: the account is back with the same code, and importing
  // the same file again only skips duplicates. Last in part 1, so nothing above depends on it.
  step = 'i-a8-backup';
  const a8Console = watchConsole(page);
  const removed = ACCOUNTS[0];
  const kept = ACCOUNTS[1];
  const backupFile = { name: download.suggestedFilename(), mimeType: 'application/json', buffer: Buffer.from(exported, 'utf8') };
  const ui = await expectedText(page);
  const backup = await openRecord(found?.record);
  const backupEntry = entriesFor(backup.accounts, removed)[0];
  rep.check(
    'a8-export-decrypts',
    Boolean(backupEntry) && entriesFor(backup.accounts, kept).length === 1,
    `exported record, opened here with the passphrase (node:crypto PBKDF2-SHA-256 + AES-256-GCM): ${describeEntries(backup)}`,
  );

  step = 'j-a8-delete';
  await page.click('#edit-btn');
  const removedRow = page.locator('.account', { hasText: removed.label });
  await removedRow.locator('.delete').click();
  // Nothing slow before the second click: the armed state times out after 4 s.
  const armed = await removedRow.evaluate((el) => el.classList.contains('confirming'));
  const armedCount = (await rows(page)).rows.length;
  await removedRow.locator('.delete').click();
  rep.check('a8-delete-armed', armed && armedCount === 2, `first click on ${removed.label}'s .delete: .confirming ${armed}, ${armedCount} rows (still 2)`);
  const gone = await page
    .waitForFunction((label) => !Array.from(document.querySelectorAll('.account .label'), (el) => el.textContent).some((t) => t.includes(label)), removed.label, { timeout: 15000 })
    .then(
      () => true,
      () => false,
    );
  const afterDelete = await rows(page);
  rep.check(
    'a8-delete-row',
    gone && afterDelete.rows.length === 1 && afterDelete.rows[0].label === kept.label,
    `rows after the second click: [${afterDelete.rows.map((r) => `${r.issuer}:${r.label}`).join(', ')}] (expected only ${kept.issuer}:${kept.label})`,
  );
  await page.click('#edit-btn');
  const storedAfterDelete = await openRecord((await readStorage(page)).local.vault);
  rep.check(
    'a8-delete-stored',
    Boolean(storedAfterDelete.accounts) && entriesFor(storedAfterDelete.accounts, removed).length === 0 && entriesFor(storedAfterDelete.accounts, kept).length === 1,
    `chrome.storage.local.vault, opened here: ${describeEntries(storedAfterDelete)} (no ${removed.label})`,
  );

  step = 'k-a8-import';
  const wantImported = await ui.imported(1, 1);
  const imported = await importViaSettings(page, backupFile, wantImported);
  const afterImport = await rows(page);
  const back = afterImport.rows.filter((r) => r.issuer === removed.issuer && r.label === removed.label);
  rep.check(
    'a8-import',
    imported.listed && imported.noticeOk && afterImport.rows.length === 2 && back.length === 1,
    `${backupFile.name} with the passphrase: list ${imported.listed}, #list-notice showed ${JSON.stringify(imported.notices)} (expected "${wantImported}", catalog ${ui.catalog}), #import-error "${imported.importError}", rows [${afterImport.rows.map((r) => `${r.issuer}:${r.label}`).join(', ')}]`,
  );
  await checkCode(rep, page, removed, ':after-import');
  const storedAfterImport = await openRecord((await readStorage(page)).local.vault);
  const restored = entriesFor(storedAfterImport.accounts, removed);
  const sameFields = (a, b) => Boolean(a && b) && ['issuer', 'label', 'secret', 'algorithm', 'digits', 'period'].every((k) => a[k] === b[k]);
  rep.check(
    'a8-import-stored',
    restored.length === 1 && sameFields(restored[0], backupEntry) && entriesFor(storedAfterImport.accounts, kept).length === 1,
    `chrome.storage.local.vault, opened here: ${describeEntries(storedAfterImport)}; ${removed.label} ${restored.length === 1 ? `${restored[0].algorithm}/${restored[0].digits}/${restored[0].period}s, id ${restored[0].id} (backup ${backupEntry?.id})` : `${restored.length} entries`}`,
  );

  step = 'l-a8-reimport';
  const wantAgain = await ui.imported(0, 2);
  const again = await importViaSettings(page, backupFile, wantAgain);
  const afterAgain = await rows(page);
  const copies = afterAgain.rows.filter((r) => r.issuer === removed.issuer && r.label === removed.label).length;
  rep.check(
    'a8-reimport-duplicate',
    again.listed && again.noticeOk && afterAgain.rows.length === 2 && copies === 1,
    `same file again: list ${again.listed}, #list-notice showed ${JSON.stringify(again.notices)} (expected "${wantAgain}"), #import-error "${again.importError}", ${afterAgain.rows.length} rows, ${copies} of ${removed.label}`,
  );
  checkStorage(rep, 'storage-ciphertext-only:after-import', await readStorage(page));
  rep.check('no-egress:after-import', net2.egress().length === 0, `remote requests: ${JSON.stringify(net2.egress())}`);
  const a8Errors = a8Console.filter((l) => l.startsWith('pageerror:'));
  rep.check('no-uncaught-errors:after-import', a8Errors.length === 0, a8Errors.join(' | ') || 'none');
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

async function newPopupPage(ctx, pagePath = POPUP) {
  const p = await ctx.newPage();
  livePages.add(p);
  p.on('close', () => livePages.delete(p));
  consoles.push(watchConsole(p));
  await opens(ctx, p, pagePath);
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
    const seeded = await seedPendingBind(pageA);
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
    const sessionNow = (await readStorage(pageA)).session;
    const session = Object.keys(sessionNow);
    rep.check('cross-page-lock', reached && b.state === 'locked', `page B state ${b.state} after page A locked; session keys [${session}]`);
    checkLockedEmpty(rep, 'lock-session-empty:cross-page', 'lock from page A, seen by page B', seeded, sessionNow);
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
    const stale = Date.now() - (IDLE_LOCK_MS + 60 * 1000);
    const seeded = await seedPendingBind(pageA, { lastActiveAt: stale });
    await pageA.reload();
    const state = await waitState(pageA, 'locked', 10000).then(
      () => 'locked',
      async () => stateOf(pageA),
    );
    const sessionNow = (await readStorage(pageA)).session;
    const session = Object.keys(sessionNow);
    rep.check(
      'idle-auto-lock',
      state === 'locked',
      `lastActiveAt set to ${new Date(stale).toISOString()} (16 min ago), reload -> state ${state}; session keys [${session}]`,
    );
    checkLockedEmpty(rep, 'lock-session-empty:idle-page', 'idle session found by an opening page', seeded, sessionNow);
  });

  // The idle check of a page that stays open (session.lockIfIdle(), run every 30 s and when the
  // page becomes visible): the visibilitychange is dispatched here instead of waited for.
  await stepRun('lock-if-idle', async () => {
    if ((await stateOf(pageA)) === 'locked') await unlock(pageA);
    await waitState(pageA, 'list', 10000);
    await pageA.bringToFront();
    const seeded = await seedPendingBind(pageA, { lastActiveAt: Date.now() - (IDLE_LOCK_MS + 60 * 1000) });
    const visible = await pageA.evaluate(() => {
      document.dispatchEvent(new Event('visibilitychange'));
      return document.visibilityState;
    });
    const state = await waitState(pageA, 'locked', 10000).then(
      () => 'locked',
      async () => stateOf(pageA),
    );
    const sessionNow = (await readStorage(pageA)).session;
    rep.check('lock-if-idle', state === 'locked', `open page, lastActiveAt 16 min ago, visibilitychange (visibilityState ${visible}) -> state ${state}`);
    checkLockedEmpty(rep, 'lock-session-empty:lock-if-idle', 'idle session found by an open page', seeded, sessionNow);
  });

  // Unlock time (v0.4): the list view shows the lock time; Extend needs two red confirmations,
  // keeps the vault unlocked past the idle limit, and every lock removes it.
  await stepRun('unlock-time', async () => {
    if ((await stateOf(pageA)) === 'locked') await unlock(pageA);
    await waitState(pageA, 'list', 10000);
    await pageA.waitForFunction(() => !document.querySelector('#unlock-bar').hidden && document.querySelector('#unlock-left').textContent !== '', null, { timeout: 15000 });
    const shown = await pageA.evaluate(() => document.querySelector('#unlock-left').textContent);
    rep.check('unlock-time-shown', /(14|15):\d\d/.test(shown), `list view shows "${shown}" (15 minutes from the open)`);
    const alarmState = () => pageA.evaluate(() => {
      const alarm = document.querySelector('#extend-alarm');
      return {
        open: !alarm.hidden,
        step: alarm.dataset.step ?? '',
        role: alarm.getAttribute('role'),
        titleColor: getComputedStyle(alarm.querySelector('.alarm-title')).color,
        okColor: getComputedStyle(alarm.querySelector('.alarm-ok')).backgroundColor,
      };
    });
    const until = async () => (await readStorage(pageA)).session.unlockedUntil;
    await pageA.click('#extend-btn');
    await pageA.click('.extend-choice[data-ms="86400000"]');
    const first = await alarmState();
    await pageA.click('#extend-alarm .alarm-cancel');
    const afterCancel = { alarm: await alarmState(), until: await until() };
    rep.check(
      'extend-cancel-first',
      first.open && first.step === '1' && first.role === 'alertdialog' && !afterCancel.alarm.open && afterCancel.until === undefined,
      `step 1 shown (${JSON.stringify(first)}), Cancel -> alarm open ${afterCancel.alarm.open}, unlockedUntil ${afterCancel.until}`,
    );
    rep.check('extend-alarm-red', first.titleColor === 'rgb(194, 0, 27)' && first.okColor === 'rgb(194, 0, 27)', `title ${first.titleColor}, button ${first.okColor} (red #c2001b)`);
    await pageA.click('.extend-choice[data-ms="86400000"]');
    // A double click on the red button cannot pass both steps: the second step's button is armed late.
    await pageA.dblclick('#extend-alarm .alarm-ok');
    const second = { alarm: await alarmState(), until: await until() };
    await pageA.click('#extend-alarm .alarm-cancel');
    const afterSecondCancel = { alarm: await alarmState(), until: await until() };
    rep.check(
      'extend-cancel-second',
      second.alarm.open && second.alarm.step === '2' && second.until === undefined && !afterSecondCancel.alarm.open && afterSecondCancel.until === undefined,
      `double click on step 1 -> step ${second.alarm.step}, unlockedUntil ${second.until}; Cancel -> unlockedUntil ${afterSecondCancel.until}`,
    );
    await pageA.click('.extend-choice[data-ms="86400000"]');
    await pageA.waitForTimeout(700);
    await pageA.click('#extend-alarm .alarm-ok');
    await pageA.waitForFunction(() => document.querySelector('#extend-alarm').dataset.step === '2');
    await pageA.waitForTimeout(700);
    const t0 = Date.now();
    await pageA.click('#extend-alarm .alarm-ok');
    await pageA.waitForFunction(() => document.querySelector('#unlock-bar').classList.contains('extended'), null, { timeout: 5000 });
    const stored = await until();
    rep.check(
      'extend-24h',
      Number.isFinite(stored) && Math.abs(stored - (t0 + 24 * 60 * 60 * 1000)) < 10000,
      `two confirmations -> unlockedUntil ${stored ? new Date(stored).toISOString() : stored} (24 h from the click); bar "${await pageA.evaluate(() => document.querySelector('#unlock-left').textContent)}"`,
    );
    // Past the idle limit, inside the extension: an open page's idle check and a reload keep it.
    await pageA.evaluate((t) => chrome.storage.session.set({ lastActiveAt: t }), Date.now() - (IDLE_LOCK_MS + 60 * 1000));
    await pageA.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
    await pageA.waitForTimeout(1500);
    const kept = await stateOf(pageA);
    await pageA.reload();
    const reloaded = await waitState(pageA, 'list', 10000).then(() => 'list', async () => stateOf(pageA));
    rep.check('extend-outlasts-idle', kept === 'list' && reloaded === 'list', `lastActiveAt 16 min ago with the extension: idle check -> ${kept}, reload -> ${reloaded}`);
    checkStorageKeys(rep, 'storage-keys:extended', await readStorage(pageA));
    const seeded = await seedPendingBind(pageA);
    await pageA.click('#lock-btn');
    await waitState(pageA, 'locked', 10000);
    checkLockedEmpty(rep, 'lock-session-empty:extended', 'manual lock during a 24 h extension', seeded, (await readStorage(pageA)).session);
  });

  // A stored key that does not open the vault is dropped when a page finds it, with everything
  // else in session storage.
  await stepRun('wrong-session-key', async () => {
    if ((await stateOf(pageA)) === 'locked') await unlock(pageA);
    await waitState(pageA, 'list', 10000);
    const wrongKey = Buffer.alloc(32, 7).toString('base64');
    // Written in one call with the offer; whichever context reads the key next (the worker
    // reacts to the write) drops all three, so the offer may already be gone 300 ms later.
    const readBack = await seedPendingBind(pageA, { vaultKey: { key: wrongKey, v: 1 }, lastActiveAt: Date.now() });
    await pageA.reload();
    const state = await waitState(pageA, 'locked', 10000).then(
      () => 'locked',
      async () => stateOf(pageA),
    );
    const sessionNow = (await readStorage(pageA)).session;
    rep.check('wrong-session-key-locks', state === 'locked', `session vaultKey replaced by 32 bytes that do not open the vault, reload -> state ${state}`);
    checkLockedEmpty(
      rep,
      'lock-session-empty:wrong-key',
      `wrong key written together with a pendingBind and dropped by ${readBack ? 'the opening page' : 'the worker before the reload (offer gone 300 ms after the write)'}`,
      true,
      sessionNow,
    );
  });

  // A9, decode path: an image with an otpauth QR, chosen in the full-tab view the "QR from an
  // image" button opens (popup.html#add-file), adds the account named by the QR; an SVG is
  // refused before any decoder runs. "Scan QR on this page" needs the activeTab grant that only
  // a real click on the toolbar icon gives, which automation cannot make. That capture path is
  // covered by this decode-path test plus the chrome.tabs.captureVisibleTab() call in
  // popup/add.js (scanTab), which hands its image to the same decodeQR(); the toolbar grant
  // itself is a manual check.
  await stepRun('qr-image', async () => {
    const png = fixtureBytes(QR_PNG);
    const svg = fixtureBytes(QR_SVG);
    const pageQ = await newPopupPage(context, `${POPUP}#add-file`);
    try {
      await pageQ.waitForSelector('body[data-state="locked"], body[data-state="add"]', { timeout: 10000 });
      // The idle lock above left the session locked; unlocking continues to the add view.
      if ((await stateOf(pageQ)) === 'locked') {
        await pageQ.fill('#unlock-pass', PASSPHRASE);
        await pageQ.click('#unlock-submit');
      }
      await waitState(pageQ, 'add', 30000);
      const ui = await expectedText(pageQ);
      const fileMode = await pageQ.evaluate(() => document.body.classList.contains('file-mode'));
      await pageQ.setInputFiles('#scan-file-input', { name: path.basename(QR_PNG.file), mimeType: QR_PNG.mimeType, buffer: png });
      const listed = await waitState(pageQ, 'list', 15000).then(
        () => true,
        () => false,
      );
      const addError = await pageQ.evaluate(() => document.querySelector('#add-error')?.textContent?.trim() ?? null);
      const snap = await rows(pageQ);
      const match = snap.rows.filter((r) => r.issuer === QR_ACCOUNT.issuer && r.label === QR_ACCOUNT.label);
      rep.check(
        'qr-image-add',
        fileMode && listed && match.length === 1,
        `${path.basename(QR_PNG.file)} (sha256 ${QR_PNG.sha256.slice(0, 12)}…) on #scan-file-input of ${POPUP}#add-file (file mode ${fileMode}): list ${listed}, #add-error "${addError}", rows [${snap.rows.map((r) => `${r.issuer}:${r.label}`).join(', ')}] (expected one ${QR_ACCOUNT.issuer}:${QR_ACCOUNT.label})`,
      );
      await checkCode(rep, pageQ, QR_ACCOUNT, '');
      checkStorage(rep, 'storage-ciphertext-only:after-qr', await readStorage(pageQ));

      // The SVG check starts from the list whatever the PNG did (a refused PNG stays in add).
      if ((await stateOf(pageQ)) === 'add') await pageQ.click('#add-cancel');
      await waitState(pageQ, 'list', 10000);
      const countBefore = (await rows(pageQ)).rows.length;
      await pageQ.click('#add-btn');
      await waitState(pageQ, 'add', 10000);
      await pageQ.setInputFiles('#scan-file-input', { name: path.basename(QR_SVG.file), mimeType: QR_SVG.mimeType, buffer: svg });
      const svgError = await pageQ
        .waitForFunction(() => document.querySelector('#add-error')?.textContent?.trim() || false, null, { timeout: 10000, polling: 100 })
        .then(
          (handle) => handle.jsonValue(),
          () => '',
        );
      const svgState = await stateOf(pageQ);
      if (svgState === 'add') await pageQ.click('#add-cancel');
      await waitState(pageQ, 'list', 10000);
      const after = (await rows(pageQ)).rows;
      rep.check(
        'qr-image-svg-refused',
        svgError === ui.imageFormat && svgState === 'add' && after.length === countBefore && !after.some((r) => r.issuer === QR_SVG.issuer),
        `${path.basename(QR_SVG.file)} (${QR_SVG.mimeType}): #add-error "${svgError}" (expected "${ui.imageFormat}", catalog ${ui.catalog}), state ${svgState}; then ${after.length} rows (before ${countBefore}), ${QR_SVG.issuer} row ${after.some((r) => r.issuer === QR_SVG.issuer)}`,
      );
    } catch (err) {
      // stepRun describes the pages still open; this one is closed below.
      err.message = `${err.message.split('\n')[0]} [QR page: ${await describePage(pageQ)}]`;
      throw err;
    } finally {
      await pageQ.close();
    }
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

// ---- part 3: auto-fill on a test copy (e2e/autofill.e2e.mjs) ----------------------------------

try {
  const autofill = await runAutofill({ rep, extensionDir: extDir });
  if (autofill.pages) {
    pageWatchers.push(autofill.pages);
    ownOrigins.add(autofill.ownOrigin);
  }
} catch (err) {
  rep.fail('part3', `${err.message.split('\n')[0]}`);
}

// Every page seen in every launch, including any the extension opened itself (its popup and
// #bind/#unlock windows), stayed on the extension's own pages or about:blank; part 3's own test
// pages may also show the routed test origins they were opened on.
const origins = ownOrigins.size ? [...ownOrigins] : [`chrome-extension://${computeExtensionId(extDir)}`];
const offenders = pageWatchers.flatMap((w) => w.offenders(origins));
const pageCount = pageWatchers.reduce((n, w) => n + w.count(), 0);
rep.check(
  'no-navigation',
  pageWatchers.length > 0 && offenders.length === 0,
  `${pageCount} pages in ${pageWatchers.length} launches; URLs outside ${origins.join(', ')}, about:blank and part 3's routed test pages: ${JSON.stringify(offenders)}`,
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

// ---- About version of a preview build ---------------------------------------------------------
// A packaged preview build's manifest carries a version_name (e.g. "0.3.0-pre.<date>.<time>
// (<commit>)"), which the browser's extensions card shows instead of version. Settings → About
// must show the same string: checked on a copy of the extension under test, built in
// os.tmpdir(), whose manifest gains VERSION_NAME and nothing else.
const VERSION_NAME = '9.9.9-e2e (abc1234)';

async function checkVersionNameCopy() {
  let copyDir;
  let profile3;
  let ctx;
  let p;
  try {
    copyDir = realExtensionDir(fs.mkdtempSync(path.join(os.tmpdir(), 'zauth-version-name-ext-')));
    fs.cpSync(extDir, copyDir, { recursive: true });
    const copyManifestPath = path.join(copyDir, 'manifest.json');
    const copyManifest = { ...JSON.parse(fs.readFileSync(copyManifestPath, 'utf8')), version_name: VERSION_NAME };
    fs.writeFileSync(copyManifestPath, JSON.stringify(copyManifest, null, 2));
    profile3 = freshProfileDir();
    ctx = await launch(copyDir, profile3);
    p = await ctx.newPage();
    await openExtensionPage(ctx, p, copyDir, POPUP);
    await waitState(p, 'setup');
    await p.fill('#setup-pass', PASSPHRASE);
    await p.fill('#setup-pass2', PASSPHRASE);
    await p.click('#setup-submit');
    await waitState(p, 'list');
    await p.click('#settings-btn');
    await waitState(p, 'settings');
    await checkAboutVersion(
      rep,
      p,
      'about-version-name',
      VERSION_NAME,
      `copy with manifest version ${JSON.stringify(copyManifest.version)}, version_name ${JSON.stringify(VERSION_NAME)}`,
    );
  } catch (err) {
    rep.fail('about-version-name', `${err.message.split('\n')[0]} [${p ? await describePage(p) : 'no page'}]`);
  } finally {
    if (ctx) await ctx.close().catch(() => {});
    if (profile3) fs.rmSync(profile3, { recursive: true, force: true });
    if (copyDir) fs.rmSync(copyDir, { recursive: true, force: true });
  }
}

await checkVersionNameCopy();
await runPasskey(rep);
rep.finish('e2e');
