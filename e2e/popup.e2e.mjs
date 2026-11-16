// End-to-end run of the real extension (extension/) in Playwright's Chromium, driven through the
// popup DOM contract in .prd/02-architecture.md. Codes are compared with an independent TOTP
// implementation written below on node:crypto (extension/lib is deliberately not imported).
//
//   npm run e2e                          # headed (CI runs it under xvfb-run)
//   E2E_HEADLESS=1 npm run e2e           # new-headless Chromium
//   E2E_ARTIFACTS=<dir> npm run e2e      # screenshots go here (default test-results/)
//   E2E_EXTENSION=<dir> npm run e2e      # another unpacked copy, e.g. an unzipped release
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
} from './harness.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const POPUP = 'popup/popup.html';
const PASSPHRASE = 'e2e correct horse battery staple';
const WRONG_PASSPHRASE = 'e2e wrong passphrase';

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

async function readStorage(page) {
  return page.evaluate(async () => ({
    local: await chrome.storage.local.get(null),
    sync: await chrome.storage.sync.get(null),
    session: await chrome.storage.session.get(null),
  }));
}

// Every encoding of each secret that plaintext storage could plausibly use.
function secretForms() {
  return ACCOUNTS.flatMap(({ secret }) => {
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
ensureArtifactsDir();
console.log(`INFO mode ${HEADLESS ? "headless (channel 'chromium')" : 'headed'}; computed id ${computeExtensionId(extDir)}`);
checkReference(rep);

let context;
let page;
let step = 'launch';
try {
  context = await launch(extDir, profile);
  const net = watchNetwork(context);
  page = await context.newPage();
  const pageConsole = watchConsole(page);
  const opened = await openExtensionPage(context, page, extDir, POPUP);
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
  page = await context.newPage();
  await openExtensionPage(context, page, extDir, POPUP);
  await waitState(page, 'locked');
  rep.pass('session-restart-locked', 'new browser session opens locked');
  await page.fill('#unlock-pass', PASSPHRASE);
  await page.click('#unlock-submit');
  await waitState(page, 'list');
  await waitForRows(page, 2);
  rep.pass('session-restart-unlock', '2 accounts after unlock');
  rep.check('no-egress:restart', net2.egress().length === 0, `remote requests: ${JSON.stringify(net2.egress())}`);
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
  fs.rmSync(profile, { recursive: true, force: true });
}
rep.finish('e2e');
