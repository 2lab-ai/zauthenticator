// Passkey unlock (.prd/04-passkey-unlock.md, A1-A5) on the real extension, with real WebAuthn
// ceremonies against Chromium's CDP virtual authenticators:
//   internal-prf     ctap2 internal authenticator with native PRF (prf bytes on create and get)
//   usb-hmac-secret  ctap2 usb authenticator with hmac-secret but not hmac-secret-mc (prf bytes
//                    on get only)
// Nothing about the ceremony is mocked. The only test hook wraps navigator.credentials in the
// ceremony page: it counts calls, records the PRF output of the real assertion (so the
// independent reference in e2e/reference.mjs can check HKDF, AAD and key wrapping), and for the
// race steps holds the real assertion until another page has changed or locked the vault.
//
//   E2E_HEADLESS=1 node e2e/passkey.e2e.mjs     # alone; npm run e2e runs it after popup + autofill
//   E2E_PASSKEY_VARIANTS=internal-prf ...        # only the named variants (comma-separated)
//
// CDP limits (not production behaviour): a virtual authenticator belongs to one tab, so the
// #unlock view runs in the tab that enrolled (reloaded as popup.html#unlock; it still closes
// itself after an unlock), and the #unlock window the toolbar popup opens has no authenticator
// with the credential (the toolbar popup itself is reached headless only: chrome.action.openPopup()
// finds no active window in a headed run); WebAuthn.Credential has no field for the hmac/PRF secret,
// so a credential exported with getCredentials and added back after a browser restart returns no
// PRF (the stored slot is checked across the restart with the PRF of the real ceremony instead).
// Phone over hybrid (QR + Bluetooth), Touch ID and security keys with a PIN are not reachable
// from CDP: owner hand test (A6).

import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ARTIFACTS,
  HEADLESS,
  createReporter,
  ensureArtifactsDir,
  extensionWorker,
  freshProfileDir,
  launch,
  openExtensionPage,
  realExtensionDir,
  watchNetwork,
  watchPages,
} from './harness.mjs';
import { base32ToBytes, decryptRecord, encryptRecordV2, openDataWithDek, referenceTotp } from './reference.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const POPUP = 'popup/popup.html';
const PASSPHRASE = 'e2e passkey correct horse battery';
const WRONG_PASSPHRASE = 'e2e passkey wrong passphrase';
const LABEL = 'Virtual key';
const IDLE_PAST_MS = 16 * 60 * 1000;
const URIS = [
  'otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example',
  'otpauth://totp/RaceEdit:race@example.com?secret=PJQXK5DIFVSTEZJNMNQXE33MFUYDAMBR&issuer=RaceEdit',
  'otpauth://totp/Sealed:seal@example.org?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Sealed',
  'otpauth://totp/UnlockRace:unlock@example.net?secret=PJQXK5DIFVSTEZJNMRQXMZJNGAYDAMBS&issuer=UnlockRace',
];
const BASE_AUTHENTICATOR = {
  protocol: 'ctap2',
  ctap2Version: 'ctap2_1',
  transport: 'internal',
  hasResidentKey: true,
  hasUserVerification: true,
  isUserVerified: true,
  automaticPresenceSimulation: true,
};
const VARIANTS = [
  { name: 'internal-prf', options: { transport: 'internal', hasPrf: true }, prfOnCreate: true, full: true },
  { name: 'usb-hmac-secret', options: { transport: 'usb', hasHmacSecret: true }, prfOnCreate: false, full: false },
];
// .prd/04-passkey-unlock.md "Session key" + .prd/03-autofill.md.
const SESSION_KEYS_ALLOWED = ['vaultKey', 'lastActiveAt', 'unlockedUntil', 'pendingBind', 'autofillServed', 'lockGen'];

const json = (value) => JSON.stringify(value);
const hasPasskey = (record) => Array.isArray(record?.slots) && record.slots.some((s) => s.type === 'passkey');
const passkeySlot = (record) => record?.slots?.find((s) => s.type === 'passkey') ?? null;
const validLockGen = (gen) => typeof gen === 'string' && /^[A-Za-z0-9+/]{22}==$/.test(gen) && Buffer.from(gen, 'base64').length === 16;

// A v1 backup record built here on node:crypto (the documented v1 format), for the import race.
function sealV1(data, passphrase, iterations = 1000) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const kdf = { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: salt.toString('base64') };
  const key = pbkdf2Sync(Buffer.from(passphrase.normalize('NFC'), 'utf8'), salt, iterations, 32, 'sha256');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(json({ v: 1, kdf }), 'utf8'));
  const ct = Buffer.concat([cipher.update(json(data), 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return { v: 1, kdf, iv: iv.toString('base64'), ct: ct.toString('base64') };
}

async function opens(record, passphrase, prf = null) {
  try {
    return { data: await decryptRecord(record, passphrase, prf) };
  } catch (err) {
    return { error: err.message };
  }
}

// ---- page helpers -----------------------------------------------------------------------------

const state = (page, value, timeout = 30000) => page.waitForSelector(`body[data-state="${value}"]`, { timeout });
const stateOf = (page) => page.evaluate(() => document.body?.dataset.state ?? '?').catch((err) => `unavailable (${err.message.split('\n')[0]})`);
const vault = (page) => page.evaluate(async () => (await chrome.storage.local.get('vault')).vault ?? null);
const session = (page) => page.evaluate(() => chrome.storage.session.get(null));
const rowCount = (page) => page.locator('.account').count();
const message = (page, key) => page.evaluate((k) => chrome.i18n.getMessage(k), key);

async function addUri(page, uri) {
  const before = await rowCount(page);
  await page.click('#add-btn');
  await state(page, 'add');
  await page.fill('#add-uri', uri);
  await page.click('#add-uri-submit');
  await state(page, 'list');
  await page.waitForFunction((n) => document.querySelectorAll('.account').length === n, before + 1, { timeout: 15000 });
}

async function passphraseUnlock(page) {
  await state(page, 'locked');
  await page.fill('#unlock-pass', PASSPHRASE);
  await page.click('#unlock-submit');
  await state(page, 'list');
}

async function lock(page) {
  await page.click('#lock-btn');
  await state(page, 'locked');
}

async function importRecord(page, record, passphrase = PASSPHRASE) {
  await page.click('#settings-btn');
  await state(page, 'settings');
  await page.setInputFiles('#import-file', { name: 'backup.json', mimeType: 'application/json', buffer: Buffer.from(json(record)) });
  await page.fill('#import-pass', passphrase);
  await page.click('#import-submit');
  try {
    await state(page, 'list');
  } catch (err) {
    const shown = await page.locator('#import-error').textContent().catch(() => '?');
    throw new Error(`import did not return to the list (#import-error ${json(shown)}): ${err.message.split('\n')[0]}`);
  }
}

// The code `page` shows on the row labelled `label`, against the reference TOTP of the base32
// `secret` at the page's clock, read away from a period boundary. → { ok, detail }
async function rowCode(page, label, secret, params) {
  const key = base32ToBytes(secret);
  const periodMs = params.period * 1000;
  let last = 'no reading';
  for (let attempt = 1; attempt <= 6; attempt += 1) {
    const snap = await page.evaluate((want) => {
      const row = Array.from(document.querySelectorAll('.account')).find((r) => r.querySelector('.label')?.textContent?.includes(want));
      return { now: Date.now(), code: row?.querySelector('.code')?.dataset.code ?? null, issuer: row?.querySelector('.issuer')?.textContent?.trim() ?? null };
    }, label);
    const into = snap.now % periodMs;
    if (snap.code === null) {
      last = `no row labelled ${json(label)}`;
    } else if (into < 1000 || periodMs - into < 1000) {
      last = 'too close to a period boundary';
    } else {
      const expected = referenceTotp(key, snap.now, params);
      if (snap.code === expected) return { ok: true, detail: `row ${json(`${snap.issuer} ${label}`)} shows ${snap.code} = reference` };
      last = `row shows ${json(snap.code)}, reference ${expected}`;
    }
    await page.waitForTimeout(1200);
  }
  return { ok: false, detail: last };
}

// Adds a CDP virtual authenticator to `page`'s tab (and `credentials`, exported earlier).
// Chromium's virtual ctap2 device stores 3 resident credentials, then answers KEY_STORE_FULL (a
// NotAllowedError, "cancelled" in the UI): the race steps delete each orphaned passkey as a user
// would (clear()) before the next enrollment.
async function authenticator(page, options, credentials = []) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { ...BASE_AUTHENTICATOR, ...options } });
  for (const credential of credentials) await cdp.send('WebAuthn.addCredential', { authenticatorId, credential });
  return {
    credentials: async () => (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials,
    clear: () => cdp.send('WebAuthn.clearCredentials', { authenticatorId }),
  };
}

// The test hook (see the header): wraps navigator.credentials in the current document. The real
// create()/get() run; the wrapper only counts, records the PRF output and can hold an assertion.
async function instrument(page) {
  await page.evaluate(() => {
    if (globalThis.zauthE2ePasskey) return;
    const container = navigator.credentials;
    const realCreate = container.create.bind(container);
    const realGet = container.get.bind(container);
    const prfOf = (credential) => {
      const value = credential?.getClientExtensionResults?.()?.prf?.results?.first;
      if (!value) return null;
      const view = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
      return Array.from(view);
    };
    const hook = { creates: 0, gets: 0, createPrf: null, getPrf: null, hold: false, held: false, release: null };
    globalThis.zauthE2ePasskey = hook;
    container.create = async (options) => {
      hook.creates += 1;
      const credential = await realCreate(options);
      hook.createPrf = prfOf(credential);
      return credential;
    };
    container.get = async (options) => {
      hook.gets += 1;
      const credential = await realGet(options);
      hook.getPrf = prfOf(credential);
      // Also outside the page (a window may close itself right after using the result).
      console.debug(`zauth-e2e:get prf=${hook.getPrf ? hook.getPrf.length : 0}`);
      if (hook.hold) {
        hook.held = true;
        await new Promise((resolve) => {
          hook.release = resolve;
        });
        hook.held = false;
      }
      return credential;
    };
  });
}

// Counts the real get() calls that returned a 32-byte PRF in `page` from now on, read from the
// hook's console line, so it works after the page closed. → () => count
function countRealGets(page) {
  let count = 0;
  page.on('console', (m) => {
    if (m.text() === 'zauth-e2e:get prf=32') count += 1;
  });
  return () => count;
}

const hookState = (page) => page.evaluate(() => {
  const { creates, gets, createPrf, getPrf, held } = globalThis.zauthE2ePasskey;
  return { creates, gets, createPrf, getPrf, held };
});

async function holdNextAssertion(page) {
  await page.evaluate(() => {
    globalThis.zauthE2ePasskey.hold = true;
  });
}

async function waitHeld(page) {
  await page.waitForFunction(() => globalThis.zauthE2ePasskey?.held === true, null, { timeout: 30000 });
}

// Releases a held assertion. → false when the page is gone.
async function release(page) {
  if (page.isClosed()) return false;
  return page
    .evaluate(() => {
      const hook = globalThis.zauthE2ePasskey;
      hook.hold = false;
      hook.release?.();
      return true;
    })
    .catch(() => false);
}

// Waits until the ceremony button is enabled again and the error line shows text. → that text
async function settledError(page, errorSel, buttonSel, timeout = 30000) {
  await page.waitForFunction(
    ([e, b]) => !document.querySelector(b).disabled && document.querySelector(e).textContent.trim() !== '',
    [errorSel, buttonSel],
    { timeout },
  );
  return (await page.locator(errorSel).textContent()).trim();
}

// A ceremony needs the browser's focus (Chromium refuses WebAuthn in a background tab): the tab
// comes to the front before the click that starts one.
async function ceremonyClick(page, selector) {
  await page.bringToFront();
  await page.click(selector);
}

// What a page shows when a step dies: state, the passkey lines and the test hook's counters.
async function describe(page) {
  if (!page) return 'none';
  if (page.isClosed()) return 'closed';
  return page
    .evaluate(() => {
      const lines = ['#passkey-status', '#passkey-error', '#unlock-passkey-status', '#unlock-passkey-error', '#unlock-error', '#list-notice']
        .map((sel) => [sel, document.querySelector(sel)?.textContent?.trim()])
        .filter(([, text]) => text);
      const hook = globalThis.zauthE2ePasskey;
      return `state=${document.body?.dataset.state} focus=${document.hasFocus()} ${JSON.stringify(Object.fromEntries(lines))} hook=${hook ? JSON.stringify({ creates: hook.creates, gets: hook.gets, held: hook.held }) : 'none'}`;
    })
    .catch((err) => `unavailable (${err.message.split('\n')[0]})`);
}

async function screenshots(page, name, fullPage = false) {
  const files = [];
  for (const colorScheme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme });
    // popup.css fades button colours over 0.15 s: let the new scheme settle before the capture.
    await page.waitForTimeout(400);
    const file = path.join(ARTIFACTS, `passkey-${name}-${colorScheme}.png`);
    await page.screenshot({ path: file, fullPage });
    files.push(file);
  }
  await page.emulateMedia({ colorScheme: null });
  return files;
}

// ---- one authenticator variant ----------------------------------------------------------------

async function runVariant(rep, extDir, variant) {
  const tag = (name) => `passkey-${variant.name}:${name}`;
  const profile = freshProfileDir('zauth-passkey-e2e-');
  const errors = [];
  const watchers = [];
  let context = null;
  let id = null;

  const start = async () => {
    context = await launch(extDir, profile);
    watchers.push({ net: watchNetwork(context), pages: watchPages(context) });
    const track = (p) => p.on('pageerror', (err) => errors.push(`${p.url()}: ${err.message}`));
    context.pages().forEach(track);
    context.on('page', track);
  };
  const openPage = async (hash = '') => {
    const page = await context.newPage();
    await page.goto(`chrome-extension://${id}/${POPUP}${hash}`);
    return page;
  };
  // Loads popup.html<hash> again in `page`'s own tab, so its virtual authenticator stays (a
  // fragment change alone would not run the page again: reload), and waits for the locked view
  // with its passkey button. → 'window' (popup.html#unlock) or 'tab'
  const openLockedView = async (page, hash) => {
    await page.goto(`chrome-extension://${id}/${POPUP}${hash}`);
    await page.reload();
    await state(page, 'locked');
    await instrument(page);
    await page.locator('#unlock-passkey').waitFor({ state: 'visible', timeout: 10000 });
    return page.evaluate(() => (document.documentElement.classList.contains('window') ? 'window' : document.documentElement.classList.contains('tab') ? 'tab' : 'popup'));
  };
  const settingsTab = async () => {
    const page = await openPage('#settings');
    await state(page, 'settings');
    await page.locator('#passkey-add').waitFor({ state: 'visible', timeout: 15000 });
    return page;
  };
  const pagesShown = {};
  const step = async (name, fn) => {
    try {
      await fn();
      return true;
    } catch (err) {
      const shown = [];
      for (const [label, p] of Object.entries(pagesShown)) shown.push(`${label}: ${await describe(p())}`);
      rep.fail(tag(name), `${(err.stack || String(err)).split('\n').slice(0, 3).join(' | ')} || ${shown.join(' || ')}`);
      return false;
    }
  };

  let P; // the main page: list, lock, passphrase unlock, the "other window" of every race
  let S; // the enrollment tab; later navigated to #unlock (its virtual authenticator stays)
  let Q; // the main page after the browser restart
  let S2; // the second enrollment tab (v2 record), later the #unlock view of the unlock races
  Object.assign(pagesShown, { P: () => P, S: () => S, Q: () => Q, S2: () => S2 });
  let auth;
  let msg;
  let prf = null;
  let exported = [];
  let ok = true;

  ok = await step('setup', async () => {
    await start();
    P = await context.newPage();
    ({ id } = await openExtensionPage(context, P, extDir, POPUP));
    msg = Object.fromEntries(
      await Promise.all(
        ['passkeyNoPrf', 'passkeyCancelled', 'passkeyChanged', 'passkeyAdded', 'passkeyRemoved', 'passkeyWorking', 'passkeyOrphan', 'errWrongPass'].map(async (k) => [k, await message(P, k)]),
      ),
    );
    await state(P, 'setup');
    await P.fill('#setup-pass', PASSPHRASE);
    await P.fill('#setup-pass2', PASSPHRASE);
    await P.click('#setup-submit');
    await state(P, 'list');
    await addUri(P, URIS[0]);
    const record = await vault(P);
    rep.check(tag('v1-until-enrollment'), record?.v === 1 && !('slots' in record), `new vault v=${record?.v}, keys [${Object.keys(record ?? {})}]`);
  });

  // A2 + A5: refusals leave the v1 record byte-identical.
  if (ok && variant.full) {
    await step('refusals', async () => {
      const before = json(await vault(P));
      const S0 = await settingsTab();
      const noPrf = await authenticator(S0, { transport: 'internal' });
      await instrument(S0);
      await S0.fill('#passkey-pass', WRONG_PASSPHRASE);
      await ceremonyClick(S0, '#passkey-add');
      const wrong = await settledError(S0, '#passkey-error', '#passkey-add');
      const afterWrong = await hookState(S0);
      rep.check(
        tag('wrong-passphrase-before-ceremony'),
        wrong === msg.errWrongPass && afterWrong.creates === 0 && afterWrong.gets === 0 && (await noPrf.credentials()).length === 0,
        `error ${json(wrong)}; create() ${afterWrong.creates}, get() ${afterWrong.gets}, credentials on the authenticator ${(await noPrf.credentials()).length}`,
      );
      await S0.fill('#passkey-pass', PASSPHRASE);
      await ceremonyClick(S0, '#passkey-add');
      const refused = await settledError(S0, '#passkey-error', '#passkey-add');
      const hook = await hookState(S0);
      const after = await vault(P);
      rep.check(
        tag('no-prf-refused-record-unchanged'),
        refused.startsWith(msg.passkeyNoPrf) && hook.creates === 1 && hook.gets === 1 && hook.getPrf === null && json(after) === before && after.v === 1,
        `authenticator without PRF: error ${json(refused)}; create() ${hook.creates}, get() ${hook.gets} (no PRF); stored record ${json(after) === before ? 'byte-identical' : 'CHANGED'} v=${after?.v}`,
      );
      await S0.close();

      const S1 = await settingsTab();
      await authenticator(S1, { transport: 'internal', hasPrf: true, isUserVerified: false });
      await instrument(S1);
      await S1.fill('#passkey-pass', PASSPHRASE);
      await ceremonyClick(S1, '#passkey-add');
      const cancelled = await settledError(S1, '#passkey-error', '#passkey-add');
      const afterCancel = await vault(P);
      rep.check(
        tag('cancel-record-unchanged'),
        cancelled.startsWith(msg.passkeyCancelled) && json(afterCancel) === before && afterCancel.v === 1,
        `user verification refused by the authenticator: error ${json(cancelled)}; stored record ${json(afterCancel) === before ? 'byte-identical' : 'CHANGED'} v=${afterCancel?.v}`,
      );
      await S1.close();
    });
  }

  if (ok) {
    ok = await step('enroll-tab', async () => {
      S = await settingsTab();
      auth = await authenticator(S, variant.options);
      await instrument(S);
      const files = await screenshots(S, `${variant.name}-enroll`, true);
      rep.pass(tag('screenshot-enroll'), files.join(', '));
    });
  }

  // A3: enrollment ceremony held after the real assertion while another page changes the vault.
  // A result that can no longer be stored leaves a passkey on the authenticator: the page says so
  // in the next view it shows (settings error line, locked view status, list notice).
  if (ok && variant.full) {
    // → the working status shown while the assertion is held
    const enrollHeld = async () => {
      await auth.clear();
      await holdNextAssertion(S);
      await S.fill('#passkey-pass', PASSPHRASE);
      await S.fill('#passkey-label', LABEL);
      await ceremonyClick(S, '#passkey-add');
      await waitHeld(S);
      return (await S.locator('#passkey-status').textContent()).trim();
    };
    const orphanAfterChange = `${msg.passkeyChanged} ${msg.passkeyOrphan}`;
    const backToSettings = async () => {
      await state(S, 'list');
      await S.click('#settings-btn');
      await state(S, 'settings');
      await S.locator('#passkey-add').waitFor({ state: 'visible', timeout: 15000 });
    };
    await step('race-enroll-edit', async () => {
      const working = await enrollHeld();
      await addUri(P, URIS[1]);
      const afterEdit = json(await vault(P));
      await release(S);
      const shown = await settledError(S, '#passkey-error', '#passkey-add');
      const now = await vault(P);
      rep.check(
        tag('race-enroll-edit-discarded'),
        working === msg.passkeyWorking && shown === orphanAfterChange && json(now) === afterEdit && !hasPasskey(now) && (await auth.credentials()).length === 1,
        `account added in another page during the held get(): status while held ${json(working)}; settings error ${json(shown)}; record ${json(now) === afterEdit ? 'equals the edited one' : 'CHANGED'}, passkey slot ${hasPasskey(now)}; orphaned credentials on the authenticator ${(await auth.credentials()).length}`,
      );
    });
    await step('race-enroll-import', async () => {
      const plain = await decryptRecord(await vault(P), PASSPHRASE);
      const { id: _drop, ...template } = plain.accounts[0];
      const backup = sealV1({ accounts: [{ ...template, issuer: 'Imported', label: 'import@example.test', secret: 'GEZDGNBVGY3TQOJQ' }] }, PASSPHRASE);
      const working = await enrollHeld();
      await importRecord(P, backup);
      const afterImport = json(await vault(P));
      await release(S);
      const shown = await settledError(S, '#passkey-error', '#passkey-add');
      const now = await vault(P);
      rep.check(
        tag('race-enroll-import-discarded'),
        working === msg.passkeyWorking && shown === orphanAfterChange && json(now) === afterImport && !hasPasskey(now) && (await rowCount(P)) === 3 && (await auth.credentials()).length === 1,
        `import merge in another page during the held get(): status while held ${json(working)}; settings error ${json(shown)}; record ${json(now) === afterImport ? 'equals the merged one' : 'CHANGED'}, passkey slot ${hasPasskey(now)}, rows ${await rowCount(P)}; orphaned credentials ${(await auth.credentials()).length}`,
      );
    });
    await step('race-enroll-manual-lock', async () => {
      const working = await enrollHeld();
      const before = json(await vault(P));
      await lock(P);
      await state(S, 'locked');
      await release(S);
      // The enrolling tab is on its locked view now: the owed notice goes to its status line.
      const notice = await S.waitForFunction((want) => document.querySelector('#unlock-passkey-status').textContent.trim() === want, msg.passkeyOrphan, { timeout: 10000 }).then(
        () => msg.passkeyOrphan,
        async () => (await S.locator('#unlock-passkey-status').textContent()).trim(),
      );
      const now = await vault(P);
      const sess = await session(P);
      rep.check(
        tag('race-enroll-manual-lock-discarded'),
        working === msg.passkeyWorking && notice === msg.passkeyOrphan && json(now) === before && !hasPasskey(now) && !sess.vaultKey && (await stateOf(S)) === 'locked' && (await auth.credentials()).length === 1,
        `Lock in another page during the held get(): enrolling tab ${await stateOf(S)} with #unlock-passkey-status ${json(notice)}; record ${json(now) === before ? 'unchanged' : 'CHANGED'}, passkey slot ${hasPasskey(now)}, session keys [${Object.keys(sess)}]; orphaned credentials ${(await auth.credentials()).length}`,
      );
      await passphraseUnlock(P);
      await backToSettings();
    });
    await step('race-enroll-idle-lock', async () => {
      const working = await enrollHeld();
      const before = json(await vault(P));
      await P.evaluate((ms) => chrome.storage.session.set({ lastActiveAt: Date.now() - ms }), IDLE_PAST_MS);
      await P.reload();
      await state(P, 'locked');
      await state(S, 'locked');
      const sess = await session(P);
      const lockedRecord = json(await vault(P));
      // Unlocked again by the other page before the held result comes back: the enrolling tab is
      // on its list now, so the owed notice goes to #list-notice (which clears itself after 5 s).
      await passphraseUnlock(P);
      await state(S, 'list');
      await S.evaluate(() => {
        const el = document.querySelector('#list-notice');
        globalThis.zauthE2eNotices = [];
        globalThis.zauthE2eNoticeObserver = new MutationObserver(() => {
          const text = el.textContent.trim();
          if (text) globalThis.zauthE2eNotices.push(text);
        });
        globalThis.zauthE2eNoticeObserver.observe(el, { childList: true, characterData: true, subtree: true });
      });
      await release(S);
      const noticed = await S.waitForFunction((want) => globalThis.zauthE2eNotices.includes(want), msg.passkeyOrphan, { timeout: 10000, polling: 100 }).then(
        () => true,
        () => false,
      );
      const notices = await S.evaluate(() => {
        globalThis.zauthE2eNoticeObserver.disconnect();
        return globalThis.zauthE2eNotices;
      });
      const now = await vault(P);
      rep.check(
        tag('race-enroll-idle-lock-discarded'),
        working === msg.passkeyWorking && noticed && lockedRecord === before && json(now) === before && !hasPasskey(now) && !sess.vaultKey && (await auth.credentials()).length === 1,
        `idle lock found by another page during the held get(), then unlocked there: session keys at the lock [${Object.keys(sess)}]; #list-notice ${json(notices)}; record ${json(now) === before ? 'unchanged' : 'CHANGED'}, passkey slot ${hasPasskey(now)}; orphaned credentials ${(await auth.credentials()).length}`,
      );
      await S.click('#settings-btn');
      await state(S, 'settings');
      await S.locator('#passkey-add').waitFor({ state: 'visible', timeout: 15000 });
    });
  }

  // A1: enrollment (v1 -> v2 migration) with the real authenticator.
  let enrolled = null;
  let payload = null;
  if (ok) {
    ok = await step('enroll', async () => {
      const v1 = await vault(P);
      const v1Data = await decryptRecord(v1, PASSPHRASE);
      await auth.clear();
      const before = await hookState(S);
      // A second settings tab with a passphrase typed in but never submitted.
      const A = await settingsTab();
      pagesShown.A = () => A;
      await A.fill('#passkey-pass', PASSPHRASE);
      await A.fill('#passkey-label', 'typed in the other tab');
      await A.evaluate(() => {
        globalThis.zauthE2eStates = [document.body.dataset.state];
        new MutationObserver(() => globalThis.zauthE2eStates.push(document.body.dataset.state)).observe(document.body, { attributes: true, attributeFilter: ['data-state'] });
      });
      await S.fill('#passkey-pass', PASSPHRASE);
      await S.fill('#passkey-label', LABEL);
      await ceremonyClick(S, '#passkey-add');
      await S.locator('#passkey-registered').waitFor({ state: 'visible', timeout: 30000 });
      // Tab A reacts to the stored change; its typed passphrase must be gone and off screen.
      const cleared = await A.waitForFunction(() => document.querySelector('#passkey-pass').value === '', null, { timeout: 15000 }).then(
        () => true,
        () => false,
      );
      await A.waitForTimeout(500);
      const other = await A.evaluate(() => ({
        pass: document.querySelector('#passkey-pass').value,
        label: document.querySelector('#passkey-label').value,
        states: globalThis.zauthE2eStates,
      }));
      const passVisible = await A.locator('#passkey-pass').isVisible();
      rep.check(
        tag('other-tab-typed-passphrase-cleared'),
        cleared && other.pass === '' && other.label === '' && !passVisible,
        `enrolled in tab B: tab A #passkey-pass ${other.pass === '' ? 'empty' : `still holds ${other.pass.length} chars`} and ${passVisible ? 'VISIBLE' : 'hidden'}, #passkey-label ${json(other.label)}; tab A views ${other.states.join(' -> ')}`,
      );
      await A.close();
      delete pagesShown.A;
      const status = (await S.locator('#passkey-status').textContent()).trim();
      const name = (await S.locator('#passkey-name').textContent()).trim();
      const hook = await hookState(S);
      enrolled = await vault(P);
      const slot = passkeySlot(enrolled);
      const creds = await auth.credentials();
      const credMatch = creds.find((c) => Buffer.from(c.credentialId, 'base64').toString('base64url') === slot?.cred);
      prf = hook.getPrf ? Buffer.from(hook.getPrf) : null;
      rep.check(
        tag('enroll'),
        status === msg.passkeyAdded && name === LABEL && enrolled?.v === 2 && enrolled.slots.length === 2 && enrolled.slots[0].type === 'passphrase' && slot?.label === LABEL && Boolean(credMatch),
        `status ${json(status)}, shown ${json(name)}; record v=${enrolled?.v} slots [${enrolled?.slots?.map((s) => s.type)}], cred ${credMatch ? 'is the authenticator credential' : 'NOT on the authenticator'} (${creds.length} credential(s) on the authenticator)`,
      );
      rep.check(
        tag('enroll-real-ceremony'),
        hook.creates - before.creates === 1 && hook.gets - before.gets === 1 && prf?.length === 32 &&
          (variant.prfOnCreate ? json(hook.createPrf) === json(hook.getPrf) : hook.createPrf === null),
        `create() ${hook.creates - before.creates}, get() ${hook.gets - before.gets}; PRF on get ${prf?.length ?? 0} B; on create ${hook.createPrf ? `${hook.createPrf.length} B, ${json(hook.createPrf) === json(hook.getPrf) ? 'equal' : 'DIFFERENT'}` : 'none (hmac-secret without -mc)'}`,
      );
      const pass = enrolled.slots[0];
      rep.check(
        tag('enroll-migration-fresh-salt'),
        Buffer.from(enrolled.id, 'base64').length === 16 && pass.kdf.salt !== v1.kdf.salt && Buffer.from(pass.kdf.salt, 'base64').length === 16 && pass.kdf.iterations >= v1.kdf.iterations,
        `id ${Buffer.from(enrolled.id, 'base64').length} B; passphrase salt ${pass.kdf.salt !== v1.kdf.salt ? 'fresh' : 'REUSED'} (${Buffer.from(pass.kdf.salt, 'base64').length} B), iterations ${pass.kdf.iterations} (v1 ${v1.kdf.iterations})`,
      );
      const byPass = await opens(enrolled, PASSPHRASE);
      const byPrf = await opens(enrolled, null, prf);
      payload = byPass.data;
      rep.check(
        tag('reference-opens-both-slots'),
        json(byPass.data) === json(v1Data) && json(byPrf.data) === json(v1Data),
        `node:crypto reference: passphrase slot ${byPass.error ?? 'opens'}, passkey slot via HKDF-SHA-256(real PRF) ${byPrf.error ?? 'opens'}, payload ${json(byPass.data) === json(v1Data) ? 'equals' : 'DIFFERS from'} the v1 payload`,
      );
      const tampered = [];
      for (const [field, edit] of [
        ['label', (r) => { passkeySlot(r).label = 'other'; }],
        ['createdAt', (r) => { passkeySlot(r).createdAt += 1; }],
        ['prfSalt', (r) => { passkeySlot(r).prfSalt = randomBytes(32).toString('base64'); }],
        ['cred', (r) => { passkeySlot(r).cred = randomBytes(16).toString('base64url'); }],
        ['id', (r) => { r.id = randomBytes(16).toString('base64'); }],
      ]) {
        const copy = structuredClone(enrolled);
        edit(copy);
        if (!(await opens(copy, null, prf)).error) tampered.push(field);
      }
      rep.check(tag('reference-aad-binds-slot'), tampered.length === 0, `passkey slot with a changed label/createdAt/prfSalt/cred/id does not open${tampered.length ? `; OPENED with ${tampered}` : ''}`);
      const sess = await session(P);
      rep.check(
        tag('enroll-session-identity'),
        sess.vaultKey?.v === 2 && sess.vaultKey?.id === enrolled.id && Buffer.from(sess.vaultKey?.key ?? '', 'base64').length === 32,
        `session vaultKey {v:${sess.vaultKey?.v}, id ${sess.vaultKey?.id === enrolled.id ? '= record id' : 'MISMATCH'}, key ${Buffer.from(sess.vaultKey?.key ?? '', 'base64').length} B}`,
      );
      const files = await screenshots(S, `${variant.name}-enrolled`, true);
      rep.pass(tag('screenshot-enrolled'), files.join(', '));
    });
  }

  // Backups: export drops the passkey slot; import goes through the passphrase only.
  if (ok) {
    await step('backup', async () => {
      const live = json(await vault(P));
      const downloading = S.waitForEvent('download');
      await S.click('#export-btn');
      const download = await downloading;
      const backup = JSON.parse(fs.readFileSync(await download.path(), 'utf8'));
      const opened = await opens(backup, PASSPHRASE);
      rep.check(
        tag('export-excludes-passkey'),
        backup.v === 2 && backup.id === enrolled.id && backup.slots.length === 1 && backup.slots[0].type === 'passphrase' && json(await vault(P)) === live && json(opened.data) === json(payload),
        `backup v=${backup.v} slots [${backup.slots?.map((s) => s.type)}]; live record ${json(await vault(P)) === live ? 'unchanged' : 'CHANGED'}; reference passphrase open ${opened.error ?? 'ok, same payload'}`,
      );
      await instrument(P);
      await importRecord(P, backup);
      await importRecord(P, JSON.parse(live));
      const hook = await hookState(P);
      const now = await vault(P);
      rep.check(
        tag('import-passphrase-only'),
        hook.creates === 0 && hook.gets === 0 && passkeySlot(now)?.cred === passkeySlot(enrolled).cred && now.id === enrolled.id,
        `imported the exported backup and a v2 record with a passkey slot: WebAuthn create() ${hook.creates}, get() ${hook.gets}; live passkey slot ${passkeySlot(now)?.cred === passkeySlot(enrolled).cred ? 'kept' : 'LOST'}`,
      );

      // A5: a v2 backup of another vault (its own id, data key, passphrase and passkey slot, built
      // by e2e/reference.mjs) imports by merge through its passphrase: its new account appears and
      // stays; this vault keeps its id and slots; no WebAuthn call.
      const plain = await decryptRecord(now, PASSPHRASE);
      const { id: _id, ...template } = plain.accounts[0];
      const added = { ...template, issuer: 'IndependentV2', label: 'import-v2@example.test', secret: 'MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U' };
      const params = { algorithm: String(template.algorithm ?? 'sha1').toLowerCase().replace('-', ''), digits: template.digits ?? 6, period: template.period ?? 30 };
      const backupPassphrase = 'e2e passkey independent v2 backup';
      const other = encryptRecordV2({ accounts: [added] }, backupPassphrase);
      const fixture = [await opens(other.record, backupPassphrase), await opens(other.record, null, other.prf)];
      const fixtureOk = fixture.every((o) => json(o.data) === json({ accounts: [added] })) && other.record.id !== now.id;
      const rows = await rowCount(P);
      await importRecord(P, other.record, backupPassphrase);
      const listed = await P.waitForFunction((n) => document.querySelectorAll('.account').length === n, rows + 1, { timeout: 10000 }).then(
        () => true,
        () => false,
      );
      const calls = await hookState(P);
      const shown = await rowCode(P, added.label, added.secret, params);
      const merged = await vault(P);
      await P.reload();
      await state(P, 'list');
      const reopened = await rowCode(P, added.label, added.secret, params);
      const stored = await vault(P);
      const has = (d) => Boolean(d?.accounts?.some((a) => a.issuer === added.issuer && a.label === added.label && a.secret === added.secret));
      const byPass = await opens(stored, PASSPHRASE);
      const byPrf = await opens(stored, null, prf);
      const kept = stored.id === now.id && stored.slots.length === 2 && json(stored.slots) === json(now.slots) && json(stored) === json(merged);
      rep.check(
        tag('import-independent-v2-merges-new-account'),
        fixtureOk && listed && shown.ok && reopened.ok && has(byPass.data) && has(byPrf.data) && kept && calls.creates === 0 && calls.gets === 0,
        `backup of another vault (id ${other.record.id === now.id ? 'SAME' : 'differs'}, own passkey slot, own passphrase; reference opens both its slots ${fixtureOk}): rows ${rows} -> ${listed ? rows + 1 : 'unchanged'}; ${shown.detail}; after reopening the page ${reopened.detail}; stored record holds it (passphrase slot ${has(byPass.data)}, this vault's passkey slot ${has(byPrf.data)}); id and slots ${kept ? 'unchanged' : 'CHANGED'}; WebAuthn create() ${calls.creates}, get() ${calls.gets}`,
      );
    });
  }

  // A1: an account edit seals v2 again; the slots stay and still open the new data.
  if (ok) {
    ok = await step('seal', async () => {
      const before = await vault(P);
      await addUri(P, URIS[2]);
      const sealed = await vault(P);
      const byPrf = await opens(sealed, null, prf);
      const rows = await rowCount(P);
      rep.check(
        tag('seal-keeps-slots'),
        sealed.id === before.id && json(sealed.slots) === json(before.slots) && sealed.data.iv !== before.data.iv && byPrf.data?.accounts?.length === rows,
        `id ${sealed.id === before.id ? 'kept' : 'CHANGED'}, slots ${json(sealed.slots) === json(before.slots) ? 'unchanged' : 'CHANGED'}, data.iv ${sealed.data.iv !== before.data.iv ? 'fresh' : 'REUSED'}; reference passkey open ${byPrf.error ?? `${byPrf.data.accounts.length} accounts`} (rows ${rows})`,
      );
    });
  }

  // Browser start: chrome.storage.session empty (no key, no lockGen). The ceremony capture writes
  // the first lockGen (store.ensureLockGen()) as the ceremony starts; the unlock must still commit.
  // The real assertion is held 1.5 s (a phone takes 10-25 s), so anything that write sets off in
  // the open pages has run before the result returns. Same tab as the enrollment (its
  // authenticator stays): first the toolbar popup's button (opens the #unlock window, no ceremony there), then
  // the locked tab (the list opens in it), then the #unlock window (the other page shows the list;
  // the window's own window.close() is recorded instead of done, so the tab and its authenticator
  // stay for A1 below).
  if (ok) {
    ok = await step('cold-start-unlock', async () => {
      const record = json(await vault(P));
      const parsed = JSON.parse(record);
      const accounts = (await opens(parsed, null, prf)).data?.accounts?.length;
      const pages = watchers[watchers.length - 1].pages;
      // Everything in chrome.storage.session goes, from an extension page, as at a browser start.
      const coldSession = async () => {
        await P.evaluate(() => chrome.storage.session.clear());
        await state(P, 'locked');
        await state(S, 'locked');
        await P.waitForTimeout(500);
        const sess = await session(P);
        if (Object.keys(sess).length !== 0) throw new Error(`session not empty after clear(): [${Object.keys(sess)}]`);
      };

      // The toolbar popup: chrome.action.openPopup() from the worker; Playwright does not list the
      // action popup as a page, so its DOM is reached through chrome.extension.getViews().
      await coldSession();
      await P.bringToFront();
      const worker = await extensionWorker(context, id);
      const popupOpened = await worker.evaluate(async () => {
        try {
          await chrome.action.openPopup();
          return 'ok';
        } catch (err) {
          return err.message;
        }
      });
      if (popupOpened !== 'ok') {
        const why = `chrome.action.openPopup() rejected: ${popupOpened}`;
        if (HEADLESS) rep.fail(tag('toolbar-popup-opens-unlock-window'), why);
        else console.log(`INFO ${tag('toolbar-popup-opens-unlock-window')} not reachable in a headed run: ${why}`);
      } else {
        const shown = await P.waitForFunction(
          () => chrome.extension.getViews({ type: 'popup' }).some((w) => w.document.body.dataset.state === 'locked' && !w.document.querySelector('#unlock-passkey').hidden),
          null,
          { timeout: 10000 },
        ).then(
          () => true,
          () => false,
        );
        const before = pages.count();
        const popup = await P.evaluate(() => {
          const [view] = chrome.extension.getViews({ type: 'popup' });
          if (!view) return null;
          const result = { classes: view.document.documentElement.className, state: view.document.body.dataset.state };
          view.document.querySelector('#unlock-passkey').click();
          return result;
        });
        const win = await pages.waitForUrl((url) => url.endsWith(`/${POPUP}#unlock`), { after: before, timeout: 10000 });
        const popupClosed = await P.waitForFunction(() => chrome.extension.getViews({ type: 'popup' }).length === 0, null, { timeout: 10000 }).then(
          () => true,
          () => false,
        );
        let winMode = 'none';
        if (win) {
          await state(win, 'locked');
          await win.locator('#unlock-passkey').waitFor({ state: 'visible', timeout: 10000 });
          winMode = await win.evaluate(() => (document.documentElement.classList.contains('window') ? 'window' : document.documentElement.className || 'popup'));
        }
        const after = await session(P);
        rep.check(
          tag('toolbar-popup-opens-unlock-window'),
          shown && popup?.classes === '' && popup?.state === 'locked' && Boolean(win) && winMode === 'window' && popupClosed && Object.keys(after).length === 0,
          `toolbar popup (classes ${json(popup?.classes)}, ${popup?.state}, passkey button shown ${shown}) -> click: #unlock window ${win ? `opened (${winMode} mode, locked, passkey button shown)` : 'NOT opened'}, popup ${popupClosed ? 'closed itself' : 'still open'}; session keys [${Object.keys(after)}] (no ceremony started in the popup)`,
        );
        if (win) await win.close();
      }

      for (const mode of ['tab', 'window']) {
        await coldSession();
        const shownMode = await openLockedView(S, mode === 'window' ? '#unlock' : '');
        await S.waitForTimeout(300);
        const atClick = await session(S);
        // Every text the view's message lines show from the click on, and window.close() calls.
        await S.evaluate(() => {
          const lines = ['#unlock-passkey-error', '#unlock-passkey-status', '#unlock-error', '#list-notice'];
          globalThis.zauthE2eLines = [];
          globalThis.zauthE2eLinesObserver = new MutationObserver(() => {
            for (const sel of lines) {
              const text = document.querySelector(sel)?.textContent?.trim();
              if (text) globalThis.zauthE2eLines.push(`${sel} ${text}`);
            }
          });
          for (const sel of lines) globalThis.zauthE2eLinesObserver.observe(document.querySelector(sel), { childList: true, characterData: true, subtree: true });
          globalThis.zauthE2eCloses = 0;
          window.close = () => {
            globalThis.zauthE2eCloses += 1;
          };
        });
        const errorsBefore = errors.length;
        const realGets = countRealGets(S);
        await holdNextAssertion(S);
        await ceremonyClick(S, '#unlock-passkey');
        // Held, or ended before any assertion (an error line): the check below says which.
        await S.waitForFunction(() => globalThis.zauthE2ePasskey?.held === true || document.querySelector('#unlock-passkey-error').textContent.trim() !== '', null, { timeout: 30000 });
        const whileHeld = await session(P);
        await S.waitForTimeout(1500);
        await release(S);
        const committed = await state(P, 'list').then(
          () => true,
          () => false,
        );
        if (mode === 'tab') await state(S, 'list').catch(() => {});
        else await S.waitForFunction(() => globalThis.zauthE2eCloses > 0, null, { timeout: 10000 }).catch(() => {});
        await S.waitForTimeout(500);
        const seen = await S.evaluate(() => {
          globalThis.zauthE2eLinesObserver.disconnect();
          return {
            lines: [...new Set(globalThis.zauthE2eLines)],
            closes: globalThis.zauthE2eCloses,
            state: document.body.dataset.state,
            rows: document.querySelectorAll('.account').length,
          };
        });
        const otherRows = await rowCount(P);
        const otherNotice = (await P.locator('#list-notice').textContent()).trim();
        const sess = await session(P);
        const keys = Object.keys(sess).sort();
        let dekRows = null;
        try {
          dekRows = openDataWithDek(parsed, Buffer.from(sess.vaultKey?.key ?? '', 'base64')).accounts.length;
        } catch {
          dekRows = null;
        }
        const quiet = seen.lines.every((line) => line === `#unlock-passkey-status ${msg.passkeyWorking}`) && ![msg.passkeyOrphan, msg.passkeyChanged].some((m) => otherNotice.includes(m));
        const gets = realGets();
        const view = mode === 'tab' ? seen.state === 'list' && seen.rows === accounts && seen.closes === 0 : seen.closes === 1;
        rep.check(
          tag(`cold-start-unlock-commits:${mode}`),
          shownMode === mode && json(Object.keys(atClick)) === json([]) && json(Object.keys(whileHeld)) === json(['lockGen']) && validLockGen(whileHeld.lockGen) && whileHeld.lockGen === sess.lockGen &&
            gets === 1 && committed && view && otherRows === accounts &&
            json(keys) === json(['lastActiveAt', 'lockGen', 'vaultKey']) && sess.vaultKey?.v === 2 && sess.vaultKey?.id === parsed.id && dekRows === accounts &&
            validLockGen(sess.lockGen) && Number.isFinite(sess.lastActiveAt) && json(await vault(P)) === record && quiet && errors.length === errorsBefore,
          `${mode} view, session keys at the click [${Object.keys(atClick)}] (empty: no key, no lockGen); during the ceremony [${Object.keys(whileHeld)}] (${validLockGen(whileHeld.lockGen) ? `the capture's first lockGen, ${whileHeld.lockGen === sess.lockGen ? 'kept by the commit' : 'NOT the one stored after'}` : 'no lockGen written'}); real get() ${gets} with PRF; ${mode === 'tab' ? `this tab now ${seen.state} with ${seen.rows} rows` : `window.close() called ${seen.closes}x`}; other page ${committed ? 'list' : 'NOT unlocked'} with ${otherRows} rows (vault holds ${accounts}); session [${keys}] {v:${sess.vaultKey?.v}, id ${sess.vaultKey?.id === parsed.id ? '= record' : 'MISMATCH'}, key opens ${dekRows ?? 'NOTHING'} accounts}, lockGen ${validLockGen(sess.lockGen) ? '16 B' : json(sess.lockGen)}; record ${json(await vault(P)) === record ? 'byte-identical' : 'CHANGED'}; lines seen ${json(seen.lines)}; page errors +${errors.length - errorsBefore}`,
        );
        // A1 below starts from an unlocked vault, whatever this check found.
        if ((await stateOf(P)) === 'locked') await passphraseUnlock(P);
      }
    });
  }

  // A1: lock, then the #unlock view's own button runs the ceremony; the other page refreshes.
  let firstLockGen = null;
  if (ok) {
    ok = await step('passkey-unlock', async () => {
      const keyBefore = (await session(P)).vaultKey?.key;
      const rows = await rowCount(P);
      await lock(P);
      await P.locator('#unlock-passkey').waitFor({ state: 'visible', timeout: 10000 });
      const files = await screenshots(P, `${variant.name}-locked`);
      rep.pass(tag('screenshot-locked'), files.join(', '));
      const locked = await session(P);
      firstLockGen = locked.lockGen;
      rep.check(
        tag('lock-leaves-lockgen-only'),
        json(Object.keys(locked)) === json(['lockGen']) && validLockGen(locked.lockGen) && locked.lockGen !== keyBefore,
        `session keys [${Object.keys(locked)}], lockGen ${validLockGen(locked.lockGen) ? '16 B' : json(locked.lockGen)}`,
      );
      const record = json(await vault(P));
      // The tab's virtual authenticator goes away with the window that closes itself after the
      // unlock: export its credential (for the restart step) first.
      exported = await auth.credentials();
      const windowMode = (await openLockedView(S, '#unlock')) === 'window';
      const realGets = countRealGets(S);
      await ceremonyClick(S, '#unlock-passkey');
      await state(P, 'list');
      await P.waitForFunction((n) => document.querySelectorAll('.account').length === n, rows, { timeout: 15000 });
      const sess = await session(P);
      // The window view never shows the list: after the unlock it closes itself, which a tab
      // Playwright navigated is not allowed to do, so it stays on its locked view here.
      await S.waitForEvent('close', { timeout: 10000 }).catch(() => {});
      const closed = S.isClosed();
      const gets = realGets();
      rep.check(
        tag('passkey-unlock-window-other-page-refreshes'),
        windowMode && sess.vaultKey?.v === 2 && sess.vaultKey?.id === enrolled.id && json(await vault(P)) === record && gets === 1 && closed,
        `#unlock view (window mode ${windowMode}) button: real get() ${gets} with PRF; other open page refreshed to ${rows} rows; session {v:${sess.vaultKey?.v}, id ${sess.vaultKey?.id === enrolled.id ? '= record' : 'MISMATCH'}}; record ${json(await vault(P)) === record ? 'unchanged' : 'CHANGED'}; unlock window ${closed ? 'closed itself' : `still open (${await stateOf(S)})`}`,
      );
    });
  }

  if (ok) {
    await step('passphrase-fallback', async () => {
      const rows = await rowCount(P);
      await lock(P);
      const gen = (await session(P)).lockGen;
      await passphraseUnlock(P);
      rep.check(
        tag('passphrase-fallback'),
        (await rowCount(P)) === rows && validLockGen(gen) && gen !== firstLockGen,
        `passphrase unlock after the passkey unlock and the seal: ${await rowCount(P)} rows; lockGen replaced by the second lock ${gen !== firstLockGen}`,
      );
      const keys = Object.keys(await session(P));
      rep.check(tag('session-keys-allowed'), keys.every((k) => SESSION_KEYS_ALLOWED.includes(k)), `session [${keys}] (within [${SESSION_KEYS_ALLOWED}])`);
    });
  }

  // Browser restart: nothing of the session survives; the stored slot still opens with the PRF.
  if (ok) {
    ok = await step('restart', async () => {
      const rows = await rowCount(P);
      await context.close();
      context = null;
      await start();
      Q = await openPage();
      await state(Q, 'locked');
      const sess = await session(Q);
      await Q.locator('#unlock-passkey').waitFor({ state: 'visible', timeout: 10000 });
      rep.check(tag('restart-locked-no-session'), Object.keys(sess).length === 0, `after restart: locked, session keys [${Object.keys(sess)}] (no key, no lockGen yet), passkey button shown`);
      const record = json(await vault(Q));
      const R = await openPage('#unlock');
      await state(R, 'locked');
      await authenticator(R, variant.options, exported);
      await instrument(R);
      await R.locator('#unlock-passkey').waitFor({ state: 'visible', timeout: 10000 });
      await ceremonyClick(R, '#unlock-passkey');
      const shown = await settledError(R, '#unlock-passkey-error', '#unlock-passkey');
      const hook = await hookState(R);
      rep.check(
        tag('restart-reinjected-credential-refused'),
        shown === msg.passkeyNoPrf && hook.gets === 1 && hook.getPrf === null && json(await vault(Q)) === record && !(await session(Q)).vaultKey,
        `credential exported by CDP and added back (CDP carries no PRF secret): get() ${hook.gets}, PRF ${hook.getPrf ? 'present' : 'none'}; error ${json(shown)}; record ${json(await vault(Q)) === record ? 'unchanged' : 'CHANGED'}, still locked`,
      );
      await R.close();
      const byPrf = await opens(JSON.parse(record), null, prf);
      rep.check(tag('restart-slot-opens-with-real-prf'), byPrf.data?.accounts?.length === rows, `reference: persisted passkey slot + PRF of the real ceremony -> ${byPrf.error ?? `${byPrf.data.accounts.length} accounts`}`);
      await passphraseUnlock(Q);
      rep.check(tag('restart-passphrase-unlock'), (await rowCount(Q)) === rows, `${await rowCount(Q)} rows`);
    });
  }

  // A3: a session envelope {key, v, id} whose key is this vault's data key but whose id is not
  // the record's reads as locked, and the reader clears it like a lock.
  if (ok) {
    await step('session-identity-mismatch', async () => {
      const before = await session(Q);
      const record = await vault(Q);
      let dekOpens = false;
      try {
        openDataWithDek(record, Buffer.from(before.vaultKey?.key ?? '', 'base64'));
        dekOpens = true;
      } catch {
        dekOpens = false;
      }
      const wrongId = randomBytes(16).toString('base64');
      await Q.evaluate(
        ({ key, id: otherId }) =>
          chrome.storage.session.set({ vaultKey: { key, v: 2, id: otherId }, pendingBind: { origin: 'https://seed.test', accountId: 'e2e-seed', at: Date.now() } }),
        { key: before.vaultKey?.key, id: wrongId },
      );
      const R = await openPage();
      const opened = await state(R, 'locked', 10000).then(
        () => 'locked',
        async () => stateOf(R),
      );
      const other = await state(Q, 'locked', 10000).then(
        () => 'locked',
        async () => stateOf(Q),
      );
      let sess = await session(R);
      for (let i = 0; i < 25 && json(Object.keys(sess)) !== json(['lockGen']); i += 1) {
        await R.waitForTimeout(200);
        sess = await session(R);
      }
      rep.check(
        tag('session-identity-mismatch-locks'),
        dekOpens && before.vaultKey?.v === 2 && before.vaultKey?.id === record.id && opened === 'locked' && other === 'locked' &&
          json(Object.keys(sess)) === json(['lockGen']) && validLockGen(sess.lockGen) && sess.lockGen !== before.lockGen && json(await vault(R)) === json(record),
        `session {key: the data key (reference opens the payload with it: ${dekOpens}), v:2, id: another id} + a pendingBind: newly opened page ${opened}, open page ${other}; session keys after [${Object.keys(sess)}] (lockGen ${sess.lockGen !== before.lockGen ? 'replaced' : 'NOT replaced'}); record ${json(await vault(R)) === json(record) ? 'unchanged' : 'CHANGED'}`,
      );
      await R.close();
      if ((await stateOf(Q)) === 'locked') await passphraseUnlock(Q);
    });
  }

  if (ok) {
    await step('remove', async () => {
      const T = await openPage('#settings');
      await state(T, 'settings');
      await T.locator('#passkey-registered').waitFor({ state: 'visible', timeout: 15000 });
      const before = await vault(Q);
      await T.click('#passkey-remove');
      await T.locator('#passkey-confirm').waitFor({ state: 'visible' });
      await T.click('#passkey-remove-cancel');
      await T.locator('#passkey-confirm').waitFor({ state: 'hidden' });
      rep.check(tag('remove-cancel-keeps-slot'), json(await vault(Q)) === json(before), `Cancel: record ${json(await vault(Q)) === json(before) ? 'unchanged' : 'CHANGED'}`);
      await T.click('#passkey-remove');
      await T.click('#passkey-remove-confirm');
      await T.locator('#passkey-add').waitFor({ state: 'visible', timeout: 15000 });
      const status = (await T.locator('#passkey-status').textContent()).trim();
      const after = await vault(Q);
      const byPass = await opens(after, PASSPHRASE);
      rep.check(
        tag('remove'),
        status === msg.passkeyRemoved && after.v === 2 && after.slots.length === 1 && json(after.slots[0]) === json(before.slots[0]) && after.id === before.id && json(after.data) === json(before.data) && byPass.data?.accounts?.length === (await rowCount(Q)),
        `status ${json(status)}; record v=${after.v} slots [${after.slots.map((s) => s.type)}], passphrase slot/id/data ${json(after.slots[0]) === json(before.slots[0]) && after.id === before.id && json(after.data) === json(before.data) ? 'unchanged' : 'CHANGED'}; reference passphrase open ${byPass.error ?? 'ok'}`,
      );
      await T.close();
      await lock(Q);
      await Q.waitForTimeout(1000);
      rep.check(tag('remove-hides-unlock-button'), await Q.locator('#unlock-passkey').isHidden(), 'locked view without a passkey slot shows no passkey button');
    });
  }

  // A3 for unlock: a second enrollment on the v2 record (no migration), then the unlock ceremony
  // held while another page cycles the lock, edits, imports, idle-locks or removes the passkey
  // (in a locked tab, which survives), then the #unlock window races (lockGen; removal, which
  // closes the window).
  if (ok && variant.full) {
    let prf2 = null;
    const passkeyOk = await step('re-enroll-v2', async () => {
      await passphraseUnlock(Q);
      const before = await vault(Q);
      S2 = await settingsTab();
      await authenticator(S2, variant.options);
      await instrument(S2);
      await S2.fill('#passkey-pass', PASSPHRASE);
      await ceremonyClick(S2, '#passkey-add');
      await S2.locator('#passkey-registered').waitFor({ state: 'visible', timeout: 30000 });
      const after = await vault(Q);
      prf2 = Buffer.from((await hookState(S2)).getPrf ?? []);
      const byPrf = await opens(after, null, prf2);
      rep.check(
        tag('re-enroll-v2-keeps-dek'),
        after.id === before.id && json(after.slots[0]) === json(before.slots[0]) && hasPasskey(after) && passkeySlot(after).label === '' && byPrf.data?.accounts?.length === (await rowCount(Q)),
        `v2 record without a slot: id ${after.id === before.id ? 'kept' : 'CHANGED'}, passphrase slot ${json(after.slots[0]) === json(before.slots[0]) ? 'unchanged' : 'CHANGED'}, empty label ${json(passkeySlot(after)?.label)}; reference passkey open ${byPrf.error ?? 'ok'}`,
      );
      await lock(Q);
    });
    // Holds the real assertion of an unlock started from the locked view of S2, run as the #unlock
    // window ('window') or as a tab ('tab'). Each race starts from a locked vault, whatever the
    // step before it left. → the working status shown while it is held
    const unlockHeld = async (mode) => {
      if ((await stateOf(Q)) !== 'locked') await lock(Q);
      const shownMode = await openLockedView(S2, mode === 'window' ? '#unlock' : '');
      if (shownMode !== mode) throw new Error(`locked view runs as ${shownMode}, not ${mode}`);
      await holdNextAssertion(S2);
      await ceremonyClick(S2, '#unlock-passkey');
      await waitHeld(S2);
      return (await S2.locator('#unlock-passkey-status').textContent()).trim();
    };
    // Releases the held assertion and checks that it was discarded. `closes`: the other page's
    // unlock closes the #unlock window (its one job is done), so the held result dies with it;
    // otherwise the page survives, the release reaches it and its locked view says the vault
    // changed. `also`: [ok, detail] for the race's own precondition (the change really happened).
    const afterRelease = async (name, working, expected, how, { closes = false, also = [true, ''] } = {}) => {
      if (!closes) await state(S2, 'locked', 15000).catch(() => {});
      const released = await release(S2);
      const shown = S2.isClosed()
        ? '(window closed)'
        : await S2.waitForFunction(() => !document.querySelector('#unlock-passkey').disabled && document.querySelector('#unlock-passkey-error').textContent.trim() !== '', null, { timeout: 15000 })
            .then(
              async () => (await S2.locator('#unlock-passkey-error').textContent()).trim(),
              async () => `(none: ${json((await S2.locator('#unlock-passkey-error').textContent()).trim())})`,
            )
            .catch(() => '(window closed)');
      await Q.waitForTimeout(500);
      const now = await vault(Q);
      const sess = await session(Q);
      const view = closes ? S2.isClosed() : released && shown === msg.passkeyChanged && (await stateOf(S2)) === 'locked';
      rep.check(
        tag(name),
        also[0] && working === msg.passkeyWorking && view && json(now) === expected && !sess.vaultKey && json(Object.keys(sess)) === json(['lockGen']) && validLockGen(sess.lockGen) && (await stateOf(Q)) === 'locked',
        `${how}${also[1] ? `; ${also[1]}` : ''}; status while held ${json(working)}; held assertion ${released ? 'released into the live page' : 'never returned (window gone)'}; #unlock-passkey-error ${json(shown)}${S2.isClosed() ? '' : ` on ${await stateOf(S2)}`}; record ${json(now) === expected ? 'byte-identical to what the other page left' : 'CHANGED'}, session keys [${Object.keys(sess)}], other page ${await stateOf(Q)}`,
      );
    };
    if (passkeyOk) {
      await step('race-unlock-lock-cycle', async () => {
        const working = await unlockHeld('tab');
        const before = json(await vault(Q));
        await passphraseUnlock(Q);
        await lock(Q);
        await afterRelease('race-unlock-tab-lock-cycle-discarded', working, before, 'locked tab; lock-unlock-lock in another page during the held get()');
      });
      await step('race-unlock-edit', async () => {
        const working = await unlockHeld('tab');
        await passphraseUnlock(Q);
        await addUri(Q, URIS[3]);
        await lock(Q);
        await afterRelease('race-unlock-tab-edit-discarded', working, json(await vault(Q)), 'locked tab; unlock + account edit + lock in another page during the held get()');
      });
      await step('race-unlock-import', async () => {
        const plain = await decryptRecord(await vault(Q), PASSPHRASE);
        const { id: _id, ...template } = plain.accounts[0];
        const entry = { ...template, issuer: 'UnlockRaceImport', label: 'unlock-import@example.test', secret: 'KRUGS4ZANFZSAYJAORSXG5BAMV4GC3LQ' };
        const backup = sealV1({ accounts: [entry] }, PASSPHRASE);
        const working = await unlockHeld('tab');
        const before = json(await vault(Q));
        await passphraseUnlock(Q);
        const rows = await rowCount(Q);
        await importRecord(Q, backup);
        const listed = await Q.waitForFunction((n) => document.querySelectorAll('.account').length === n, rows + 1, { timeout: 10000 }).then(
          () => true,
          () => false,
        );
        await lock(Q);
        const merged = json(await vault(Q));
        await afterRelease('race-unlock-tab-import-discarded', working, merged, 'locked tab; unlock + import merge of a backup with a new account + lock in another page during the held get()', {
          also: [listed && merged !== before, `merge ${listed && merged !== before ? `added the account (rows ${rows} -> ${rows + 1}) and resealed` : 'DID NOT change the vault'}`],
        });
      });
      await step('race-unlock-idle', async () => {
        const working = await unlockHeld('tab');
        const before = json(await vault(Q));
        await passphraseUnlock(Q);
        await state(S2, 'list', 15000);
        // The product's idle path: lastActiveAt in the past in the extension's session storage, then
        // the open page's own idle check (popup.js runs session.lockIfIdle() every 30 s and when the
        // page becomes visible; the visibilitychange is dispatched here instead of waited for).
        await Q.bringToFront();
        await Q.evaluate((ms) => chrome.storage.session.set({ lastActiveAt: Date.now() - ms }), IDLE_PAST_MS);
        const visible = await Q.evaluate(() => {
          document.dispatchEvent(new Event('visibilitychange'));
          return document.visibilityState;
        });
        const idled = await state(Q, 'locked', 10000).then(
          () => true,
          () => false,
        );
        await afterRelease('race-unlock-tab-idle-lock-discarded', working, before, 'locked tab; unlock, then an idle lock (lastActiveAt 16 min ago, lockIfIdle on visibilitychange) in another page during the held get()', {
          also: [idled, `other page ${idled ? `idle-locked itself (visibilityState ${visible})` : 'did NOT idle-lock'}`],
        });
      });
      await step('race-unlock-tab-remove', async () => {
        const working = await unlockHeld('tab');
        const before = await vault(Q);
        await passphraseUnlock(Q);
        const T = await openPage('#settings');
        await state(T, 'settings');
        await T.locator('#passkey-registered').waitFor({ state: 'visible', timeout: 15000 });
        await T.click('#passkey-remove');
        await T.click('#passkey-remove-confirm');
        await T.locator('#passkey-add').waitFor({ state: 'visible', timeout: 15000 });
        await T.close();
        await lock(Q);
        const removed = await vault(Q);
        await afterRelease('race-unlock-tab-remove-discarded', working, json(removed), 'locked tab; unlock + passkey removal + lock in another page during the held get()', {
          also: [hasPasskey(before) && !hasPasskey(removed), `the other page ${hasPasskey(before) && !hasPasskey(removed) ? 'removed the slot' : 'did NOT remove the slot'}`],
        });
      });
      // A passkey again, from the same tab and authenticator, for the two #unlock window races.
      const againOk = await step('re-enroll-for-window-races', async () => {
        if ((await stateOf(Q)) === 'locked') await passphraseUnlock(Q);
        await state(S2, 'list', 15000);
        await S2.click('#settings-btn');
        await state(S2, 'settings');
        await S2.locator('#passkey-add').waitFor({ state: 'visible', timeout: 15000 });
        await instrument(S2);
        await S2.fill('#passkey-pass', PASSPHRASE);
        await ceremonyClick(S2, '#passkey-add');
        await S2.locator('#passkey-registered').waitFor({ state: 'visible', timeout: 30000 });
        prf2 = Buffer.from((await hookState(S2)).getPrf ?? []);
        const byPrf = await opens(await vault(Q), null, prf2);
        if (!byPrf.data) throw new Error(`the new passkey slot does not open with its PRF: ${byPrf.error}`);
        await lock(Q);
      });
      if (againOk) {
        // Only the session commit can catch this one: the unlock window stays on its locked view (a
        // storage hint that changes nothing must not drop the ceremony), and the record is the same.
        await step('race-unlock-lockgen', async () => {
          const working = await unlockHeld('window');
          const before = json(await vault(Q));
          await Q.evaluate(async () => {
            const bytes = crypto.getRandomValues(new Uint8Array(16));
            await chrome.storage.session.set({ lockGen: btoa(String.fromCharCode(...bytes)) });
          });
          await afterRelease('race-unlock-window-lockgen-discarded', working, before, '#unlock window; lockGen replaced during the held get() (what a lock in any other context leaves; record and lock state unchanged)');
        });
        // Last: the window closes itself when the other page unlocks, and takes the tab's virtual
        // authenticator with it.
        await step('race-unlock-remove', async () => {
          const working = await unlockHeld('window');
          await passphraseUnlock(Q);
          const T = await openPage('#settings');
          await state(T, 'settings');
          await T.locator('#passkey-registered').waitFor({ state: 'visible', timeout: 15000 });
          await T.click('#passkey-remove');
          await T.click('#passkey-remove-confirm');
          await T.locator('#passkey-add').waitFor({ state: 'visible', timeout: 15000 });
          await T.close();
          await lock(Q);
          const removed = await vault(Q);
          await afterRelease('race-unlock-window-remove-discarded', working, json(removed), '#unlock window; unlock + passkey removal + lock in another page during the held get()', { closes: true });
          rep.check(tag('race-unlock-remove-no-slot'), !hasPasskey(await vault(Q)) && (await opens(await vault(Q), null, prf2)).error !== undefined, 'the removed slot stays removed');
        });
      }
    }
  }

  for (const [i, { net, pages }] of watchers.entries()) {
    const egress = net.egress();
    rep.check(tag(`no-egress:${i + 1}`), egress.length === 0, egress.length ? json(egress) : `0 remote requests, ${net.extensionUrls.length} extension requests seen`);
    const offenders = id ? pages.offenders([`chrome-extension://${id}`]) : [];
    rep.check(tag(`no-navigation:${i + 1}`), offenders.length === 0, offenders.length ? json(offenders) : `${pages.count()} pages, none left the extension`);
  }
  rep.check(tag('no-pageerror'), errors.length === 0, errors.length ? json(errors) : 'no uncaught page errors');
  if (context) await context.close().catch(() => {});
  fs.rmSync(profile, { recursive: true, force: true });
}

// The variants to run: all of them when E2E_PASSKEY_VARIANTS is unset, else exactly the named
// ones. A set value naming an unknown variant, or none, is a FAIL line naming the valid ones (so
// a typo cannot turn the suite into zero checks). → the variants, or null after that FAIL
function selectedVariants(rep) {
  const raw = process.env.E2E_PASSKEY_VARIANTS;
  if (raw === undefined) return VARIANTS;
  const valid = VARIANTS.map((v) => v.name);
  const names = raw.split(',').map((name) => name.trim()).filter(Boolean);
  const unknown = names.filter((name) => !valid.includes(name));
  if (names.length === 0 || unknown.length > 0) {
    rep.fail('passkey-variants', `E2E_PASSKEY_VARIANTS=${json(raw)} ${names.length === 0 ? 'selects no variant' : `names unknown variant(s) ${unknown.join(', ')}`}; valid: ${valid.join(', ')} (unset runs all)`);
    return null;
  }
  console.log(`INFO passkey variants ${names.join(', ')} (E2E_PASSKEY_VARIANTS)`);
  return VARIANTS.filter((v) => names.includes(v.name));
}

export async function runPasskey(rep) {
  const variants = selectedVariants(rep);
  if (!variants) return;
  ensureArtifactsDir();
  const extDir = realExtensionDir(process.env.E2E_EXTENSION || path.join(REPO_ROOT, 'extension'));
  for (const variant of variants) await runVariant(rep, extDir, variant);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const rep = createReporter();
  await runPasskey(rep);
  rep.finish('passkey-e2e');
}
