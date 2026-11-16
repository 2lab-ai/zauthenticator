// Auto-fill end to end (.prd/03-autofill.md, traces S1-S4) in a real Chromium, run as part 3 of
// e2e/popup.e2e.mjs (npm run e2e) or on its own:
//
//   node e2e/autofill.e2e.mjs            # same E2E_HEADLESS / E2E_EXTENSION / E2E_ARTIFACTS
//
// It runs a TEST COPY of the extension, built in os.tmpdir(), that differs from the shipped one in
// two manifest fields, both of which the trust gate refuses (self-test cases background-test-entry
// and key-host-permissions-test-origins):
//   background.service_worker  background.test.js (e2e/fixtures/background.test.js): the shipped
//                              background.js unchanged plus globalThis.__zauthTest.handleMenuClick,
//                              because a click in the browser's context menu cannot be automated.
//   host_permissions           the routed test origins, so the browser grants the bind request at
//                              once instead of showing its native prompt (a manual check). In the
//                              shipped manifest that access is optional and granted per site.
// The test origins are answered by context.route(); nothing leaves the machine. Codes are compared
// with e2e/reference.mjs, and the vault is opened there with the passphrase, independently of
// extension/lib.
//
// Each step reports its own PASS/FAIL lines; a step whose precondition failed reports one FAIL
// naming it instead of waiting on timeouts. If the auto-fill sources are not in the extension yet,
// every step fails at once with the missing files named.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  HEADLESS,
  allowTestOrigins,
  computeExtensionId,
  createReporter,
  extensionWorker,
  freshProfileDir,
  launch,
  openExtensionPage,
  realExtensionDir,
  watchConsole,
  watchContentScripts,
  watchNetwork,
  watchPages,
} from './harness.mjs';
import { base32ToBytes, decryptRecord, referenceTotp } from './reference.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const POPUP = 'popup/popup.html';
const PASSPHRASE = 'e2e autofill passphrase (test only)';
const IDLE_LOCK_MS = 15 * 60 * 1000;
// .prd/03-autofill.md, "Cross-unit contract": session storage holds a subset of these keys.
const SESSION_KEYS_ALLOWED = ['vaultKey', 'lastActiveAt', 'pendingBind'];
const OTP = 'https://otp.test';
const EVIL = 'https://evil.test';
const HOST = 'https://host.test';
const TEST_ORIGINS = [OTP, EVIL, HOST];
// How long a page that must not be filled is watched.
const NO_FILL_WAIT_MS = 3000;
// The registered auto-fill content script, in injection order.
const CONTENT_SCRIPT_FILES = ['lib/fieldfind.js', 'content/autofill.js'];
// The auto-fill sources the test copy needs (AF-A and AF-B of the v0-2-autofill workstream).
const REQUIRED_FILES = ['background.js', 'lib/autofill-worker.js', 'lib/bindings.js', 'lib/fieldfind.js', 'content/autofill.js'];

const ACCOUNT_A = {
  uri: 'otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example',
  issuer: 'Example',
  label: 'alice@example.com',
  secret: 'JBSWY3DPEHPK3PXP',
  algorithm: 'sha1',
  digits: 6,
  period: 30,
};
const ACCOUNT_B = {
  uri: 'otpauth://totp/Example256:bob@example.org?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=Example256&algorithm=SHA256&digits=8&period=60',
  issuer: 'Example256',
  label: 'bob@example.org',
  secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA',
  algorithm: 'sha256',
  digits: 8,
  period: 60,
};

// ---- test pages --------------------------------------------------------------------------------

// The data: icon keeps Chromium from asking for /favicon.ico.
const HEAD = '<meta charset="utf-8"><link rel="icon" href="data:,">';
const LOGIN_HTML = `<!doctype html><html><head>${HEAD}<title>Sign in</title></head><body><form method="post" action="/submitted"><label>Code <input id="otp" name="otp" autocomplete="one-time-code"></label><button>Sign in</button></form></body></html>`;
// host.test frames otp.test and has an OTP field of its own, which must stay empty.
const HOST_HTML = `<!doctype html><html><head>${HEAD}<title>Host</title></head><body><input id="otp" autocomplete="one-time-code"><iframe src="${OTP}/frame"></iframe></body></html>`;

async function routeTestOrigins(context) {
  const served = [];
  for (const origin of TEST_ORIGINS) {
    await context.route(`${origin}/**`, (route) => {
      const url = new URL(route.request().url());
      served.push(url.href);
      return route.fulfill({ status: 200, contentType: 'text/html', body: url.origin === HOST ? HOST_HTML : LOGIN_HTML });
    });
  }
  return served;
}

// Builds the test copy described at the top of this file. → absolute (real) path
function buildTestCopy(extensionDir) {
  const root = realExtensionDir(fs.mkdtempSync(path.join(os.tmpdir(), 'zauth-autofill-ext-')));
  fs.cpSync(extensionDir, root, { recursive: true });
  fs.copyFileSync(path.join(REPO_ROOT, 'e2e', 'fixtures', 'background.test.js'), path.join(root, 'background.test.js'));
  const manifestPath = path.join(root, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  manifest.background = { ...manifest.background, service_worker: 'background.test.js' };
  manifest.host_permissions = TEST_ORIGINS.map((o) => `${o}/*`);
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  return root;
}

// ---- small helpers -----------------------------------------------------------------------------

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Polls `probe` until it returns something truthy. → that value, or null after `timeout`
async function poll(probe, timeout = 10000, interval = 250) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const value = await probe();
    if (value) return value;
    if (Date.now() > deadline) return null;
    await sleep(interval);
  }
}

// Waits until the current period of `account` has at least `needMs` left, so a code computed
// now is still current when the page shows it.
async function waitForFreshPeriod(account, needMs = 8000) {
  const periodMs = account.period * 1000;
  const left = periodMs - (Date.now() % periodMs);
  if (left < needMs) await sleep(left + 300);
}

const codeAt = (account, ms) => referenceTotp(base32ToBytes(account.secret), ms, account);

async function waitState(page, state, timeout = 30000) {
  await page.waitForSelector(`body[data-state="${state}"]`, { timeout });
}

// The value of `selector` in `frame` once it matches `pattern`, or whatever it holds after
// `timeout` (null when the field is missing).
async function fieldValue(frame, selector, pattern, timeout) {
  await frame
    .waitForFunction(([sel, src]) => new RegExp(src).test(document.querySelector(sel)?.value ?? ''), [selector, pattern.source], { timeout })
    .catch(() => {});
  return frame.evaluate((sel) => document.querySelector(sel)?.value ?? null, selector);
}

function digitsPattern(account) {
  return new RegExp(`^\\d{${account.digits}}$`);
}

// ---- the run -----------------------------------------------------------------------------------

// Runs every step and reports through `rep`. → { pages, ownOrigin } for the caller's
// no-navigation check (pages = watchPages() of this run, or null when nothing launched).
export async function runAutofill({ rep, extensionDir }) {
  const st = { failed: new Set(), consoles: [] };
  const missing = REQUIRED_FILES.filter((rel) => !fs.existsSync(path.join(extensionDir, rel)));
  const steps = [];
  const step = (name, needs, fn) => steps.push({ name, needs, fn });
  let copyDir;
  let profile;

  // In the worker of the test copy. The worker is looked up again for every call.
  const inWorker = async (fn, arg) => (await extensionWorker(st.context, st.id)).evaluate(fn, arg);
  const storage = () =>
    inWorker(async () => ({
      local: await chrome.storage.local.get(null),
      sync: await chrome.storage.sync.get(null),
      session: await chrome.storage.session.get(null),
    }));
  // The stored vault, opened here with the passphrase. → data or { error }
  const vaultData = async () => {
    try {
      return await decryptRecord((await storage()).local.vault, PASSPHRASE);
    } catch (err) {
      return { error: err.message };
    }
  };
  const bindingsIn = (data) => (Array.isArray(data?.bindings) ? data.bindings : []);
  // The browser's own record of the registered content scripts, read from an extension page.
  const registered = (page = st.popup) => page.evaluate(() => chrome.scripting.getRegisteredContentScripts());
  const autofillScript = async () => (await registered()).find((s) => s.id === 'autofill') ?? null;
  const tabIdOf = async (url) => {
    const ids = await inWorker((u) => chrome.tabs.query({}).then((tabs) => tabs.filter((t) => t.url === u).map((t) => t.id)), url);
    if (ids.length === 0) throw new Error(`no tab with url ${url}`);
    return ids[ids.length - 1];
  };
  // What a context-menu click on an account item delivers to the worker.
  const menuClick = (accountId, url, tabId) =>
    inWorker(
      ({ accountId: id, url: u, tabId: tab }) =>
        globalThis.__zauthTest.handleMenuClick({ menuItemId: `acct:${id}`, editable: true, frameId: 0, pageUrl: u, frameUrl: u }, { id: tab, url: u }),
      { accountId, url, tabId },
    );
  const ownUrl = (hash) => `${st.ownOrigin}/${POPUP}#${hash}`;

  // A page the test opens on a routed origin; allowed for the page watcher, watched for the
  // extension's content scripts in its top frame, with its top-frame navigations counted.
  async function openTestPage(url, extraOrigins = []) {
    const page = await st.context.newPage();
    allowTestOrigins(page, [new URL(url).origin, ...extraOrigins]);
    const worlds = await watchContentScripts(page, st.id);
    const rec = { page, worlds, navigations: 0 };
    page.on('framenavigated', (frame) => {
      if (frame === page.mainFrame()) rec.navigations += 1;
    });
    await page.goto(url);
    return rec;
  }
  async function reload(rec) {
    rec.worlds.reset();
    await rec.page.reload();
    rec.navigations = 1;
  }
  // The page is still the one the test loaded: no form submission, no other navigation.
  const stayed = (rec, url) => rec.page.url() === url && rec.navigations === 1;

  async function openPopup() {
    const page = await st.context.newPage();
    st.consoles.push(watchConsole(page));
    await openExtensionPage(st.context, page, copyDir, POPUP);
    return page;
  }
  async function unlockIn(page) {
    await page.fill('#unlock-pass', PASSPHRASE);
    await page.click('#unlock-submit');
  }
  // Locks with the Lock button of the control popup page. A page that shows the locked view
  // does not follow an unlock made in another window, so it is reloaded into the list first.
  async function lockFromPopup() {
    const unlockedView = 'body[data-state="list"], body[data-state="settings"], body[data-state="add"]';
    if (!(await st.popup.$(unlockedView))) await st.popup.reload();
    await st.popup.waitForSelector(unlockedView, { timeout: 15000 });
    await st.popup.click('#lock-btn');
    await waitState(st.popup, 'locked', 15000);
  }
  function checkSessionKeys(name, session) {
    const keys = Object.keys(session).sort();
    const extra = keys.filter((k) => !SESSION_KEYS_ALLOWED.includes(k));
    rep.check(name, extra.length === 0, `session [${keys}] (within [${SESSION_KEYS_ALLOWED}])`);
  }
  // A pending auto-fill offer written into session storage, shaped as the worker writes one, so a
  // lock that removed only the v0.1 keys cannot pass checkSessionEmpty(). `extra` is written in
  // the same call. → the offer read back 300 ms later (null when something removed it)
  const seedPendingBind = (extra = {}) =>
    inWorker(
      async ({ accountId, more }) => {
        await chrome.storage.session.set({ pendingBind: { origin: 'https://seed.test', accountId, at: Date.now() }, ...more });
        await new Promise((resolve) => setTimeout(resolve, 300));
        return (await chrome.storage.session.get('pendingBind')).pendingBind ?? null;
      },
      { accountId: st.idA, more: extra },
    );
  // A lock leaves chrome.storage.session empty: no key, no activity time, no pending bind.
  // `seeded` is what seedPendingBind() read back before the lock, or 'real' when the step had a
  // pending offer of its own; without one the check could not fail and does not pass.
  async function checkSessionEmpty(name, how, seeded = 'real') {
    const session = await poll(async () => {
      const s = (await storage()).session;
      return Object.keys(s).length === 0 ? s : null;
    }, 5000);
    const now = session ?? (await storage()).session;
    const before = seeded === 'real' ? 'a real pendingBind before' : `pendingBind seeded before: ${seeded ? 'yes' : 'NO (check not meaningful)'}`;
    rep.check(name, Boolean(seeded) && Object.keys(now).length === 0, `${how}; ${before}; session keys after [${Object.keys(now)}] (must be empty)`);
  }
  // Menu fill on a fresh page at `url` (its top-frame #otp field), then the #bind window.
  // → { rec, value, expected, at, win }
  async function menuFillAndBindWindow(account, accountId, url, extraOrigins = []) {
    const rec = await openTestPage(url, extraOrigins);
    await rec.page.bringToFront();
    await rec.page.focus('#otp');
    const tabId = await tabIdOf(url);
    await waitForFreshPeriod(account);
    const before = st.pages.count();
    const at = Date.now();
    await menuClick(accountId, url, tabId);
    const value = await fieldValue(rec.page, '#otp', digitsPattern(account), 10000);
    const expected = codeAt(account, at);
    const win = await st.pages.waitForUrl((u) => u === ownUrl('bind'), { after: before, timeout: 10000 });
    if (win) st.consoles.push(watchConsole(win));
    return { rec, value, expected, at, win };
  }

  // For a failure report: the frame's URL, its field, and the extension's isolated worlds in it
  // (an out-of-process iframe gets its own CDP session; Runtime.enable reports existing worlds).
  async function describeFrame(frame) {
    const field = await frame
      .evaluate(() => {
        const el = document.querySelector('#otp');
        return el ? { value: el.value, visible: el.checkVisibility?.() ?? null, readyState: document.readyState } : null;
      })
      .catch((err) => `unreadable (${err.message.split('\n')[0]})`);
    let worlds = 'not an out-of-process frame';
    try {
      const cdp = await st.context.newCDPSession(frame);
      const seen = [];
      cdp.on('Runtime.executionContextCreated', ({ context }) => {
        if (context.auxData?.type === 'isolated') seen.push(context);
      });
      await cdp.send('Runtime.enable');
      await sleep(200);
      worlds = `isolated worlds ${JSON.stringify(seen.map((c) => c.origin))}`;
      // In the content script's own world: does the finder see the field now, and what does the
      // worker answer this frame now?
      const own = seen.find((c) => c.origin === st.ownOrigin);
      if (own) {
        const { result } = await cdp.send('Runtime.evaluate', {
          contextId: own.id,
          awaitPromise: true,
          returnByValue: true,
          expression: `(async () => ({ found: (globalThis.zauthFieldFind?.findInDocument(document) ?? []).length, reply: await chrome.runtime.sendMessage({ type: 'autofill-code' }).then((r) => (r && r.code ? 'a code' : JSON.stringify(r)), (e) => 'error ' + e.message) }))()`,
        });
        worlds += `; in the content-script world now: ${JSON.stringify(result.value ?? result.description)}`;
      }
      await cdp.detach();
    } catch (err) {
      worlds = `no CDP session (${err.message.split('\n')[0]})`;
    }
    const asks = await inWorker(() => globalThis.__zauthE2eAsks ?? null).catch(() => null);
    return `${frame.url()} field ${JSON.stringify(field)}, ${worlds}; requests the worker received: ${JSON.stringify(asks?.slice(-4))}`;
  }

  // ---- steps -----------------------------------------------------------------------------------

  step('autofill-setup', [], async () => {
    copyDir = buildTestCopy(extensionDir);
    st.id = computeExtensionId(copyDir);
    st.ownOrigin = `chrome-extension://${st.id}`;
    profile = freshProfileDir('zauth-e2e-autofill-profile-');
    console.log(`INFO autofill test copy ${copyDir} computed-id ${st.id} (${HEADLESS ? 'headless' : 'headed'})`);
    st.context = await launch(copyDir, profile);
    st.net = watchNetwork(st.context);
    st.pages = watchPages(st.context);
    st.served = await routeTestOrigins(st.context);
    st.popup = await openPopup();
    await waitState(st.popup, 'setup', 15000);
    await st.popup.fill('#setup-pass', PASSPHRASE);
    await st.popup.fill('#setup-pass2', PASSPHRASE);
    await st.popup.click('#setup-submit');
    await waitState(st.popup, 'list');
    await st.popup.click('#add-btn');
    await waitState(st.popup, 'add');
    await st.popup.fill('#add-uri', `${ACCOUNT_A.uri}\n${ACCOUNT_B.uri}`);
    await st.popup.click('#add-uri-submit');
    await waitState(st.popup, 'list');
    await st.popup.waitForFunction(() => document.querySelectorAll('.account').length === 2, null, { timeout: 15000 });
    const rows = await st.popup.evaluate(() => Array.from(document.querySelectorAll('.account'), (r) => ({ id: r.dataset.id, label: r.querySelector('.label')?.textContent ?? '' })));
    st.idA = rows.find((r) => r.label.includes(ACCOUNT_A.label))?.id;
    st.idB = rows.find((r) => r.label.includes(ACCOUNT_B.label))?.id;
    const hook = await inWorker(() => typeof globalThis.__zauthTest?.handleMenuClick);
    // Diagnostics only: a passive listener (it never answers) that records which frames asked
    // the worker for a code, for failure reports.
    await inWorker(() => {
      globalThis.__zauthE2eAsks = [];
      chrome.runtime.onMessage.addListener((message, sender) => {
        globalThis.__zauthE2eAsks.push({ type: message?.type, origin: sender.origin, frameId: sender.frameId, at: Date.now() });
      });
    });
    const workerUrl = (await extensionWorker(st.context, st.id)).url();
    rep.check(
      'autofill-setup',
      Boolean(st.idA && st.idB) && hook === 'function',
      `vault with ${rows.length} accounts (ids ${st.idA}, ${st.idB}); worker ${workerUrl}, __zauthTest.handleMenuClick is a ${hook}`,
    );
    if (!(st.idA && st.idB) || hook !== 'function') throw new Error('setup incomplete');
  });

  // The extension-page CSP (connect-src 'none') governs the service worker too: a fetch from it
  // to a routed test URL is refused before the route sees it.
  step('worker-fetch-blocked', ['autofill-setup'], async () => {
    const url = `${OTP}/worker-fetch-probe`;
    const probe = await inWorker(async (u) => {
      const violations = [];
      const onViolation = (e) => violations.push(`${e.effectiveDirective} ${e.blockedURI}`);
      self.addEventListener('securitypolicyviolation', onViolation);
      const result = await fetch(u).then(
        () => 'ok',
        (e) => `blocked:${e.message}`,
      );
      await new Promise((resolve) => setTimeout(resolve, 200));
      self.removeEventListener('securitypolicyviolation', onViolation);
      return { result, violations };
    }, url);
    rep.check(
      'worker-fetch-blocked',
      probe.result.startsWith('blocked') && probe.violations.some((v) => v.startsWith('connect-src')) && !st.served.includes(url),
      `fetch(${url}) in the extension's service worker -> ${probe.result}; violations ${JSON.stringify(probe.violations)}; route saw it: ${st.served.includes(url)}`,
    );
  });

  // S1: a menu fill types the current code into the focused field, submits nothing, records
  // activity and offers to remember the site in a #bind window.
  step('s1-menu-fill', ['autofill-setup'], async () => {
    const url = `${OTP}/login`;
    const { rec, value, expected, at, win } = await menuFillAndBindWindow(ACCOUNT_A, st.idA, url);
    st.s1 = { rec, url };
    rep.check('s1-menu-fill', value === expected, `field on ${url} holds ${JSON.stringify(value)}; reference ${expected} at ${new Date(at).toISOString()}`);
    await sleep(500);
    rep.check('s1-no-submit', stayed(rec, url), `page still at ${rec.page.url()}, ${rec.navigations} top-frame navigation(s) (only the test's own load)`);
    st.bindWin = win;
    let shown = null;
    if (win) {
      await waitState(win, 'bind', 10000).catch(() => {});
      shown = await win.evaluate(() => ({
        state: document.body.dataset.state,
        origin: document.querySelector('#bind-origin')?.textContent?.trim() ?? null,
        account: document.querySelector('#bind-account')?.textContent?.trim() ?? null,
      }));
    }
    rep.check(
      's1-bind-window',
      Boolean(win) && shown?.state === 'bind' && shown?.origin === OTP,
      win ? `window ${ownUrl('bind')} (now ${win.url()}): state ${shown?.state}, #bind-origin ${JSON.stringify(shown?.origin)}, #bind-account ${JSON.stringify(shown?.account)}` : `no page showed ${ownUrl('bind')}`,
    );
    const { session } = await storage();
    const pending = session.pendingBind;
    rep.check(
      's1-pending-bind',
      pending?.origin === OTP && pending?.accountId === st.idA && Number.isFinite(pending?.at) && session.lastActiveAt >= at,
      `session pendingBind ${JSON.stringify(pending)}, lastActiveAt ${session.lastActiveAt} (menu fill at ${at}, must be refreshed)`,
    );
    checkSessionKeys('storage-keys:after-menu-fill', session);
    if (!win) throw new Error('no #bind window');
  });

  // S2: Allow in the #bind window stores the binding in the vault, registers the content script
  // for exactly that origin and clears the pending bind; the window closes.
  step('s2-bind-allow', ['s1-menu-fill'], async () => {
    await st.bindWin.click('#bind-allow', { timeout: 5000 });
    const closed = await poll(async () => st.bindWin.isClosed(), 10000);
    const data = await poll(async () => {
      const d = await vaultData();
      return bindingsIn(d).some((b) => b?.origin === OTP) ? d : null;
    });
    const bindings = bindingsIn(data ?? (await vaultData()));
    rep.check(
      's2-binding-stored',
      bindings.length === 1 && bindings[0].origin === OTP && bindings[0].accountId === st.idA && Number.isFinite(bindings[0].createdAt),
      `vault opened here with the passphrase: bindings ${JSON.stringify(bindings)}`,
    );
    const script = await poll(autofillScript);
    // Exactly the bound origin, every frame, after load, and the two files of the content script
    // (lib/fieldfind.js, a classic script that sets the field finder, then content/autofill.js).
    rep.check(
      's2-registration',
      JSON.stringify(script?.matches) === JSON.stringify([`${OTP}/*`]) &&
        JSON.stringify(script?.js) === JSON.stringify(CONTENT_SCRIPT_FILES) &&
        script?.allFrames === true &&
        script?.runAt === 'document_idle',
      `chrome.scripting.getRegisteredContentScripts() from an extension page: ${JSON.stringify(await registered())}`,
    );
    const { session, local, sync } = await storage();
    rep.check('s2-pending-cleared', !('pendingBind' in session) && Boolean(closed), `session keys [${Object.keys(session)}] (no pendingBind); #bind window closed ${Boolean(closed)}`);
    rep.check(
      'storage-keys:after-bind',
      Object.keys(local).join() === 'vault' && Object.keys(sync).length === 0 && Object.keys(session).every((k) => SESSION_KEYS_ALLOWED.includes(k)),
      `local [${Object.keys(local)}] (exactly [vault]), sync [${Object.keys(sync)}], session [${Object.keys(session)}] (within [${SESSION_KEYS_ALLOWED}])`,
    );
    if (!script) throw new Error('no registration');
  });

  // S3: later loads of the bound origin are filled once with the current code; nothing else is.
  step('s3-autofill-bound', ['s2-bind-allow'], async () => {
    await waitForFreshPeriod(ACCOUNT_A);
    const lastBefore = (await storage()).session.lastActiveAt;
    const url = `${OTP}/login`;
    const rec = await openTestPage(url);
    st.s3 = rec;
    const value = await fieldValue(rec.page, '#otp', digitsPattern(ACCOUNT_A), 10000);
    const expected = codeAt(ACCOUNT_A, Date.now());
    rep.check('s3-autofill-bound', value === expected && rec.worlds.inMainFrame() >= 1, `fresh tab ${url}: field ${JSON.stringify(value)}, reference ${expected}; content-script worlds in the top frame ${rec.worlds.inMainFrame()}`);
    await sleep(500);
    rep.check('s3-no-submit', stayed(rec, url), `page still at ${rec.page.url()}, ${rec.navigations} top-frame navigation(s)`);
    const lastAfter = (await storage()).session.lastActiveAt;
    rep.check('s3-autofill-no-touch', lastAfter === lastBefore, `session lastActiveAt ${lastBefore} before, ${lastAfter} after the auto-fill (must not change)`);
  });

  step('s3-unbound-origin', ['s2-bind-allow'], async () => {
    const url = `${EVIL}/login`;
    const rec = await openTestPage(url);
    await sleep(NO_FILL_WAIT_MS);
    const value = await rec.page.evaluate(() => document.querySelector('#otp').value);
    // The same detector saw the script on otp.test in s3-autofill-bound.
    rep.check(
      's3-unbound-origin',
      value === '' && rec.worlds.inMainFrame() === 0,
      `${url} (same page as otp.test) after ${NO_FILL_WAIT_MS} ms: field ${JSON.stringify(value)}, content-script worlds in the top frame ${rec.worlds.inMainFrame()} (otp.test: ${st.s3?.worlds.inMainFrame() ?? 'not run'})`,
    );
    await rec.page.close();
  });

  step('s3-iframe', ['s2-bind-allow'], async () => {
    await waitForFreshPeriod(ACCOUNT_A);
    const rec = await openTestPage(`${HOST}/`, [OTP]);
    const frame = await (await rec.page.waitForSelector('iframe', { timeout: 10000 })).contentFrame();
    const value = await fieldValue(frame, '#otp', digitsPattern(ACCOUNT_A), 10000);
    const expected = codeAt(ACCOUNT_A, Date.now());
    await sleep(500);
    const top = await rec.page.evaluate(() => document.querySelector('#otp').value);
    let diagnosis = '';
    if (value !== expected) diagnosis = `; iframe: ${await describeFrame(frame)}`;
    rep.check(
      's3-iframe',
      value === expected && top === '' && rec.worlds.inMainFrame() === 0,
      `${HOST}/ framing ${OTP}/frame: iframe field ${JSON.stringify(value)} (reference ${expected}), host.test field ${JSON.stringify(top)}, content-script worlds in the host.test frame ${rec.worlds.inMainFrame()}${diagnosis}`,
    );
    await rec.page.close();
  });

  step('s3-locked', ['s3-autofill-bound'], async () => {
    const seeded = await seedPendingBind();
    await lockFromPopup();
    await checkSessionEmpty('lock-session-empty:autofill-manual', 'Lock button while a site is bound', seeded);
    await reload(st.s3);
    // A fresh tab shows whether the script was injected (see watchContentScripts): it is, and the
    // worker gives it nothing.
    const fresh = await openTestPage(`${OTP}/login`);
    await sleep(NO_FILL_WAIT_MS);
    const value = await st.s3.page.evaluate(() => document.querySelector('#otp').value);
    const freshValue = await fresh.page.evaluate(() => document.querySelector('#otp').value);
    rep.check(
      's3-locked-no-fill',
      value === '' && freshValue === '' && fresh.worlds.inMainFrame() >= 1,
      `locked: reload ${OTP}/login -> field ${JSON.stringify(value)} after ${NO_FILL_WAIT_MS} ms; fresh tab -> field ${JSON.stringify(freshValue)}, the script was injected (${fresh.worlds.inMainFrame()} world) and got no code`,
    );
    await fresh.page.close();
  });

  step('s3-unlocked-refill', ['s3-locked'], async () => {
    await unlockIn(st.popup);
    await waitState(st.popup, 'list');
    await waitForFreshPeriod(ACCOUNT_A);
    await reload(st.s3);
    const value = await fieldValue(st.s3.page, '#otp', digitsPattern(ACCOUNT_A), 10000);
    const expected = codeAt(ACCOUNT_A, Date.now());
    rep.check('s3-unlocked-refill', value === expected, `unlocked again, reload ${OTP}/login: field ${JSON.stringify(value)}, reference ${expected}`);
  });

  // Idle: lastActiveAt older than 15 minutes. No extension page is open, so the worker is what
  // finds the session idle (on the content script's request) and clears it.
  step('s3-idle', ['s3-unlocked-refill'], async () => {
    await st.popup.close();
    st.popup = undefined;
    const stale = Date.now() - (IDLE_LOCK_MS + 60 * 1000);
    const seeded = await seedPendingBind({ lastActiveAt: stale });
    await reload(st.s3);
    await sleep(NO_FILL_WAIT_MS);
    const value = await st.s3.page.evaluate(() => document.querySelector('#otp').value);
    const { session } = await storage();
    rep.check(
      's3-idle-no-fill',
      value === '' && session.vaultKey === undefined,
      `lastActiveAt set to ${new Date(stale).toISOString()} (16 min ago), reload ${OTP}/login: field ${JSON.stringify(value)}; session vaultKey ${session.vaultKey === undefined ? 'gone' : 'still stored'}`,
    );
    await checkSessionEmpty('lock-session-empty:idle-worker', 'idle session found by the worker', seeded);
    st.popup = await openPopup();
    await waitState(st.popup, 'locked', 15000);
  });

  // S4: Settings lists the binding; Remove drops it from the vault and unregisters the script.
  step('s4-remove-binding', ['s3-idle'], async () => {
    await unlockIn(st.popup);
    await waitState(st.popup, 'list');
    await st.popup.click('#settings-btn');
    await waitState(st.popup, 'settings');
    const row = st.popup.locator(`#bindings .binding[data-origin="${OTP}"]`);
    const listed = await row.waitFor({ timeout: 10000 }).then(() => true, () => false);
    const rowText = listed ? (await row.textContent()).replace(/\s+/g, ' ').trim() : '';
    rep.check('s4-settings-row', listed, `#bindings .binding[data-origin="${OTP}"]: ${listed ? JSON.stringify(rowText) : 'not shown'}`);
    if (!listed) throw new Error('no binding row');
    await row.locator('.binding-remove').click();
    // A remove that asks for a second click (like the account delete) gets it.
    if (!(await poll(async () => (await row.count()) === 0, 3000))) {
      console.log('INFO s4 .binding-remove needed a second click');
      if ((await row.count()) > 0) await row.locator('.binding-remove').click();
    }
    const gone = await poll(async () => (await row.count()) === 0, 10000);
    const data = await poll(async () => {
      const d = await vaultData();
      return !d.error && !bindingsIn(d).some((b) => b?.origin === OTP) ? d : null;
    });
    const unregistered = await poll(async () => {
      const s = await autofillScript();
      return !s || !s.matches.includes(`${OTP}/*`);
    });
    rep.check(
      's4-binding-removed',
      Boolean(gone && data && unregistered),
      `row gone ${Boolean(gone)}; vault bindings ${JSON.stringify(bindingsIn(data ?? (await vaultData())))}; registrations ${JSON.stringify(await registered())}`,
    );
    // The test copy holds otp.test as a required host permission, which permissions.remove()
    // cannot take away; only an optional grant (the shipped design) is removable, and observing
    // that needs the native prompt. Reported, not asserted.
    const contains = await st.popup.evaluate((o) => chrome.permissions.contains({ origins: [`${o}/*`] }), OTP);
    console.log(`INFO s4 chrome.permissions.contains(${OTP}/*) after remove: ${contains} (required host permission in the test copy)`);
    await reload(st.s3);
    const fresh = await openTestPage(`${OTP}/login`);
    await sleep(NO_FILL_WAIT_MS);
    const value = await st.s3.page.evaluate(() => document.querySelector('#otp').value);
    const freshValue = await fresh.page.evaluate(() => document.querySelector('#otp').value);
    rep.check(
      's4-after-remove-no-fill',
      value === '' && freshValue === '' && fresh.worlds.inMainFrame() === 0,
      `reload ${OTP}/login -> field ${JSON.stringify(value)}; fresh tab -> field ${JSON.stringify(freshValue)}, content-script worlds ${fresh.worlds.inMainFrame()} (not injected any more)`,
    );
    await fresh.page.close();
    await st.popup.click('#settings-back');
    await waitState(st.popup, 'list');
  });

  // Deleting an account deletes its bindings in the same vault write; the script goes too.
  step('delete-account-bindings', ['s4-remove-binding'], async () => {
    const url = `${OTP}/login`;
    const { rec, value, expected, win } = await menuFillAndBindWindow(ACCOUNT_B, st.idB, url);
    rep.check('menu-fill-8-digits', value === expected, `account ${ACCOUNT_B.issuer} (${ACCOUNT_B.algorithm}/${ACCOUNT_B.digits}/${ACCOUNT_B.period}s): field ${JSON.stringify(value)}, reference ${expected}`);
    if (!win) throw new Error('no #bind window');
    await waitState(win, 'bind', 10000);
    await win.click('#bind-allow', { timeout: 5000 });
    const bound = await poll(async () => bindingsIn(await vaultData()).some((b) => b?.origin === OTP && b?.accountId === st.idB));
    const script = await poll(autofillScript);
    if (!bound || !script) throw new Error(`binding for ${ACCOUNT_B.issuer} not set up: stored ${Boolean(bound)}, registered ${Boolean(script)}`);
    await rec.page.close();
    await st.popup.bringToFront();
    await st.popup.click('#edit-btn');
    const accountRow = st.popup.locator(`.account[data-id="${st.idB}"]`);
    await accountRow.locator('.delete').click();
    await accountRow.locator('.delete').click();
    const rowGone = await poll(async () => (await accountRow.count()) === 0, 10000);
    await st.popup.click('#edit-btn');
    const data = await poll(async () => {
      const d = await vaultData();
      return Array.isArray(d.accounts) && !d.accounts.some((a) => a?.id === st.idB) && !bindingsIn(d).some((b) => b?.accountId === st.idB) ? d : null;
    });
    const unregistered = await poll(async () => !(await autofillScript()));
    rep.check(
      'delete-account-bindings',
      Boolean(rowGone && data && unregistered),
      `${ACCOUNT_B.issuer} deleted (row gone ${Boolean(rowGone)}): vault accounts ${JSON.stringify((data ?? (await vaultData())).accounts?.map((a) => a.issuer))}, bindings ${JSON.stringify(bindingsIn(data ?? (await vaultData())))}; registrations ${JSON.stringify(await registered())}`,
    );
  });

  // Locked: an account item fills nothing and opens the #unlock window instead.
  step('menu-locked', ['autofill-setup'], async () => {
    if (!st.popup) st.popup = await openPopup();
    if ((await st.popup.evaluate(() => document.body.dataset.state)) !== 'locked') await lockFromPopup();
    const url = `${OTP}/login`;
    const rec = await openTestPage(url);
    await rec.page.bringToFront();
    await rec.page.focus('#otp');
    const tabId = await tabIdOf(url);
    const before = st.pages.count();
    await menuClick(st.idA, url, tabId);
    const win = await st.pages.waitForUrl((u) => u === ownUrl('unlock'), { after: before, timeout: 10000 });
    await sleep(1000);
    const value = await rec.page.evaluate(() => document.querySelector('#otp').value);
    const { session } = await storage();
    rep.check('menu-locked-no-fill', value === '' && !('pendingBind' in session), `locked, menu item for ${ACCOUNT_A.issuer}: field ${JSON.stringify(value)}, session keys [${Object.keys(session)}]`);
    let state = null;
    if (win) {
      st.consoles.push(watchConsole(win));
      state = await win.waitForSelector('body[data-state="locked"]', { timeout: 10000 }).then(() => 'locked', async () => win.evaluate(() => document.body.dataset.state));
    }
    rep.check('menu-locked-unlock-window', Boolean(win) && state === 'locked', win ? `window ${ownUrl('unlock')}: state ${state}` : `no page showed ${ownUrl('unlock')}`);
    st.unlockWin = win;
    await rec.page.close();
  });

  // A lock while a bind offer is pending removes it with the key; Allow afterwards stores nothing.
  // On host.test, which no earlier step binds; its top frame has an OTP field of its own.
  step('lock-with-pending-bind', ['menu-locked'], async () => {
    if (st.unlockWin && !st.unlockWin.isClosed() && (await st.unlockWin.evaluate(() => document.body.dataset.state)) === 'locked') await unlockIn(st.unlockWin);
    else await unlockIn(st.popup);
    if (!(await poll(async () => (await storage()).session.vaultKey))) throw new Error('did not unlock');
    const url = `${HOST}/`;
    const { rec, value, expected, win } = await menuFillAndBindWindow(ACCOUNT_A, st.idA, url, [OTP]);
    const pending = (await storage()).session.pendingBind;
    console.log(`INFO menu fill on ${url}: field ${JSON.stringify(value)}, reference ${expected}; pendingBind ${JSON.stringify(pending)}`);
    if (pending?.origin !== HOST || !win) throw new Error(`no pending bind for ${HOST} (${JSON.stringify(pending)}) or no #bind window`);
    await lockFromPopup();
    await checkSessionEmpty('lock-session-empty:pending-bind', 'Lock button while a bind offer was pending');
    // The window may already show the locked view; then there is nothing to click.
    await win.click('#bind-allow', { timeout: 2000 }).catch(() => {});
    await sleep(1500);
    await unlockIn(st.popup);
    await waitState(st.popup, 'list');
    const bindings = bindingsIn(await vaultData());
    const script = await autofillScript();
    rep.check(
      's2-locked-meanwhile-nothing-stored',
      !bindings.some((b) => b?.origin === HOST) && !script?.matches?.includes(`${HOST}/*`),
      `Allow after the lock: vault bindings ${JSON.stringify(bindings)}, registrations ${JSON.stringify(await registered())} (nothing for ${HOST})`,
    );
    await rec.page.close();
  });

  step('autofill-summary', ['autofill-setup'], async () => {
    const { local, sync, session } = await storage();
    rep.check(
      'storage-keys:autofill-end',
      Object.keys(local).join() === 'vault' && Object.keys(sync).length === 0 && Object.keys(session).every((k) => SESSION_KEYS_ALLOWED.includes(k)),
      `local [${Object.keys(local)}], sync [${Object.keys(sync)}], session [${Object.keys(session)}]`,
    );
    const egress = st.net.egressBeyondTestPages();
    rep.check('no-egress:autofill', egress.length === 0, `remote requests other than the test's own page loads (${st.served.length} routed): ${JSON.stringify(egress)}`);
    const errors = st.consoles.flat().filter((l) => l.startsWith('pageerror:'));
    rep.check('no-uncaught-errors:autofill', errors.length === 0, errors.join(' | ') || 'none');
  });

  // ---- run them ---------------------------------------------------------------------------------

  if (missing.length) {
    for (const { name } of steps) rep.fail(name, `pending integration: ${missing.join(', ')} not in ${extensionDir}`);
    return { pages: null, ownOrigin: null };
  }
  try {
    for (const { name, needs, fn } of steps) {
      const blocked = needs.filter((n) => st.failed.has(n));
      if (blocked.length) {
        st.failed.add(name);
        rep.fail(name, `not run: ${blocked.join(', ')} failed`);
        continue;
      }
      const before = rep.failed;
      try {
        await fn();
        if (rep.failed > before) st.failed.add(name);
      } catch (err) {
        st.failed.add(name);
        rep.fail(name, err.message.split('\n')[0]);
      }
    }
  } finally {
    if (st.context) await st.context.close().catch(() => {});
    if (profile) fs.rmSync(profile, { recursive: true, force: true });
    if (copyDir) fs.rmSync(copyDir, { recursive: true, force: true });
  }
  return { pages: st.pages ?? null, ownOrigin: st.ownOrigin ?? null };
}

// On its own: the extension under test is E2E_EXTENSION or extension/.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const rep = createReporter();
  const extensionDir = realExtensionDir(process.env.E2E_EXTENSION || path.join(REPO_ROOT, 'extension'));
  const { pages, ownOrigin } = await runAutofill({ rep, extensionDir });
  if (pages) {
    const offenders = pages.offenders([ownOrigin]);
    rep.check('no-navigation:autofill', offenders.length === 0, `${pages.count()} pages; URLs outside ${ownOrigin}, about:blank and the test's own routed pages: ${JSON.stringify(offenders)}`);
  }
  rep.finish('e2e-autofill');
}
