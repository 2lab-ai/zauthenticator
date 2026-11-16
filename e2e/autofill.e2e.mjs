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
//                              because a click in the browser's context menu cannot be automated,
//                              and __zauthTest.frameIdFor, the frameId such a click reports for a
//                              frame.
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
const SESSION_KEYS_ALLOWED = ['vaultKey', 'lastActiveAt', 'pendingBind', 'autofillServed'];
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
// Two more numeric fields sized for a code ahead of the OTP field: a zip code (named for another
// number) and one with no name at all. One fill per page load: only #otp may be filled.
const MULTI_PATH = '/multi';
const MULTI_HTML = `<!doctype html><html><head>${HEAD}<title>Sign in</title></head><body><form method="post" action="/submitted"><label>Zip <input id="zip" name="zip" inputmode="numeric" maxlength="6"></label><label>Number <input inputmode="numeric" maxlength="6"></label><label>Code <input id="otp" name="otp" autocomplete="one-time-code"></label><button>Sign in</button></form></body></html>`;
const UNNAMED = 'input[inputmode="numeric"]:not([name]):not([id])';
// Only fields sized like a code, with nothing that says one-time code: a PIN and an unnamed tel
// field (no id or name: "tel" would name it for another number). Auto-fill must fill neither.
const PINONLY_PATH = '/pinonly';
const PINONLY_HTML = `<!doctype html><html><head>${HEAD}<title>PIN</title></head><body><form method="post" action="/submitted"><label>PIN <input name="pin" inputmode="numeric" maxlength="6"></label><label>Number <input type="tel" maxlength="8"></label><button>Go</button></form></body></html>`;
// A sign-in step whose own script plays the site. Sign in turns the code down: with ?reject=empty
// the field is emptied (as for an expired code), with ?reject=swap a new field is put in place of
// the old one (a re-rendered form; the old one is kept as window.oldOtp); a later Sign in only says
// what it got. Every input event on a code field is logged in window.inputs ({ value, trusted }).
// A type="button" outside any form: the page never navigates, so a code that comes back can only
// come from the content script already running in it.
const SPA_PATH = '/spa-login';
const SPA_HTML = `<!doctype html><html><head>${HEAD}<title>Sign in</title></head><body><label>Code <input id="otp" name="otp" autocomplete="one-time-code"></label><button id="go" type="button">Sign in</button><p id="msg"></p><script>
const reject = new URLSearchParams(location.search).get('reject');
window.inputs = [];
document.addEventListener('input', (e) => window.inputs.push({ value: e.target.value, trusted: e.isTrusted }), true);
let tries = 0;
document.getElementById('go').addEventListener('click', () => {
  tries += 1;
  const msg = document.getElementById('msg');
  const otp = document.getElementById('otp');
  if (tries > 1) {
    msg.textContent = 'got ' + otp.value;
  } else if (reject === 'swap') {
    const next = document.createElement('input');
    next.id = 'otp';
    next.name = 'otp';
    next.autocomplete = 'one-time-code';
    window.oldOtp = otp;
    otp.replaceWith(next);
    msg.textContent = 'invalid code';
  } else {
    otp.value = '';
    msg.textContent = 'invalid code';
  }
});
</script></body></html>`;
// A site that submits as soon as a whole code is typed and reloads the sign-in page when it turns
// the code down. Every code it got is kept in localStorage under "submits:" + the ?run= value
// ({ code, at }), so the list survives the reloads; after 8 it stops reloading (a run without
// limits would otherwise loop).
const AUTO_SUBMIT_PATH = '/auto-submit';
const AUTO_SUBMIT_HTML = `<!doctype html><html><head>${HEAD}<title>Sign in</title></head><body><label>Code <input id="otp" name="otp" autocomplete="one-time-code"></label><p id="msg"></p><script>
const key = 'submits:' + new URLSearchParams(location.search).get('run');
const submits = JSON.parse(localStorage.getItem(key) || '[]');
document.getElementById('msg').textContent = submits.length + ' codes turned down';
document.getElementById('otp').addEventListener('input', (e) => {
  if (!/^[0-9]{6}$/.test(e.target.value)) return;
  submits.push({ code: e.target.value, at: Date.now() });
  localStorage.setItem(key, JSON.stringify(submits));
  if (submits.length < 8) setTimeout(() => location.reload(), 200);
});
</script></body></html>`;

async function routeTestOrigins(context) {
  const served = [];
  const pages = new Map([
    [MULTI_PATH, MULTI_HTML],
    [PINONLY_PATH, PINONLY_HTML],
    [SPA_PATH, SPA_HTML],
    [AUTO_SUBMIT_PATH, AUTO_SUBMIT_HTML],
  ]);
  for (const origin of TEST_ORIGINS) {
    await context.route(`${origin}/**`, (route) => {
      const url = new URL(route.request().url());
      served.push(url.href);
      const body = url.origin === HOST ? HOST_HTML : (pages.get(url.pathname) ?? LOGIN_HTML);
      return route.fulfill({ status: 200, contentType: 'text/html', body });
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

// A page's content script that filled a field asks for the next code right after the period ends
// (it keeps the filled code current). Waits until the current period is at least 2 s old and has
// at least 2 s left, so a short storage read-back sees no such request.
async function clearOfPeriodEnds(account) {
  const periodMs = account.period * 1000;
  const into = Date.now() % periodMs;
  if (into < 2000) await sleep(2000 - into);
  else if (periodMs - into < 2000) await sleep(periodMs - into + 2000);
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

  // ---- menu clicks inside a frame --------------------------------------------------------------

  // A fresh tab on https://host.test/, which frames https://otp.test/frame; both documents have an
  // #otp field. → { rec, tabId, frame, frameId } once the frame's field is there. frameId is what the
  // browser reports for the frame (__zauthTest.frameIdFor); anything but a subframe id throws, since
  // a click aimed at the top frame would make every "nothing filled" check pass for nothing.
  async function openFramedPage() {
    const url = `${HOST}/`;
    const rec = await openTestPage(url, [OTP, EVIL]);
    await rec.page.bringToFront();
    const frame = await (await rec.page.waitForSelector('iframe', { timeout: 10000 })).contentFrame();
    await frame.waitForSelector('#otp', { timeout: 10000 });
    const tabId = await tabIdOf(url);
    const frameId = await frameIdOf(tabId, `${OTP}/frame`);
    if (!Number.isInteger(frameId) || frameId <= 0) throw new Error(`no subframe id for ${OTP}/frame in tab ${tabId} (got ${frameId})`);
    return { rec, tabId, frame, frameId };
  }
  const frameIdOf = (tabId, url) => inWorker(({ tab, u }) => globalThis.__zauthTest.frameIdFor(tab, u), { tab: tabId, u: url });
  // Focuses #otp in `frame` and makes sure it is the frame document's active element.
  async function focusIn(frame) {
    await frame.focus('#otp');
    const active = await frame.evaluate(() => document.activeElement?.id ?? null);
    if (active !== 'otp') throw new Error(`focus did not land on #otp in ${frame.url()} (active element #${active})`);
  }
  // What a context-menu click on an account item inside a frame delivers to the worker. A null
  // frameUrl leaves the key out, as the browser does when it has no URL for the frame.
  const frameMenuClick = (accountId, tabId, { frameId, frameUrl, pageUrl }) =>
    inWorker(
      ({ id, tab, frame, fu, pu }) => {
        const info = { menuItemId: `acct:${id}`, editable: true, frameId: frame, pageUrl: pu };
        if (fu !== null) info.frameUrl = fu;
        return globalThis.__zauthTest.handleMenuClick(info, { id: tab, url: pu });
      },
      { id: accountId, tab: tabId, frame: frameId, fu: frameUrl ?? null, pu: pageUrl },
    );
  // The state of a #bind window: its view and the origin and account it shows.
  async function bindShown(win) {
    await waitState(win, 'bind', 10000).catch(() => {});
    return win.evaluate(() => ({
      state: document.body.dataset.state,
      origin: document.querySelector('#bind-origin')?.textContent?.trim() ?? null,
      account: document.querySelector('#bind-account')?.textContent?.trim() ?? null,
    }));
  }
  // What a menu click in `frame` of the framed page left behind: both fields, a #bind window opened
  // since page count `before` (with what it shows), and the session's pending offer.
  async function afterFrameClick(rec, frame, before) {
    const frameValue = await frame.evaluate(() => document.querySelector('#otp')?.value ?? null).catch((err) => `unreadable (${err.message.split('\n')[0]})`);
    const hostValue = await rec.page.evaluate(() => document.querySelector('#otp').value);
    const win = await st.pages.waitForUrl((u) => u === ownUrl('bind'), { after: before, timeout: 0 });
    if (win) st.consoles.push(watchConsole(win));
    const shown = win ? await bindShown(win).catch(() => null) : null;
    const pending = (await storage()).session.pendingBind ?? null;
    const detail = `${frame.url()} field ${JSON.stringify(frameValue)}, ${HOST} field ${JSON.stringify(hostValue)}; #bind window ${win ? `showing origin ${JSON.stringify(shown?.origin)} (state ${shown?.state})` : 'none'}; session pendingBind ${JSON.stringify(pending)}`;
    return { frameValue, hostValue, win, shown, pending, detail };
  }
  // The control popup page is open and the vault unlocked: unlocks it there when it is not.
  async function ensureUnlocked() {
    const opened = !st.popup || st.popup.isClosed();
    if (opened) st.popup = await openPopup();
    if ((await storage()).session.vaultKey) return;
    if (!opened) await st.popup.reload();
    await waitState(st.popup, 'locked', 15000);
    await unlockIn(st.popup);
    if (!(await poll(async () => (await storage()).session.vaultKey))) throw new Error('did not unlock');
    await waitState(st.popup, 'list');
  }

  // Asks the worker for a code from the content script's own isolated world in the top frame of
  // `page`, as content/autofill.js does (the worker sees the same tab, origin and extension id).
  // → the reply, or { error }
  async function askAsContentScript(page) {
    const cdp = await st.context.newCDPSession(page);
    try {
      const { frameTree } = await cdp.send('Page.getFrameTree');
      const worlds = [];
      cdp.on('Runtime.executionContextCreated', ({ context }) => {
        if (context.auxData?.type === 'isolated' && context.origin === st.ownOrigin && context.auxData.frameId === frameTree.frame.id) worlds.push(context.id);
      });
      await cdp.send('Runtime.enable');
      await sleep(200);
      if (worlds.length === 0) return { error: 'no content-script world in the top frame' };
      const { result } = await cdp.send('Runtime.evaluate', {
        contextId: worlds.at(-1),
        awaitPromise: true,
        returnByValue: true,
        expression: "chrome.runtime.sendMessage({ type: 'autofill-code' })",
      });
      return result.value ?? { error: result.description ?? 'no value' };
    } catch (err) {
      return { error: err.message.split('\n')[0] };
    } finally {
      await cdp.detach().catch(() => {});
    }
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

  // S1, a click inside a frame: the origin checked and offered is the frame's own, read from the
  // click's frameUrl, never the embedding page's. Without a frameUrl there is no origin to check:
  // nothing is filled and nothing offered. Run while nothing is bound, so no content script fills
  // the frame either (menu-iframe-bind, at the end, is the click that does fill).
  step('menu-iframe-no-frame-url', ['autofill-setup'], async () => {
    const f = await openFramedPage();
    try {
      await focusIn(f.frame);
      await waitForFreshPeriod(ACCOUNT_A);
      const before = st.pages.count();
      await frameMenuClick(st.idA, f.tabId, { frameId: f.frameId, frameUrl: null, pageUrl: `${HOST}/` });
      await sleep(NO_FILL_WAIT_MS);
      const seen = await afterFrameClick(f.rec, f.frame, before);
      rep.check(
        'menu-iframe-no-frame-url',
        seen.frameValue === '' && seen.hostValue === '' && !seen.win && seen.pending === null,
        `click in frame ${f.frameId} (${OTP}/frame) with pageUrl ${HOST}/ and no frameUrl, after ${NO_FILL_WAIT_MS} ms: ${seen.detail} (must be: both fields empty, no window, no offer)`,
      );
      if (seen.win && !seen.win.isClosed()) await seen.win.close();
    } finally {
      await f.rec.page.close();
    }
  });

  // S1, the frame navigated to another origin between the click and the fill: the click says
  // otp.test, the frame now shows evil.test. Nothing is filled there and nothing is offered.
  step('menu-origin-changed', ['autofill-setup'], async () => {
    const f = await openFramedPage();
    try {
      const evilUrl = `${EVIL}/frame`;
      await f.rec.page.evaluate((u) => {
        document.querySelector('iframe').src = u;
      }, evilUrl);
      const frame = await poll(async () => {
        const fr = await (await f.rec.page.$('iframe'))?.contentFrame();
        return fr && fr.url() === evilUrl ? fr : null;
      });
      if (!frame) throw new Error(`the frame did not navigate to ${evilUrl}`);
      await frame.waitForSelector('#otp', { timeout: 10000 });
      // The same frame (the browser keeps a frame's id across navigations), now at evil.test.
      const evilId = await frameIdOf(f.tabId, evilUrl);
      if (evilId !== f.frameId) throw new Error(`frame id ${f.frameId} at ${OTP}/frame, ${evilId} at ${evilUrl}: not the same frame`);
      await focusIn(frame);
      await waitForFreshPeriod(ACCOUNT_A);
      const before = st.pages.count();
      await frameMenuClick(st.idA, f.tabId, { frameId: f.frameId, frameUrl: `${OTP}/frame`, pageUrl: `${HOST}/` });
      await sleep(NO_FILL_WAIT_MS);
      const seen = await afterFrameClick(f.rec, frame, before);
      rep.check(
        'menu-origin-changed',
        seen.frameValue === '' && seen.hostValue === '' && !seen.win && seen.pending === null,
        `click in frame ${f.frameId} with frameUrl ${OTP}/frame while the frame shows ${frame.url()}, after ${NO_FILL_WAIT_MS} ms: ${seen.detail} (must be: both fields empty, no window, no offer)`,
      );
      if (seen.win && !seen.win.isClosed()) await seen.win.close();
    } finally {
      await f.rec.page.close();
    }
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

  // One fill per page load, and only the OTP field: a zip code field and an unnamed numeric field,
  // both sized for a code and ahead of it in the page, stay empty.
  step('s3-one-fill-per-page', ['s2-bind-allow'], async () => {
    await waitForFreshPeriod(ACCOUNT_A);
    const url = `${OTP}${MULTI_PATH}`;
    const rec = await openTestPage(url);
    const value = await fieldValue(rec.page, '#otp', digitsPattern(ACCOUNT_A), 10000);
    const expected = codeAt(ACCOUNT_A, Date.now());
    await sleep(NO_FILL_WAIT_MS);
    const now = await rec.page.evaluate((unnamed) => ({ otp: document.querySelector('#otp').value, zip: document.querySelector('#zip').value, unnamed: document.querySelector(unnamed).value }), UNNAMED);
    rep.check(
      's3-one-fill-per-page',
      value === expected && now.otp === expected && now.zip === '' && now.unnamed === '',
      `${url}: #otp ${JSON.stringify(value)} (reference ${expected}); ${NO_FILL_WAIT_MS} ms later #otp ${JSON.stringify(now.otp)}, #zip (inputmode numeric, maxlength 6) ${JSON.stringify(now.zip)}, unnamed numeric maxlength-6 field ${JSON.stringify(now.unnamed)} (both must stay empty)`,
    );
    await rec.page.close();
  });

  // Auto-fill needs a sign of a one-time code: on a bound page whose only fields are a PIN and an
  // unnamed tel field, both sized for a code, the content script runs and fills nothing.
  step('s3-no-signal-no-fill', ['s2-bind-allow'], async () => {
    const url = `${OTP}${PINONLY_PATH}`;
    const rec = await openTestPage(url);
    await sleep(NO_FILL_WAIT_MS);
    const now = await rec.page.evaluate(() => ({
      pin: document.querySelector('input[name="pin"]')?.value ?? null,
      tel: document.querySelector('input[type="tel"]')?.value ?? null,
    }));
    rep.check(
      's3-no-signal-no-fill',
      now.pin === '' && now.tel === '' && rec.worlds.inMainFrame() >= 1,
      `${url} after ${NO_FILL_WAIT_MS} ms: pin field (inputmode numeric, maxlength 6) ${JSON.stringify(now.pin)}, unnamed tel maxlength-8 field ${JSON.stringify(now.tel)} (both must stay empty); content-script worlds in the top frame ${rec.worlds.inMainFrame()} (must be at least 1)`,
    );
    await rec.page.close();
  });

  // "Fresh code and retry after a failed attempt" (.prd/03-autofill.md): five tabs of the
  // /spa-login page, all filled by the content script within one period with the same code. The
  // site turns that code down in two of them: one empties the field, one puts a new field in its
  // place; either field then gets the next period's code once it starts, never the code turned
  // down (each page's input log has it once). One tab is left alone: when the period ends its code
  // becomes the next one. In one the user types a code of their own over the filled one, in one the
  // user deletes it: across the same period end the first keeps the user's code, the second stays
  // empty.
  step('s3-retry-after-reject', ['s2-bind-allow'], async () => {
    const page = (reject) => `${OTP}${SPA_PATH}?reject=${reject}`;
    const periodMs = ACCOUNT_A.period * 1000;
    const recs = [];
    const value = (rec) => rec.page.evaluate(() => document.querySelector('#otp')?.value ?? null);
    const inputs = (rec) => rec.page.evaluate(() => window.inputs);
    // The #otp field of `rec` once it holds the reference code of the moment it is read.
    // → { ok, value } (value: what it held last)
    const currentCode = async (rec, timeout) => {
      let last = null;
      const ok = await poll(
        async () => {
          last = await value(rec);
          return last === codeAt(ACCOUNT_A, Date.now());
        },
        timeout,
        100,
      );
      return { ok: Boolean(ok), value: last };
    };
    // How many input events carried `code` in the page's own log.
    const carried = async (rec, code) => (await inputs(rec)).filter((i) => i.value === code).length;
    try {
      await waitForFreshPeriod(ACCOUNT_A, 15000);
      for (const reject of ['empty', 'swap', 'empty', 'empty', 'empty']) recs.push(await openTestPage(page(reject)));
      const [emptied, swapped, idle, user, cleared] = recs;
      const filled = [];
      for (const rec of recs) filled.push(await currentCode(rec, 10000));
      // The end of the period the tabs were filled in, and that period's code.
      const boundary = (Math.floor(Date.now() / periodMs) + 1) * periodMs;
      const first = codeAt(ACCOUNT_A, boundary - 1);
      if (!filled.every((f) => f.ok && f.value === first)) {
        throw new Error(`precondition: /spa-login not auto-filled in one period: tabs ${JSON.stringify(filled.map((f) => f.value))}, reference ${first}`);
      }
      // The user's own code over the filled one, in one edit (no empty field in between).
      const typed = ['111111', '222222', '333333'].find((v) => v !== first && v !== codeAt(ACCOUNT_A, boundary));
      await user.page.fill('#otp', typed);
      // The user deletes the filled code in one edit (select all, Delete): a trusted input event
      // that leaves the field empty, as the page emptying it would, but by the user.
      await cleared.page.fill('#otp', '');
      const userEdit = (await inputs(cleared)).filter((i) => i.trusted);
      if (!userEdit.some((i) => i.value === '')) throw new Error(`precondition: no trusted input event emptied the field: ${JSON.stringify(await inputs(cleared))}`);

      // Sign in turns the code down in two tabs.
      await emptied.page.click('#go');
      await swapped.page.click('#go');
      const leftAtReject = boundary - Date.now();
      const swap = await swapped.page.evaluate(() => ({
        msg: document.querySelector('#msg').textContent,
        oldInPage: window.oldOtp ? window.oldOtp.isConnected : null,
        isNew: document.querySelector('#otp') !== window.oldOtp,
      }));
      const refill = await currentCode(emptied, boundary - Date.now() + 5000);
      rep.check(
        's3-retry-after-reject',
        refill.ok && refill.value !== first && Date.now() > boundary && (await carried(emptied, first)) === 1 && stayed(emptied, page('empty')),
        `${page('empty')}: filled ${first}; Sign in ${leftAtReject} ms before the period end -> the field emptied by the page; then ${JSON.stringify(refill.value)} (the code turned down was ${first}, carried by ${await carried(emptied, first)} input event(s)), reference ${codeAt(ACCOUNT_A, Date.now())}, ${Date.now() - boundary} ms after the period end; ${emptied.navigations} top-frame navigation(s)`,
      );
      const second = await currentCode(swapped, Math.max(0, boundary - Date.now()) + 5000);
      const swapLog = await inputs(swapped);
      rep.check(
        's3-retry-new-field',
        second.ok && second.value !== first && Date.now() > boundary && swap.oldInPage === false && swap.isNew && (await carried(swapped, first)) === 1 && new Set(swapLog.map((i) => i.value)).size === swapLog.length && stayed(swapped, page('swap')),
        `${page('swap')}: filled ${first}; Sign in -> ${JSON.stringify(swap.msg)}, old field in the page ${swap.oldInPage}, a new field ${swap.isNew}; the new field ${JSON.stringify(second.value)} (never ${first}), reference ${codeAt(ACCOUNT_A, Date.now())}, ${Date.now() - boundary} ms after the period end; input events ${JSON.stringify(swapLog)}`,
      );

      // Across the same period end, the other three tabs.
      if (Date.now() < boundary + 1000) await sleep(boundary + 1000 - Date.now());
      const fresh = await currentCode(idle, 5000);
      rep.check(
        's3-keep-fresh',
        fresh.ok && fresh.value !== first && Date.now() > boundary && stayed(idle, page('empty')),
        `untouched tab, period ended at ${new Date(boundary).toISOString()}: the field held ${first}, now ${JSON.stringify(fresh.value)}, reference ${codeAt(ACCOUNT_A, Date.now())}`,
      );
      const kept = await value(user);
      rep.check(
        's3-user-value-kept',
        kept === typed && Date.now() > boundary + 1000 && stayed(user, page('empty')),
        `auto-filled ${first}, then the user typed ${JSON.stringify(typed)}; ${Date.now() - boundary} ms after the period end the field holds ${JSON.stringify(kept)}`,
      );
      const empty = await value(cleared);
      rep.check(
        's3-user-cleared-stays-empty',
        empty === '' && Date.now() > boundary + 1000 && (await carried(cleared, codeAt(ACCOUNT_A, boundary))) === 0 && stayed(cleared, page('empty')),
        `auto-filled ${first}, then the user deleted it (trusted input events ${JSON.stringify(userEdit)}); ${Date.now() - boundary} ms after the period end the field holds ${JSON.stringify(empty)}; input events ${JSON.stringify(await inputs(cleared))}`,
      );
    } finally {
      for (const rec of recs) await rec.page.close();
    }
  });

  // Bounds across page loads (.prd/03-autofill.md, "Fresh code and retry after a failed attempt"):
  // a site that submits as soon as a code is typed and reloads its sign-in page when it turns the
  // code down starts the content script afresh every time. The worker gives that tab each code once
  // and 3 codes in any 5 minutes: the page gets 3 different codes, each the current one when it got
  // it (one per period: about a minute), and then no more. Proof of the stop without waiting a
  // fourth period: a request from the content script's own world in that tab then gets
  // { code: null } outright, not a wait.
  step('s3-reload-budget', ['s2-bind-allow'], async () => {
    // At least 5 s left: a first code with under 3 s left would be counted but not filled.
    await waitForFreshPeriod(ACCOUNT_A, 5000);
    const run = Date.now();
    const url = `${OTP}${AUTO_SUBMIT_PATH}?run=${run}`;
    const rec = await openTestPage(url);
    try {
      const submits = async () => (await rec.page.evaluate((k) => JSON.parse(localStorage.getItem(k) || '[]'), `submits:${run}`).catch(() => null)) ?? [];
      const three = await poll(async () => ((await submits()).length >= 3 ? true : null), 70000, 500);
      // A fourth load asks right after the third reload; give it time to.
      await sleep(3000);
      const got = await submits();
      const reply = await askAsContentScript(rec.page);
      const codes = got.map((x) => x.code);
      const current = got.every((x) => x.code === codeAt(ACCOUNT_A, x.at));
      rep.check(
        's3-reload-budget',
        Boolean(three) && got.length === 3 && new Set(codes).size === 3 && current && reply?.code === null && !Object.hasOwn(reply, 'validMs'),
        `${url} reloads after every code: it got ${JSON.stringify(got.map((x) => ({ code: x.code, reference: codeAt(ACCOUNT_A, x.at), at: new Date(x.at).toISOString() })))} (must be 3, all different, each the reference at its time) over ${got.length ? got.at(-1).at - got[0].at : 0} ms; then a request from the content script's world -> ${JSON.stringify(reply)} (must be { code: null }, no validMs)`,
      );
    } finally {
      await rec.page.close();
    }
  });

  step('s3-locked', ['s3-autofill-bound'], async () => {
    const seeded = await seedPendingBind();
    await lockFromPopup();
    await checkSessionEmpty('lock-session-empty:autofill-manual', 'Lock button while a site is bound', seeded);
    // Locked: the content script is unregistered (the next unlock registers it again).
    const none = await poll(async () => (await registered()).length === 0);
    rep.check('s3-locked-unregistered', Boolean(none), `chrome.scripting.getRegisteredContentScripts() from an extension page while locked: ${JSON.stringify(await registered())} (must be [])`);
    await reload(st.s3);
    // A fresh tab shows whether the script was injected (see watchContentScripts): it is not.
    const fresh = await openTestPage(`${OTP}/login`);
    await sleep(NO_FILL_WAIT_MS);
    const value = await st.s3.page.evaluate(() => document.querySelector('#otp').value);
    const freshValue = await fresh.page.evaluate(() => document.querySelector('#otp').value);
    rep.check(
      's3-locked-no-fill',
      value === '' && freshValue === '' && fresh.worlds.inMainFrame() === 0,
      `locked: reload ${OTP}/login -> field ${JSON.stringify(value)} after ${NO_FILL_WAIT_MS} ms; fresh tab -> field ${JSON.stringify(freshValue)}, content-script worlds in the top frame ${fresh.worlds.inMainFrame()} (not injected while locked)`,
    );
    await fresh.page.close();
  });

  step('s3-unlocked-refill', ['s3-locked'], async () => {
    await unlockIn(st.popup);
    await waitState(st.popup, 'list');
    // The unlock registers the script again, for this browser session only.
    const script = await poll(async () => {
      const s = await autofillScript();
      return s && JSON.stringify(s.matches) === JSON.stringify([`${OTP}/*`]) ? s : null;
    });
    rep.check(
      's3-unlocked-registered',
      script?.persistAcrossSessions === false,
      `after unlock, chrome.scripting.getRegisteredContentScripts() from an extension page: ${JSON.stringify(await registered())} (autofill for [${OTP}/*], persistAcrossSessions false)`,
    );
    await waitForFreshPeriod(ACCOUNT_A);
    const fresh = await openTestPage(`${OTP}/login`);
    await reload(st.s3);
    const freshValue = await fieldValue(fresh.page, '#otp', digitsPattern(ACCOUNT_A), 10000);
    const value = await fieldValue(st.s3.page, '#otp', digitsPattern(ACCOUNT_A), 10000);
    const expected = codeAt(ACCOUNT_A, Date.now());
    rep.check(
      's3-unlocked-refill',
      value === expected && freshValue === expected && fresh.worlds.inMainFrame() >= 1,
      `unlocked again: fresh tab ${OTP}/login -> field ${JSON.stringify(freshValue)}, content-script worlds in the top frame ${fresh.worlds.inMainFrame()}; reload -> field ${JSON.stringify(value)}; reference ${expected}`,
    );
    await fresh.page.close();
  });

  // Idle: lastActiveAt older than 15 minutes. No extension page is open, so the worker is what
  // finds the session idle (on the content script's request) and clears it.
  step('s3-idle', ['s3-unlocked-refill'], async () => {
    await st.popup.close();
    st.popup = undefined;
    // The content script in st.s3 still follows the code it filled: a request of its own in the
    // seed's read-back would find the session idle before the reload does.
    await clearOfPeriodEnds(ACCOUNT_A);
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

  // S1 + S2 from a click inside a cross-origin frame: host.test frames otp.test; the code goes into
  // the frame's field only, the #bind window offers the frame's origin and Allow binds exactly that.
  // Needs an unlocked vault with nothing bound (as the steps above leave it), so that no content
  // script fills the frame and the offer is the frame's first.
  step('menu-iframe-bind', ['autofill-setup'], async () => {
    await ensureUnlocked();
    const already = bindingsIn(await vaultData());
    if (already.length > 0 || (await autofillScript())) {
      throw new Error(`precondition: nothing bound, but vault bindings ${JSON.stringify(already)}, registrations ${JSON.stringify(await registered())}`);
    }
    const f = await openFramedPage();
    let win = null;
    try {
      await focusIn(f.frame);
      await waitForFreshPeriod(ACCOUNT_A);
      const before = st.pages.count();
      const at = Date.now();
      await frameMenuClick(st.idA, f.tabId, { frameId: f.frameId, frameUrl: `${OTP}/frame`, pageUrl: `${HOST}/` });
      const value = await fieldValue(f.frame, '#otp', digitsPattern(ACCOUNT_A), 10000);
      const expected = codeAt(ACCOUNT_A, at);
      win = await st.pages.waitForUrl((u) => u === ownUrl('bind'), { after: before, timeout: 10000 });
      await sleep(500);
      const seen = await afterFrameClick(f.rec, f.frame, before);
      rep.check(
        'menu-iframe-fill',
        value === expected && seen.hostValue === '',
        `click in frame ${f.frameId} (frameUrl ${OTP}/frame, pageUrl ${HOST}/): frame field ${JSON.stringify(value)} (reference ${expected}), ${HOST} field ${JSON.stringify(seen.hostValue)} (must stay empty)`,
      );
      rep.check(
        'menu-iframe-bind-window',
        Boolean(win) && seen.shown?.state === 'bind' && seen.shown?.origin === OTP && seen.pending?.origin === OTP,
        `${seen.detail} (must offer ${OTP}, not ${HOST})`,
      );
      if (!win) throw new Error('no #bind window');
      await win.click('#bind-allow', { timeout: 5000 });
      const data = await poll(async () => {
        const d = await vaultData();
        return bindingsIn(d).some((b) => b?.origin === OTP) ? d : null;
      });
      const bindings = bindingsIn(data ?? (await vaultData()));
      const script = await poll(autofillScript);
      rep.check(
        'menu-iframe-registration',
        bindings.length === 1 && bindings[0].origin === OTP && bindings[0].accountId === st.idA && JSON.stringify(script?.matches) === JSON.stringify([`${OTP}/*`]),
        `after Allow: vault bindings ${JSON.stringify(bindings)}; registrations ${JSON.stringify(await registered())} (exactly [${OTP}/*])`,
      );
    } finally {
      await f.rec.page.close();
      if (win && !win.isClosed()) await win.close();
    }
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
