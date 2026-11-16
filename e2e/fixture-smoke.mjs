// Proves the e2e harness on this machine without the real extension: generates a throwaway
// extension in os.tmpdir() (the architecture doc's manifest and CSP, one page), then checks
// launch, id computation vs. chrome://extensions, page navigation, storage, the CSP network
// block, download capture, screenshots, and that chrome.storage.session dies with the session.
// Part 2 generates a second throwaway extension shaped like the auto-fill design (a module
// service worker, a content script registered at run time, host access for routed test origins)
// and proves the mechanics the auto-fill e2e relies on: reaching the worker, the extension-page
// CSP in the worker, content scripts on routed https pages and cross-site iframes and where
// they did not run, a window the worker opens, a permission request from a real click, and
// that the egress and page watchers exempt only what the test opened itself.
//
//   node e2e/fixture-smoke.mjs            # headed
//   E2E_HEADLESS=1 node e2e/fixture-smoke.mjs

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ARTIFACTS,
  HEADLESS,
  allowTestOrigins,
  computeExtensionId,
  createReporter,
  ensureArtifactsDir,
  extensionWorker,
  freshProfileDir,
  launch,
  openExtensionPage,
  probeFetch,
  readIdsFromExtensionsPage,
  realExtensionDir,
  watchConsole,
  watchContentScripts,
  watchNetwork,
  watchPages,
} from './harness.mjs';

const MANIFEST = {
  manifest_version: 3,
  name: 'zauthenticator-fixture',
  version: '0.0.1',
  permissions: ['storage', 'activeTab'],
  action: { default_popup: 'popup/popup.html' },
  content_security_policy: {
    extension_pages:
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  },
};

const HTML = `<!doctype html>
<html>
<head><meta charset="utf-8"><title>fixture</title></head>
<body data-state="loading">
<button id="export-btn">export</button>
<script type="module" src="popup.js"></script>
</body>
</html>
`;

const JS = `document.getElementById('export-btn').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify({ v: 1, ct: 'AAAA' })], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'fixture-backup.json';
  document.body.append(a);
  a.click();
  a.remove();
});
document.body.dataset.state = 'ready';
`;

function makeFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zauth-fixture-ext-'));
  fs.mkdirSync(path.join(root, 'popup'));
  fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify(MANIFEST, null, 2));
  fs.writeFileSync(path.join(root, 'popup', 'popup.html'), HTML);
  fs.writeFileSync(path.join(root, 'popup', 'popup.js'), JS);
  return root;
}

// ---- part 2 fixture: the auto-fill shape ------------------------------------------------------

const CODE = '424242';
const TEST_ORIGINS = ['https://otp.test', 'https://evil.test', 'https://host.test'];
const AUTOFILL_MANIFEST = {
  manifest_version: 3,
  name: 'zauthenticator-fixture-autofill',
  version: '0.0.1',
  permissions: ['storage', 'scripting'],
  host_permissions: TEST_ORIGINS.map((o) => `${o}/*`),
  background: { service_worker: 'worker.js', type: 'module' },
  content_security_policy: { extension_pages: MANIFEST.content_security_policy.extension_pages },
};
const AUTOFILL_FILES = {
  'code.js': `export const CODE = '${CODE}';\n`,
  // A module worker: the import only works with type 'module'.
  'worker.js': `import { CODE } from './code.js';
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === 'fixture-code') sendResponse({ code: CODE, origin: sender.origin ?? null });
});
globalThis.fixture = {
  register: (origin) =>
    chrome.scripting.registerContentScripts([
      { id: 'fixture', matches: [origin + '/*'], js: ['content.js'], allFrames: true, runAt: 'document_idle' },
    ]),
  registered: () => chrome.scripting.getRegisteredContentScripts(),
  openWindow: () => chrome.windows.create({ url: chrome.runtime.getURL('popup/popup.html#bind'), type: 'popup', width: 400, height: 600 }),
  async probeFetch(url) {
    const violations = [];
    const onViolation = (e) => violations.push(e.effectiveDirective + ' ' + e.blockedURI);
    self.addEventListener('securitypolicyviolation', onViolation);
    const result = await fetch(url).then(() => 'ok', (e) => 'blocked:' + e.message);
    await new Promise((resolve) => setTimeout(resolve, 200));
    self.removeEventListener('securitypolicyviolation', onViolation);
    return { result, violations };
  },
};
`,
  // Fills the first input once with the worker's answer and records the sender origin the
  // worker saw, where the page can read it.
  'content.js': `const field = document.querySelector('input');
chrome.runtime.sendMessage({ type: 'fixture-code' }).then((reply) => {
  if (!field || field.value) return;
  field.value = reply.code;
  field.dataset.origin = reply.origin;
});
`,
  // Like the real popup: drops the hash with replaceState as soon as it starts.
  'popup/popup.html': `<!doctype html>
<html><head><meta charset="utf-8"><title>bind</title></head>
<body data-state="loading"><button id="allow">Allow</button><p id="result"></p>
<script type="module" src="popup.js"></script></body></html>
`,
  'popup/popup.js': `const view = location.hash.slice(1);
if (view) history.replaceState(null, '', location.pathname);
document.body.dataset.state = view || 'none';
document.getElementById('allow').addEventListener('click', async () => {
  const result = document.getElementById('result');
  try {
    result.textContent = String(await chrome.permissions.request({ origins: ['https://otp.test/*'] }));
  } catch (err) {
    result.textContent = 'error: ' + err.message;
  }
});
`,
};

function makeAutofillFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zauth-fixture-autofill-'));
  fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify(AUTOFILL_MANIFEST, null, 2));
  for (const [rel, text] of Object.entries(AUTOFILL_FILES)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), text);
  }
  return root;
}

// A login page with one OTP field; the data: icon keeps Chromium from asking for /favicon.ico.
const loginHtml = (title) =>
  `<!doctype html><html><head><meta charset="utf-8"><link rel="icon" href="data:,"><title>${title}</title></head><body><form><input id="otp" autocomplete="one-time-code"><button>Sign in</button></form></body></html>`;

async function routeTestOrigins(context) {
  const served = [];
  for (const origin of [...TEST_ORIGINS, 'https://other.test']) {
    await context.route(`${origin}/**`, (route) => {
      const url = new URL(route.request().url());
      served.push(url.href);
      const body =
        url.origin === 'https://host.test'
          ? `<!doctype html><html><head><meta charset="utf-8"><link rel="icon" href="data:,"></head><body><input id="top-otp" autocomplete="one-time-code"><iframe src="https://otp.test/frame"></iframe></body></html>`
          : loginHtml(url.href);
      return route.fulfill({ status: 200, contentType: 'text/html', body });
    });
  }
  return served;
}

const rep = createReporter();
const extDir = realExtensionDir(makeFixture());
const profile = freshProfileDir();
const computed = computeExtensionId(extDir);
console.log(`INFO mode ${HEADLESS ? "headless (channel 'chromium')" : 'headed'}`);
console.log(`INFO extension ${extDir} computed-id ${computed}`);

let context;
try {
  context = await launch(extDir, profile);
  rep.pass('launch', `chromium ${context.browser()?.version() ?? '(persistent context)'}`);
  const net = watchNetwork(context);

  const listed = await readIdsFromExtensionsPage(context);
  rep.check(
    'id-fallback-agrees',
    listed.length === 1 && listed[0].id === computed,
    `chrome://extensions lists ${JSON.stringify(listed)}`,
  );

  const page = await context.newPage();
  const consoleLines = watchConsole(page);
  const { id, method } = await openExtensionPage(context, page, extDir, 'popup/popup.html');
  const runtimeId = await page.evaluate(() => chrome.runtime.id);
  rep.check('id-computed', method === 'computed' && runtimeId === computed, `method=${method} chrome.runtime.id=${runtimeId}`);
  await page.waitForSelector('body[data-state="ready"]', { timeout: 10000 });
  rep.pass('navigate', page.url());

  const stored = await page.evaluate(async () => {
    await chrome.storage.local.set({ probe: 'local-ok' });
    await chrome.storage.session.set({ probe: 'session-ok' });
    return { local: await chrome.storage.local.get(null), session: await chrome.storage.session.get(null) };
  });
  rep.check(
    'storage',
    stored.local.probe === 'local-ok' && stored.session.probe === 'session-ok',
    JSON.stringify(stored),
  );

  const probe = await probeFetch(page);
  await page.waitForTimeout(300);
  rep.check('fetch-blocked', probe.result.startsWith('blocked'), probe.result);
  rep.check('csp-violation-event', probe.violations.some((v) => v.startsWith('connect-src')), JSON.stringify(probe.violations));
  const cspConsole = consoleLines.filter((l) => /Content Security Policy/i.test(l));
  console.log(`INFO csp-console ${cspConsole.length ? cspConsole.join(' | ') : '(none)'}`);
  console.log(`INFO remote-requests-seen ${JSON.stringify(net.records)}`);

  const [download] = await Promise.all([page.waitForEvent('download', { timeout: 10000 }), page.click('#export-btn')]);
  const body = fs.readFileSync(await download.path(), 'utf8');
  rep.check('download-capture', JSON.parse(body).v === 1, `${download.suggestedFilename()} ${body}`);

  ensureArtifactsDir();
  const shot = path.join(ARTIFACTS, 'fixture-smoke.png');
  await page.screenshot({ path: shot });
  rep.check('screenshot', fs.statSync(shot).size > 0, shot);

  rep.check('no-egress', net.egress().length === 0, `remote requests not blocked by CSP: ${JSON.stringify(net.egress())}`);

  // Positive controls: the request listener sees the extension page's own loads, and a remote
  // request from an ordinary page (answered by a local route, nothing leaves the machine).
  rep.check(
    'monitor-sees-extension-loads',
    net.extensionUrls.some((u) => u.endsWith('/popup/popup.js')),
    `${net.extensionUrls.length} chrome-extension:// requests seen`,
  );
  const control = 'https://monitor-control.invalid/ping';
  await context.route(control, (route) => route.fulfill({ status: 200, body: 'pong' }));
  const plain = await context.newPage();
  await plain.goto('about:blank');
  await plain.evaluate((u) => fetch(u).then((r) => r.text()), control);
  await plain.close();
  rep.check(
    'monitor-sees-remote',
    net.egress().some((r) => r.url === control),
    JSON.stringify(net.egress()),
  );
  await context.close();
  context = undefined;

  // Same profile, new browser session: storage.local persists, storage.session is gone.
  context = await launch(extDir, profile);
  const page2 = await context.newPage();
  const again = await openExtensionPage(context, page2, extDir, 'popup/popup.html');
  const after = await page2.evaluate(async () => ({
    local: await chrome.storage.local.get(null),
    session: await chrome.storage.session.get(null),
  }));
  rep.check(
    'session-restart',
    again.id === computed && after.local.probe === 'local-ok' && after.session.probe === undefined,
    `id=${again.id} ${JSON.stringify(after)}`,
  );
} catch (err) {
  rep.fail('smoke', err?.stack?.split('\n').slice(0, 3).join(' / ') ?? String(err));
} finally {
  if (context) await context.close().catch(() => {});
  context = undefined;
  fs.rmSync(profile, { recursive: true, force: true });
  fs.rmSync(extDir, { recursive: true, force: true });
}

// ---- part 2: auto-fill mechanics --------------------------------------------------------------

const autofillDir = realExtensionDir(makeAutofillFixture());
const autofillId = computeExtensionId(autofillDir);
const profile3 = freshProfileDir();
console.log(`INFO autofill fixture ${autofillDir} computed-id ${autofillId}`);
try {
  context = await launch(autofillDir, profile3);
  const net = watchNetwork(context);
  const pages = watchPages(context);
  const served = await routeTestOrigins(context);

  // The module worker: found among the context's service workers and evaluated in.
  const worker = await extensionWorker(context, autofillId);
  const shape = await (await extensionWorker(context, autofillId)).evaluate(() => typeof globalThis.fixture?.register);
  rep.check('autofill-worker', worker.url() === `chrome-extension://${autofillId}/worker.js` && shape === 'function', `${worker.url()}, fixture.register is a ${shape}`);

  // The extension-page CSP (connect-src 'none') also governs the worker: a fetch to a routed
  // URL is refused before the route sees it.
  const control = 'https://otp.test/worker-fetch-control';
  const swProbe = await (await extensionWorker(context, autofillId)).evaluate((u) => globalThis.fixture.probeFetch(u), control);
  rep.check(
    'autofill-worker-csp',
    swProbe.result.startsWith('blocked') && swProbe.violations.some((v) => v.startsWith('connect-src')) && !served.includes(control),
    `worker fetch(${control}) -> ${swProbe.result}; violations ${JSON.stringify(swProbe.violations)}; route saw it: ${served.includes(control)}`,
  );

  await (await extensionWorker(context, autofillId)).evaluate(() => globalThis.fixture.register('https://otp.test'));
  const registered = await (await extensionWorker(context, autofillId)).evaluate(() => globalThis.fixture.registered());
  rep.check(
    'autofill-register',
    registered.length === 1 && registered[0].id === 'fixture' && JSON.stringify(registered[0].matches) === '["https://otp.test/*"]',
    JSON.stringify(registered),
  );

  // Bound origin: the script runs in the top frame (seen as an isolated world of the
  // extension) and fills the field with the worker's answer; the worker saw the page's origin.
  const bound = await context.newPage();
  allowTestOrigins(bound, ['https://otp.test']);
  const boundWorlds = await watchContentScripts(bound, autofillId);
  await bound.goto('https://otp.test/login');
  const filled = await bound
    .waitForFunction((code) => document.querySelector('#otp')?.value === code, CODE, { timeout: 10000 })
    .then(() => true, () => false);
  const boundState = await bound.evaluate(() => ({ value: document.querySelector('#otp').value, origin: document.querySelector('#otp').dataset.origin ?? null }));
  rep.check(
    'autofill-inject-bound',
    filled && boundState.origin === 'https://otp.test' && boundWorlds.inMainFrame() >= 1,
    `https://otp.test/login: field ${JSON.stringify(boundState.value)}, sender.origin ${boundState.origin}, content-script worlds in the top frame ${boundWorlds.inMainFrame()}`,
  );

  // Unbound origin, same page: no world, no fill. Meaningful because the same detector saw the
  // script on otp.test just above.
  const unbound = await context.newPage();
  allowTestOrigins(unbound, ['https://evil.test']);
  const unboundWorlds = await watchContentScripts(unbound, autofillId);
  await unbound.goto('https://evil.test/login');
  await unbound.waitForTimeout(2000);
  const unboundValue = await unbound.evaluate(() => document.querySelector('#otp').value);
  rep.check(
    'autofill-not-injected-unbound',
    unboundValue === '' && unboundWorlds.inMainFrame() === 0,
    `https://evil.test/login after 2 s: field ${JSON.stringify(unboundValue)}, content-script worlds in the top frame ${unboundWorlds.inMainFrame()} (otp.test showed ${boundWorlds.inMainFrame()})`,
  );

  // A bound origin framed by another site: the script runs in the iframe (out of process, so
  // seen by what it did) and not in the top frame.
  const framing = await context.newPage();
  allowTestOrigins(framing, ['https://host.test', 'https://otp.test']);
  const framingWorlds = await watchContentScripts(framing, autofillId);
  await framing.goto('https://host.test/');
  const frame = await (await framing.waitForSelector('iframe')).contentFrame();
  const frameFilled = await frame
    .waitForFunction((code) => document.querySelector('#otp')?.value === code, CODE, { timeout: 10000 })
    .then(() => true, () => false);
  const frameOrigin = await frame.evaluate(() => document.querySelector('#otp').dataset.origin ?? null);
  await framing.waitForTimeout(500);
  const topValue = await framing.evaluate(() => document.querySelector('#top-otp').value);
  rep.check(
    'autofill-iframe',
    frameFilled && frameOrigin === 'https://otp.test' && topValue === '' && framingWorlds.inMainFrame() === 0,
    `https://host.test/ framing https://otp.test/frame: iframe filled ${frameFilled} (sender.origin ${frameOrigin}), top field ${JSON.stringify(topValue)}, worlds in the top frame ${framingWorlds.inMainFrame()}`,
  );

  // A window the worker opens shows up as a page whose recorded URLs include the hash the page
  // drops at once with replaceState.
  const before = pages.count();
  await (await extensionWorker(context, autofillId)).evaluate(() => globalThis.fixture.openWindow());
  const win = await pages.waitForUrl((u) => u === `chrome-extension://${autofillId}/popup/popup.html#bind`, { after: before });
  const winState = win ? await win.waitForSelector('body[data-state="bind"]', { timeout: 10000 }).then(() => 'bind', () => 'not bind') : 'no window';
  rep.check('autofill-window', Boolean(win) && winState === 'bind', `page with popup.html#bind: ${win ? win.url() : 'none'} (state ${winState})`);

  // A real click is a user gesture: chrome.permissions.request() for an origin the manifest
  // already grants resolves true without a prompt.
  if (win) {
    await win.click('#allow');
    const answer = await win.waitForFunction(() => document.querySelector('#result').textContent, null, { timeout: 10000 }).then((h) => h.jsonValue(), () => '(none)');
    rep.check('autofill-permission-click', answer === 'true', `permissions.request after page.click: ${answer}`);
  } else {
    rep.fail('autofill-permission-click', 'no window to click in');
  }

  // Watchers: only document loads of the pages the test opened are exempt from egress, and
  // only their own allowed origins from the page check. Controls: a fetch from a test page to
  // its own origin counts as egress, and a test page sent to an origin it was not allowed is an
  // offender.
  const own = [`chrome-extension://${autofillId}`];
  const egressBefore = net.egressBeyondTestPages();
  const offendersBefore = pages.offenders(own);
  rep.check(
    'autofill-watchers-exempt-test-pages',
    egressBefore.length === 0 && offendersBefore.length === 0 && served.length >= 3,
    `${served.length} routed loads; egress beyond test pages ${JSON.stringify(egressBefore)}; pages outside the extension and allowed test origins ${JSON.stringify(offendersBefore)}`,
  );
  await bound.evaluate(() => fetch('/beacon').then((r) => r.text()));
  await unbound.goto('https://other.test/elsewhere');
  const egressAfter = net.egressBeyondTestPages().map((r) => r.url);
  const offendersAfter = pages.offenders(own);
  rep.check(
    'autofill-watchers-controls',
    egressAfter.includes('https://otp.test/beacon') && offendersAfter.includes('https://other.test/elsewhere'),
    `egress ${JSON.stringify(egressAfter)}; offenders ${JSON.stringify(offendersAfter)}`,
  );
} catch (err) {
  rep.fail('autofill-smoke', err?.stack?.split('\n').slice(0, 3).join(' / ') ?? String(err));
} finally {
  if (context) await context.close().catch(() => {});
  fs.rmSync(profile3, { recursive: true, force: true });
  fs.rmSync(autofillDir, { recursive: true, force: true });
}
rep.finish('fixture-smoke');
