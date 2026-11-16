// Proves the e2e harness on this machine without the real extension: generates a throwaway
// extension in os.tmpdir() (the architecture doc's manifest and CSP, one page), then checks
// launch, id computation vs. chrome://extensions, page navigation, storage, the CSP network
// block, download capture, screenshots, and that chrome.storage.session dies with the session.
//
//   node e2e/fixture-smoke.mjs            # headed
//   E2E_HEADLESS=1 node e2e/fixture-smoke.mjs

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
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
  readIdsFromExtensionsPage,
  realExtensionDir,
  watchConsole,
  watchNetwork,
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
  fs.rmSync(profile, { recursive: true, force: true });
  fs.rmSync(extDir, { recursive: true, force: true });
}
rep.finish('fixture-smoke');
