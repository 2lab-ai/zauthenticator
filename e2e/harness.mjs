// Shared Playwright harness for e2e/popup.e2e.mjs and e2e/fixture-smoke.mjs.
//
// Launches the Playwright-bundled Chromium with one unpacked extension, finds the extension id
// without a background service worker, watches every remote request and every opened page in the
// context, and prints one `PASS|FAIL <name> <detail>` line per assertion.

import { chromium } from 'playwright';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const HEADLESS = process.env.E2E_HEADLESS === '1';
export const ARTIFACTS = path.resolve(process.env.E2E_ARTIFACTS || 'test-results');

// Chromium derives an unpacked extension's id from its absolute path: sha256 of the path bytes,
// first 16 bytes as 32 hex digits, each digit 0-f mapped to a-p. Chromium resolves symlinks first
// (on macOS /var -> /private/var), so callers pass the realpath.
export function computeExtensionId(absPath) {
  const hex = createHash('sha256').update(absPath, 'utf8').digest('hex').slice(0, 32);
  return Array.from(hex, (c) => String.fromCharCode(97 + parseInt(c, 16))).join('');
}

export function realExtensionDir(dir) {
  return fs.realpathSync.native(path.resolve(dir));
}

export function freshProfileDir(prefix = 'zauth-e2e-profile-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// headless: false by default (CI runs it under xvfb). E2E_HEADLESS=1 selects the full Chromium
// build in new-headless mode via channel 'chromium'; the headless shell cannot load extensions.
export async function launch(extDir, userDataDir) {
  const options = {
    headless: HEADLESS,
    acceptDownloads: true,
    args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`],
  };
  if (HEADLESS) options.channel = 'chromium';
  return chromium.launchPersistentContext(userDataDir, options);
}

// Pages the harness itself opens for its own bookkeeping (the chrome://extensions lookup).
// watchPages() exempts exactly these Page objects, never a URL.
const harnessPages = new WeakSet();

// Fallback id lookup: chrome://extensions renders one <extensions-item id="<extension id>"> per
// installed extension, two shadow roots deep.
export async function readIdsFromExtensionsPage(context) {
  const page = await context.newPage();
  harnessPages.add(page);
  try {
    await page.goto('chrome://extensions/');
    const handle = await page.waitForFunction(
      () => {
        const manager = document.querySelector('extensions-manager');
        const list = manager?.shadowRoot?.querySelector('extensions-item-list');
        const items = list?.shadowRoot?.querySelectorAll('extensions-item');
        if (!items || items.length === 0) return null;
        return Array.from(items, (item) => ({
          id: item.id,
          name: item.shadowRoot?.querySelector('#name')?.textContent?.trim() ?? '',
        }));
      },
      null,
      { timeout: 15000 },
    );
    return await handle.jsonValue();
  } finally {
    await page.close();
  }
}

async function openAndConfirm(page, id, pagePath) {
  try {
    await page.goto(`chrome-extension://${id}/${pagePath}`, { waitUntil: 'load', timeout: 15000 });
    const runtimeId = await page.evaluate(() => globalThis.chrome?.runtime?.id ?? null);
    return runtimeId === id;
  } catch {
    return false;
  }
}

// Opens chrome-extension://<id>/<pagePath> in `page`. Tries the id computed from the path first,
// then the chrome://extensions fallback. Returns { id, method } or throws.
export async function openExtensionPage(context, page, extDir, pagePath) {
  const computed = computeExtensionId(extDir);
  if (await openAndConfirm(page, computed, pagePath)) return { id: computed, method: 'computed' };
  let items;
  try {
    items = await readIdsFromExtensionsPage(context);
  } catch (err) {
    throw new Error(`extension page ${pagePath} did not load with computed id ${computed}, and chrome://extensions lookup failed: ${err.message.split('\n')[0]}`);
  }
  for (const { id } of items) {
    if (await openAndConfirm(page, id, pagePath)) return { id, method: 'chrome://extensions' };
  }
  throw new Error(`extension page ${pagePath} did not load (computed ${computed}, listed ${JSON.stringify(items)})`);
}

const REMOTE = /^(https?|wss?|ftp):/i;
// A request Chromium refused before it reached the network stack. Exempt by failure reason only,
// never by URL, so an unexpected request to any host still counts as egress.
const BLOCKED_BEFORE_NETWORK = /ERR_BLOCKED_BY_CSP|blocked:csp/i;

// Records every remote-scheme request in the context with its outcome.
export function watchNetwork(context) {
  const records = [];
  const extensionUrls = [];
  const byRequest = new Map();
  context.on('request', (req) => {
    if (req.url().startsWith('chrome-extension://')) extensionUrls.push(req.url());
    if (!REMOTE.test(req.url())) return;
    let frameUrl = '';
    try {
      frameUrl = req.frame().url();
    } catch {
      frameUrl = '(no frame)';
    }
    const rec = { url: req.url(), method: req.method(), type: req.resourceType(), frameUrl, outcome: 'pending' };
    byRequest.set(req, rec);
    records.push(rec);
  });
  context.on('requestfailed', (req) => {
    const rec = byRequest.get(req);
    if (rec) rec.outcome = `failed:${req.failure()?.errorText ?? 'unknown'}`;
  });
  context.on('requestfinished', (req) => {
    const rec = byRequest.get(req);
    if (rec) rec.outcome = 'finished';
  });
  return {
    records,
    // Positive control: the extension's own resource loads, proving the listener sees
    // requests issued by extension pages at all.
    extensionUrls,
    egress: () => records.filter((r) => !BLOCKED_BEFORE_NETWORK.test(r.outcome)),
  };
}

// Records every page (tab or popup window) in the context and every main-frame URL it shows,
// including pages the extension opens itself (chrome.tabs.create, window.open). CSP does not
// govern top-level navigation, so this is the runtime check behind the gate's navigation rule.
export function watchPages(context) {
  const pages = [];
  const track = (page) => {
    const rec = { page, urls: [page.url()] };
    pages.push(rec);
    page.on('framenavigated', (frame) => {
      if (frame === page.mainFrame()) rec.urls.push(frame.url());
    });
  };
  context.pages().forEach(track);
  context.on('page', track);
  return {
    count: () => pages.length,
    // URLs outside the extension's own origins (chrome-extension://<id>, as resolved by
    // openExtensionPage) other than about:blank, on any page the harness did not open for itself.
    offenders(ownOrigins) {
      return pages
        .filter((rec) => !harnessPages.has(rec.page))
        .flatMap((rec) => rec.urls)
        .filter((url) => url !== 'about:blank' && url !== '' && !ownOrigins.some((origin) => url.startsWith(`${origin}/`)));
    },
  };
}

// Collects console lines of a page; CSP violations are reported there by Chromium.
export function watchConsole(page) {
  const lines = [];
  page.on('console', (msg) => lines.push(`${msg.type()}: ${msg.text()}`));
  page.on('pageerror', (err) => lines.push(`pageerror: ${err.message}`));
  return lines;
}

// Runs fetch() to a remote URL inside the page and reports the result plus any
// securitypolicyviolation events raised for it.
export async function probeFetch(page, url = 'https://example.com/') {
  return page.evaluate(async (target) => {
    const violations = [];
    const onViolation = (e) => violations.push(`${e.effectiveDirective || e.violatedDirective} ${e.blockedURI}`);
    document.addEventListener('securitypolicyviolation', onViolation);
    const result = await fetch(target).then(
      () => 'ok',
      (e) => `blocked:${e.message}`,
    );
    await new Promise((resolve) => setTimeout(resolve, 200));
    document.removeEventListener('securitypolicyviolation', onViolation);
    return { result, violations };
  }, url);
}

export function createReporter() {
  let passed = 0;
  let failed = 0;
  const line = (status, name, detail) => console.log(`${status} ${name}${detail ? ` ${detail}` : ''}`);
  const reporter = {
    pass(name, detail = '') {
      passed += 1;
      line('PASS', name, detail);
    },
    fail(name, detail = '') {
      failed += 1;
      line('FAIL', name, detail);
    },
    check(name, ok, detail = '') {
      if (ok) reporter.pass(name, detail);
      else reporter.fail(name, detail);
      return ok;
    },
    get failed() {
      return failed;
    },
    // Prints the summary line and sets the exit code.
    finish(suite) {
      if (failed === 0 && passed > 0) line('PASS', suite, `${passed}/${passed} assertions`);
      else line('FAIL', suite, `${failed} of ${passed + failed} assertions failed`);
      process.exitCode = failed === 0 && passed > 0 ? 0 : 1;
    },
  };
  return reporter;
}

export function ensureArtifactsDir() {
  fs.mkdirSync(ARTIFACTS, { recursive: true });
  return ARTIFACTS;
}
