// Shared Playwright harness for e2e/popup.e2e.mjs, e2e/autofill.e2e.mjs and e2e/fixture-smoke.mjs.
//
// Launches the Playwright-bundled Chromium with one unpacked extension, finds the extension id
// without relying on its service worker, watches every remote request and every opened page in
// the context, sees which frames the extension's content scripts ran in, and prints one
// `PASS|FAIL <name> <detail>` line per assertion.

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

// headless: false by default (CI runs it under xvfb). E2E_HEADLESS=1 selects new-headless mode.
// channel 'chromium' (the full Chromium build) in both modes: the headless shell cannot load
// extensions.
//
// UI language: --lang=en-US asks Chromium for an English UI, which Chromium reads on Linux and
// Windows. macOS Chromium ignores --lang and follows the system language list (AppleLanguages);
// Playwright refuses the -AppleLanguages argument for a persistent context. locale: 'en-US' only
// emulates navigator.language, Accept-Language and chrome.i18n.getUILanguage(): measured on
// macOS, it does not change the catalog chrome.i18n.getMessage() reads (--lang=ko with
// locale ko-KR still gave English messages). popup.e2e.mjs prints the catalog language.
export async function launch(extDir, userDataDir) {
  const options = {
    headless: HEADLESS,
    acceptDownloads: true,
    locale: 'en-US',
    args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`, '--lang=en-US'],
    channel: 'chromium',
  };
  return chromium.launchPersistentContext(userDataDir, options);
}

// Pages the harness itself opens for its own bookkeeping (the chrome://extensions lookup).
// watchPages() exempts exactly these Page objects, never a URL.
const harnessPages = new WeakSet();

// Pages a test opens itself on routed test origins (https://otp.test and the like, answered by
// context.route, nothing leaves the machine): Page object → origins that page may show. The
// exemption is by Page object and origin together: any other URL on such a page still counts,
// and a page the extension opens is never in this map.
const testPages = new WeakMap();

export function allowTestOrigins(page, origins) {
  testPages.set(page, new Set(origins));
}

function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return '';
  }
}

// The extension's service worker in `context` (URL under chrome-extension://<id>/), waiting up
// to `timeout` for it to start. Callers resolve it again for every use instead of keeping it:
// Chromium may stop an idle worker and start a new one.
export async function extensionWorker(context, id, timeout = 10000) {
  const own = (worker) => worker.url().startsWith(`chrome-extension://${id}/`);
  const running = context.serviceWorkers().find(own);
  if (running) return running;
  return context.waitForEvent('serviceworker', { predicate: own, timeout });
}

// Records the isolated worlds Chromium creates for the extension's content scripts in `page`
// (CDP Runtime.executionContextCreated with auxData.type 'isolated' and the extension's origin).
// Playwright's own utility worlds have other origins and are not counted. A cross-site iframe
// runs in another renderer under site isolation, so its worlds are not seen here: check such a
// frame by what the script did in it. Call before page.goto().
// Evidence only for a frame the extension never ran in before: measured with Playwright 1.65.1
// (Chromium 159), a tab the script had run in reported the world again on every reload after
// the script was unregistered, while a fresh tab reported none. Use a fresh tab for "injected or
// not". → { worlds, mainFrameId, inMainFrame(), reset() }
export async function watchContentScripts(page, id) {
  const cdp = await page.context().newCDPSession(page);
  const worlds = [];
  cdp.on('Runtime.executionContextCreated', ({ context }) => {
    if (context.auxData?.type === 'isolated' && context.origin === `chrome-extension://${id}`) {
      worlds.push({ frameId: context.auxData.frameId, name: context.name });
    }
  });
  await cdp.send('Runtime.enable');
  const { frameTree } = await cdp.send('Page.getFrameTree');
  const mainFrameId = frameTree.frame.id;
  return {
    worlds,
    mainFrameId,
    // Content-script worlds created in the top frame since the watch began.
    inMainFrame: () => worlds.filter((w) => w.frameId === mainFrameId).length,
    // Forgets what was seen so far (before a reload).
    reset: () => worlds.splice(0, worlds.length),
  };
}

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
    let page = null;
    try {
      page = req.frame().page();
    } catch {
      page = null; // a service worker's request has no frame
    }
    const rec = { url: req.url(), method: req.method(), type: req.resourceType(), frameUrl, outcome: 'pending' };
    Object.defineProperty(rec, 'page', { value: page, enumerable: false });
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
    // egress() without the document loads (main frame or iframe) of routed test origins on
    // pages the test opened with allowTestOrigins(). Any other request to a test origin, from
    // any page or the worker, still counts.
    egressBeyondTestPages: () =>
      records.filter(
        (r) => !BLOCKED_BEFORE_NETWORK.test(r.outcome) && !(r.type === 'document' && r.page && testPages.get(r.page)?.has(originOf(r.url))),
      ),
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
    // openExtensionPage) other than about:blank, on any page the harness did not open for itself;
    // on a page the test opened with allowTestOrigins(), URLs of those origins are not counted.
    offenders(ownOrigins) {
      return pages
        .filter((rec) => !harnessPages.has(rec.page))
        .flatMap((rec) => rec.urls.filter((url) => !testPages.get(rec.page)?.has(originOf(url))))
        .filter((url) => url !== 'about:blank' && url !== '' && !ownOrigins.some((origin) => url.startsWith(`${origin}/`)));
    },
    // The first page opened since the watch began (or already open) whose main frame has shown
    // a URL for which test(url) holds, e.g. a window the extension opened. → Page or null after
    // `timeout`. A URL changed by history.replaceState() still counts: every URL is recorded.
    async waitForUrl(test, { timeout = 10000, after = 0 } = {}) {
      const deadline = Date.now() + timeout;
      for (;;) {
        const rec = pages.slice(after).find((r) => r.urls.some(test));
        if (rec) return rec.page;
        if (Date.now() > deadline) return null;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
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
