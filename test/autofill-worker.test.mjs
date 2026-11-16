// lib/autofill-worker.js against mocked chrome.* APIs (.prd/03-autofill.md, "Contract tests"): the
// menu model, sender validation, the menu fill (S1), the reconciler (S2, S4) and the storage
// triggers. Everything below the worker is real: session.js, store.js, bindings.js, vault.js and
// totp.js over mocked chrome.storage and Web Locks. Codes are checked against an RFC 6238
// implementation written here on node:crypto. fillFocused() is taken from the executeScript call
// and run from its source text alone, as the browser runs it.
import test, { afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import fs from 'node:fs';
import vm from 'node:vm';

const MESSAGES = JSON.parse(fs.readFileSync(new URL('../extension/_locales/en/messages.json', import.meta.url), 'utf8'));
const SELF_ID = 'self-extension-id';
// A host permission the manifest itself asks for (the e2e test copy adds such origins).
const REQUIRED = 'https://required.test/*';

// ---- mocked extension APIs ---------------------------------------------------------------------

const hop = () => new Promise((resolve) => setTimeout(resolve, 1));
const areas = { local: new Map(), session: new Map() };
function area(m) {
  return {
    async get(keys) {
      await hop();
      const out = {};
      for (const k of [].concat(keys)) if (m.has(k)) out[k] = structuredClone(m.get(k));
      return out;
    },
    async set(items) {
      await hop();
      for (const [k, v] of Object.entries(items)) m.set(k, structuredClone(v));
    },
    async remove(keys) {
      await hop();
      for (const k of [].concat(keys)) m.delete(k);
    },
  };
}

const calls = [];       // [name, argument] in call order
let menu = new Map();   // context menu items by id
let registered = [];    // registered content scripts
let granted = [];       // granted host permission patterns
let refused = new Set(); // patterns permissions.remove refuses
let executeScript;      // the chrome.scripting.executeScript behaviour of the current test
let beforeRegistration = null; // run once inside the next getRegisteredContentScripts call
const accessLevels = [];       // chrome.storage.session.setAccessLevel arguments, from import on

globalThis.chrome = {
  runtime: {
    id: SELF_ID,
    lastError: undefined,
    getURL: (p) => `chrome-extension://${SELF_ID}/${p}`,
    getManifest: () => ({ host_permissions: [REQUIRED] }),
  },
  i18n: { getMessage: (key) => MESSAGES[key]?.message ?? '' },
  storage: {
    local: area(areas.local),
    session: {
      ...area(areas.session),
      async setAccessLevel(options) {
        accessLevels.push(structuredClone(options));
      },
    },
    onChanged: { addListener() {}, removeListener() {} },
  },
  contextMenus: {
    async removeAll() {
      await hop();
      calls.push(['removeAll']);
      menu = new Map();
    },
    // Like the real API: errors only through chrome.runtime.lastError inside the callback.
    create(properties, done) {
      setTimeout(() => {
        if (menu.has(properties.id)) {
          chrome.runtime.lastError = { message: `Cannot create item with duplicate id ${properties.id}` };
          calls.push(['duplicate', properties.id]);
        } else {
          menu.set(properties.id, structuredClone(properties));
        }
        done();
        chrome.runtime.lastError = undefined;
      }, 1);
      return properties.id;
    },
  },
  scripting: {
    async executeScript(options) {
      calls.push(['executeScript', options]);
      return executeScript(options);
    },
    async getRegisteredContentScripts({ ids } = {}) {
      if (beforeRegistration) {
        const run = beforeRegistration;
        beforeRegistration = null;
        await run();
      }
      return structuredClone(ids ? registered.filter((s) => ids.includes(s.id)) : registered);
    },
    async registerContentScripts(list) {
      calls.push(['register', structuredClone(list)]);
      registered = structuredClone(list);
    },
    async updateContentScripts(list) {
      calls.push(['update', structuredClone(list)]);
      registered = structuredClone(list);
    },
    async unregisterContentScripts({ ids }) {
      calls.push(['unregister', ids]);
      registered = registered.filter((s) => !ids.includes(s.id));
    },
  },
  permissions: {
    async getAll() {
      calls.push(['permissions.getAll']);
      return { permissions: ['storage', 'activeTab', 'contextMenus', 'scripting'], origins: [...granted] };
    },
    async remove({ origins }) {
      calls.push(['permissions.remove', origins]);
      if (origins.includes(REQUIRED)) throw new Error('You cannot remove required permissions.');
      if (origins.some((o) => refused.has(o))) throw new Error('refused');
      granted = granted.filter((o) => !origins.includes(o));
      return true;
    },
  },
  windows: {
    async create(options) {
      calls.push(['window', options.url, options.type]);
    },
  },
  tabs: {
    async create(options) {
      calls.push(['tab', options.url]);
    },
  },
};

// Web Locks mock: one FIFO queue per name.
const tails = new Map();
Object.defineProperty(globalThis, 'navigator', {
  configurable: true,
  value: {
    locks: {
      request(name, fn) {
        const prev = tails.get(name) ?? Promise.resolve();
        const run = prev.then(() => fn());
        tails.set(name, run.catch(() => {}));
        return run;
      },
    },
  },
});

const vault = await import('../extension/lib/vault.js');
const store = await import('../extension/lib/store.js');
const worker = await import('../extension/lib/autofill-worker.js');

// ---- fixtures ----------------------------------------------------------------------------------

const PASS = 'correct horse battery';
const IDLE_MS = 16 * 60 * 1000;
const A = { id: 'acc-a', issuer: 'GitHub', label: 'alice', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30, createdAt: 1 };
const B = { id: 'acc-b', issuer: '', label: 'bob@example.com', secret: 'GEZDGNBVGY3TQOJQ', algorithm: 'SHA256', digits: 8, period: 60, createdAt: 2 };
// RFC 6238 Appendix B: the SHA-1 seed "12345678901234567890", 8 digits; T = 59 s → 94287082.
const RFC = { id: 'acc-rfc', issuer: 'RFC 6238', label: 'appendix-b', secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', algorithm: 'SHA1', digits: 8, period: 30, createdAt: 3 };
const binding = (origin, accountId) => ({ origin, accountId, createdAt: 1 });

// Stores a vault holding `data` and, unless locked, its session key with the given activity time.
async function seed(data, { locked = false, lastActive = Date.now() } = {}) {
  areas.local.clear();
  areas.session.clear();
  const { record, rawKey } = await vault.create(PASS, data, { iterations: 1000 });
  areas.local.set('vault', record);
  if (!locked) await store.setSessionKey(rawKey, lastActive);
  return rawKey;
}

// Writes new vault data with the stored key, as an extension page's mutation would.
async function rewrite(change) {
  const key = await store.getSessionKey();
  const record = await store.getRecord();
  const data = await vault.open(key, record);
  change(data);
  await store.saveRecord(await vault.seal(key, record, data));
}

function base32Bytes(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const out = [];
  for (const c of text.replace(/=+$/, '').toUpperCase()) {
    value = (value << 5) | alphabet.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function referenceTotp({ secret, algorithm, digits, period }, nowMs) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(nowMs / 1000 / period)));
  const mac = createHmac(algorithm.toLowerCase(), base32Bytes(secret)).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

// `run` computes a code at some moment between these two reads of the clock.
async function codeAroundNow(account, run) {
  const before = Date.now();
  const result = await run();
  const after = Date.now();
  return { result, allowed: [referenceTotp(account, before), referenceTotp(account, after)] };
}

const sender = (origin, extra = {}) => ({ id: SELF_ID, origin, url: `${origin}/login`, tab: { id: 1 }, frameId: 0, ...extra });
const ask = (s, message = { type: 'autofill-code' }) => worker.handleMessage(message, s);
const click = (info, tab = { id: 7 }) => worker.handleMenuClick(info, tab);
const named = (name) => calls.filter((c) => c[0] === name);
const windows = () => named('window').map((c) => [c[1].split('#')[1], c[2]]);

afterEach(async () => {
  // Handlers start a menu rebuild without waiting for it; let it end inside its own test.
  await worker.rebuildMenu();
  calls.length = 0;
  menu = new Map();
  registered = [];
  granted = [];
  refused = new Set();
  beforeRegistration = null;
});

test('referenceTotp reproduces RFC 6238 Appendix B', () => {
  assert.equal(referenceTotp(RFC, 59 * 1000), '94287082');
  assert.equal(referenceTotp(RFC, 1111111109 * 1000), '07081804');
});

// ---- menu model --------------------------------------------------------------------------------

test('menu, locked: only "Unlock zauthenticator…" under the zauthenticator parent, in editable fields', async () => {
  await seed({ accounts: [A, B] }, { locked: true });
  await worker.rebuildMenu();
  assert.deepEqual([...menu.keys()], ['zauthenticator', 'unlock']);
  assert.equal(menu.get('zauthenticator').title, 'zauthenticator');
  assert.equal(menu.get('unlock').title, 'Unlock zauthenticator…');
  assert.equal(menu.get('unlock').parentId, 'zauthenticator');
  for (const item of menu.values()) assert.deepEqual(item.contexts, ['editable']);
});

test('menu, idle past the limit: the session is locked and only the unlock item is shown', async () => {
  await seed({ accounts: [A] }, { lastActive: Date.now() - IDLE_MS });
  await worker.rebuildMenu();
  assert.deepEqual([...menu.keys()], ['zauthenticator', 'unlock']);
  assert.equal(areas.session.has('vaultKey'), false);
});

test('menu, unlocked: one item per account titled "issuer · label" (either alone when the other is empty)', async () => {
  const unnamed = { ...A, id: 'acc-n', issuer: '', label: '' };
  const issuerOnly = { ...A, id: 'acc-i', issuer: 'Only Issuer', label: ' ' };
  await seed({ accounts: [A, B, unnamed, issuerOnly] });
  await worker.rebuildMenu();
  assert.deepEqual([...menu.keys()], ['zauthenticator', 'acct:acc-a', 'acct:acc-b', 'acct:acc-n', 'acct:acc-i']);
  assert.equal(menu.get('acct:acc-a').title, 'GitHub · alice');
  assert.equal(menu.get('acct:acc-b').title, 'bob@example.com');
  assert.equal(menu.get('acct:acc-n').title, 'Unnamed account');
  assert.equal(menu.get('acct:acc-i').title, 'Only Issuer');
  for (const [id, item] of menu) if (id !== 'zauthenticator') assert.equal(item.parentId, 'zauthenticator');
});

test('menu, empty vault: one disabled "No accounts yet" item', async () => {
  await seed({ accounts: [] });
  await worker.rebuildMenu();
  assert.deepEqual([...menu.keys()], ['zauthenticator', 'no-accounts']);
  assert.equal(menu.get('no-accounts').enabled, false);
  assert.equal(menu.get('no-accounts').title, 'No accounts yet');
});

test('menu: concurrent rebuilds run one at a time (no duplicate ids) and coalesce', async () => {
  await seed({ accounts: [A, B] });
  calls.length = 0;
  await Promise.all(Array.from({ length: 6 }, () => worker.rebuildMenu()));
  assert.deepEqual([...menu.keys()], ['zauthenticator', 'acct:acc-a', 'acct:acc-b']);
  assert.deepEqual(named('duplicate'), []);
  assert.ok(named('removeAll').length <= 2, `${named('removeAll').length} rebuilds for 6 calls`);
});

// ---- sender validation (S3) --------------------------------------------------------------------

const BOUND = { accounts: [A, B], bindings: [binding('https://otp.test', 'acc-a'), binding('https://eight.test', 'acc-b'), binding('https://gone.test', 'acc-x')] };

test('a content script of a bound origin gets the current code (independent RFC 6238)', async () => {
  await seed(BOUND);
  const six = await codeAroundNow(A, () => ask(sender('https://otp.test')));
  assert.match(six.result.code, /^\d{6}$/);
  assert.ok(six.allowed.includes(six.result.code), `${six.result.code} not in ${six.allowed}`);
  assert.deepEqual(Object.keys(six.result), ['code']);
  const eight = await codeAroundNow(B, () => ask(sender('https://eight.test')));
  assert.match(eight.result.code, /^\d{8}$/);
  assert.ok(eight.allowed.includes(eight.result.code));
  // No sender.origin: the origin of sender.url.
  const fromUrl = await codeAroundNow(A, () => ask({ id: SELF_ID, url: 'https://otp.test/deep/path?q=1' }));
  assert.ok(fromUrl.allowed.includes(fromUrl.result.code));
});

test('the code is the RFC 6238 Appendix B value at T = 59 s', async (t) => {
  const realNow = Date.now;
  Date.now = () => 59 * 1000;
  t.after(() => {
    Date.now = realNow;
  });
  await seed({ accounts: [RFC], bindings: [binding('https://otp.test', 'acc-rfc')] }, { lastActive: 59 * 1000 });
  assert.deepEqual(await ask(sender('https://otp.test')), { code: '94287082' });
});

test('wrong extension id, unbound origin, sub-domain, http, opaque origin, missing account → { code: null }', async () => {
  await seed(BOUND);
  const none = { code: null };
  assert.deepEqual(await ask(sender('https://otp.test', { id: 'another-extension' })), none);
  assert.deepEqual(await ask({ ...sender('https://otp.test'), id: undefined }), none);
  assert.deepEqual(await ask(sender('https://evil.test')), none);
  assert.deepEqual(await ask(sender('https://sub.otp.test')), none);
  assert.deepEqual(await ask(sender('https://otp.test:8443')), none);
  assert.deepEqual(await ask(sender('http://otp.test')), none);
  assert.deepEqual(await ask(sender('null')), none);
  assert.deepEqual(await ask({ id: SELF_ID, url: 'not a url' }), none);
  assert.deepEqual(await ask(sender('https://gone.test')), none);
  assert.deepEqual(await ask(sender(`chrome-extension://${SELF_ID}`)), none);
});

test('anything but { type: "autofill-code" } → { code: null }', async () => {
  await seed(BOUND);
  for (const message of [{ type: 'other' }, {}, null, undefined, 'autofill-code']) {
    assert.deepEqual(await worker.handleMessage(message, sender('https://otp.test')), { code: null }, String(JSON.stringify(message)));
  }
  assert.deepEqual(await worker.handleMessage({ type: 'autofill-code' }, undefined), { code: null });
});

test('locked or idle → { code: null }; idle also locks', async () => {
  await seed(BOUND, { locked: true });
  assert.deepEqual(await ask(sender('https://otp.test')), { code: null });
  await seed(BOUND, { lastActive: Date.now() - IDLE_MS });
  assert.deepEqual(await ask(sender('https://otp.test')), { code: null });
  assert.equal(areas.session.has('vaultKey'), false);
});

test('auto-fill is not activity: lastActiveAt is not refreshed', async () => {
  const last = Date.now() - 5 * 60 * 1000;
  await seed(BOUND, { lastActive: last });
  await ask(sender('https://otp.test'));
  assert.equal(areas.session.get('lastActiveAt'), last);
});

// ---- menu click (S1) ---------------------------------------------------------------------------

const MENU_VAULT = { accounts: [A, B], bindings: [binding('https://bound.test', 'acc-a')] };
// fillFocused() answers with the origin it checked (its second argument) when it filled.
const filledOk = async (options) => [{ frameId: options.target.frameIds[0], result: options.args[1] }];

test('menu fill: the code goes into the clicked frame, counts as activity, and an unbound https origin gets the offer', async () => {
  executeScript = filledOk;
  await seed(MENU_VAULT, { lastActive: Date.now() - 60 * 1000 });
  const { allowed } = await codeAroundNow(B, () =>
    click({ menuItemId: 'acct:acc-b', frameId: 3, frameUrl: 'https://login.example.test/x?y=1', pageUrl: 'https://top.test/' }));
  const [[, options]] = named('executeScript');
  assert.deepEqual(options.target, { tabId: 7, frameIds: [3] });
  assert.equal(options.func.name, 'fillFocused');
  assert.equal(options.args.length, 2);
  assert.ok(allowed.includes(options.args[0]), `${options.args[0]} not in ${allowed}`);
  // The origin of the clicked frame, which fillFocused() compares with the document it runs in.
  assert.equal(options.args[1], 'https://login.example.test');
  assert.ok(Date.now() - areas.session.get('lastActiveAt') < 5000, 'lastActiveAt refreshed');
  const pending = areas.session.get('pendingBind');
  assert.deepEqual({ origin: pending.origin, accountId: pending.accountId }, { origin: 'https://login.example.test', accountId: 'acc-b' });
  assert.deepEqual(windows(), [['bind', 'popup']]);
});

test('menu fill in the top frame: frame 0 and the page origin', async () => {
  executeScript = filledOk;
  await seed(MENU_VAULT);
  await click({ menuItemId: 'acct:acc-a', pageUrl: 'https://new.test/login' });
  assert.deepEqual(named('executeScript')[0][1].target.frameIds, [0]);
  assert.equal(areas.session.get('pendingBind').origin, 'https://new.test');
});

test('no offer for an origin already bound to the chosen account, or that is not https', async () => {
  executeScript = filledOk;
  await seed(MENU_VAULT);
  await click({ menuItemId: 'acct:acc-a', frameId: 0, pageUrl: 'https://bound.test/2fa' });
  await click({ menuItemId: 'acct:acc-a', frameId: 0, pageUrl: 'http://plain.test/' });
  await click({ menuItemId: 'acct:acc-a', frameId: 0, pageUrl: 'file:///tmp/x.html' });
  assert.equal(named('executeScript').length, 3);
  assert.deepEqual(windows(), []);
  assert.equal(areas.session.has('pendingBind'), false);
});

test('a site bound to another account: choosing this one fills it and offers to switch; Allow then binds the site to it', async () => {
  executeScript = filledOk;
  await seed(MENU_VAULT);
  await click({ menuItemId: 'acct:acc-b', frameId: 0, pageUrl: 'https://bound.test/2fa' });
  assert.equal(named('executeScript').length, 1);
  const pending = areas.session.get('pendingBind');
  assert.deepEqual({ origin: pending.origin, accountId: pending.accountId }, { origin: 'https://bound.test', accountId: 'acc-b' });
  assert.deepEqual(windows(), [['bind', 'popup']]);
  // Only offered: until Allow the site stays bound to the first account.
  assert.equal((await ask(sender('https://bound.test'))).code.length, A.digits);
  // The bind window's Allow (after the browser's prompt) stores the new account for the site.
  const bindPage = await import('../extension/popup/session.js?rebind-window');
  assert.equal(await bindPage.resume(), 'list');
  assert.deepEqual(bindPage.bindings().map((b) => [b.origin, b.accountId]), [['https://bound.test', 'acc-a']]);
  await bindPage.addBinding(pending.origin, pending.accountId);
  await bindPage.clearPendingBind();
  assert.deepEqual(bindPage.bindings().map((b) => [b.origin, b.accountId]), [['https://bound.test', 'acc-b']]);
  const next = await codeAroundNow(B, () => ask(sender('https://bound.test')));
  assert.ok(next.allowed.includes(next.result.code), `${next.result.code} not in ${next.allowed}`);
  // Chosen again with the account it is bound to now: filled, nothing offered.
  calls.length = 0;
  await click({ menuItemId: 'acct:acc-b', frameId: 0, pageUrl: 'https://bound.test/2fa' });
  assert.equal(named('executeScript').length, 1);
  assert.deepEqual(windows(), []);
  assert.equal(areas.session.has('pendingBind'), false);
});

test('a site bound to an account the vault no longer has is offered for the chosen one', async () => {
  executeScript = filledOk;
  await seed({ accounts: [A, B], bindings: [binding('https://gone.test', 'acc-x')] });
  await click({ menuItemId: 'acct:acc-a', frameId: 0, pageUrl: 'https://gone.test/' });
  const pending = areas.session.get('pendingBind');
  assert.deepEqual({ origin: pending.origin, accountId: pending.accountId }, { origin: 'https://gone.test', accountId: 'acc-a' });
  assert.deepEqual(windows(), [['bind', 'popup']]);
});

test('a switch is offered only where the fill happened: a refused or navigated fill on a site bound to another account offers nothing', async () => {
  await seed(MENU_VAULT);
  executeScript = async () => {
    throw new Error('Cannot access contents of the page.');
  };
  await click({ menuItemId: 'acct:acc-b', frameId: 0, pageUrl: 'https://bound.test/2fa' });
  executeScript = async (options) => [{ frameId: options.target.frameIds[0], result: 'https://elsewhere.test' }];
  await click({ menuItemId: 'acct:acc-b', frameId: 0, pageUrl: 'https://bound.test/2fa' });
  assert.equal(named('executeScript').length, 2);
  assert.deepEqual(windows(), []);
  assert.equal(areas.session.has('pendingBind'), false);
});

test('no offer when nothing was filled: executeScript refused, or no editable field focused', async () => {
  await seed(MENU_VAULT);
  executeScript = async () => {
    throw new Error('Cannot access contents of the page.');
  };
  await click({ menuItemId: 'acct:acc-a', pageUrl: 'https://new.test/' });
  executeScript = async () => [{ frameId: 0, result: false }];
  await click({ menuItemId: 'acct:acc-a', pageUrl: 'https://new.test/' });
  executeScript = async () => [];
  await click({ menuItemId: 'acct:acc-a', pageUrl: 'https://new.test/' });
  assert.deepEqual(windows(), []);
  assert.equal(areas.session.has('pendingBind'), false);
});

test('no offer when setPendingBind refuses (the vault locked while the field was filled)', async () => {
  await seed(MENU_VAULT);
  executeScript = async (options) => {
    await store.clearSessionKey();
    return filledOk(options);
  };
  await click({ menuItemId: 'acct:acc-a', pageUrl: 'https://new.test/' });
  assert.equal(named('executeScript').length, 1);
  assert.deepEqual(windows(), []);
  assert.equal(areas.session.has('pendingBind'), false);
});

test('locked, idle, or the Unlock item: the unlock window opens and nothing is filled', async () => {
  executeScript = filledOk;
  await seed(MENU_VAULT, { locked: true });
  await click({ menuItemId: 'acct:acc-a', pageUrl: 'https://new.test/' });
  await click({ menuItemId: 'unlock', pageUrl: 'https://new.test/' });
  await seed(MENU_VAULT, { lastActive: Date.now() - IDLE_MS });
  await click({ menuItemId: 'acct:acc-a', pageUrl: 'https://new.test/' });
  assert.deepEqual(named('executeScript'), []);
  assert.deepEqual(windows(), [['unlock', 'popup'], ['unlock', 'popup'], ['unlock', 'popup']]);
});

test('an account the vault no longer has, or no tab: nothing is filled', async () => {
  executeScript = filledOk;
  await seed(MENU_VAULT);
  await click({ menuItemId: 'acct:acc-missing', pageUrl: 'https://new.test/' });
  await worker.handleMenuClick({ menuItemId: 'acct:acc-a', pageUrl: 'https://new.test/' }, undefined);
  await click({ menuItemId: 'acct:acc-a', pageUrl: 'https://new.test/' }, { id: -1 });
  await click({ menuItemId: 'zauthenticator', pageUrl: 'https://new.test/' });
  assert.deepEqual(named('executeScript'), []);
  assert.deepEqual(windows(), []);
});

test('menu fill in a subframe whose URL the click did not report: nothing is injected or offered (never the page URL)', async () => {
  executeScript = filledOk;
  await seed(MENU_VAULT);
  await click({ menuItemId: 'acct:acc-a', frameId: 3, pageUrl: 'https://embedder.test/' });
  await click({ menuItemId: 'acct:acc-a', frameId: 5, frameUrl: undefined, pageUrl: 'https://embedder.test/login' });
  await click({ menuItemId: 'acct:acc-a', frameId: 5, frameUrl: 'not a url', pageUrl: 'https://embedder.test/login' });
  assert.deepEqual(named('executeScript'), []);
  assert.deepEqual(windows(), []);
  assert.equal(areas.session.has('pendingBind'), false);
});

test("menu fill in the top frame checks the page's origin; a subframe's checks the frame's", async () => {
  executeScript = filledOk;
  await seed(MENU_VAULT);
  await click({ menuItemId: 'acct:acc-a', frameId: 0, pageUrl: 'https://top.test/a', frameUrl: 'https://other.test/' });
  await click({ menuItemId: 'acct:acc-a', frameId: 2, pageUrl: 'https://top.test/a', frameUrl: 'https://framed.test:8443/b' });
  await click({ menuItemId: 'acct:acc-a', frameId: 4, pageUrl: 'https://top.test/a', frameUrl: 'http://plain.test/c' });
  assert.deepEqual(named('executeScript').map((c) => [c[1].target.frameIds[0], c[1].args[1]]), [
    [0, 'https://top.test'],
    [2, 'https://framed.test:8443'],
    [4, 'http://plain.test'],
  ]);
});

test('no offer unless the frame answers with the origin it was given (a navigated frame fills nothing)', async () => {
  await seed(MENU_VAULT);
  for (const result of [true, 'https://elsewhere.test', false, null]) {
    executeScript = async (options) => [{ frameId: options.target.frameIds[0], result }];
    await click({ menuItemId: 'acct:acc-a', frameId: 0, pageUrl: 'https://new.test/login' });
  }
  assert.equal(named('executeScript').length, 4);
  assert.deepEqual(windows(), []);
  assert.equal(areas.session.has('pendingBind'), false);
  // The same click with the expected answer offers the site.
  executeScript = filledOk;
  await click({ menuItemId: 'acct:acc-a', frameId: 0, pageUrl: 'https://new.test/login' });
  assert.equal(areas.session.get('pendingBind').origin, 'https://new.test');
});

test('entries of a hand-edited vault (no id, a repeated id) can be chosen from the menu', async () => {
  executeScript = filledOk;
  const { id: _a, ...noId } = A;
  await seed({ accounts: [noId, { ...B, id: 'dup' }, { ...RFC, id: 'dup' }] });
  await worker.rebuildMenu();
  const items = [...menu.keys()].filter((k) => k.startsWith('acct:'));
  assert.equal(items.length, 3);
  for (const menuItemId of items) await click({ menuItemId, frameId: 0, pageUrl: 'https://bound.test/' });
  assert.equal(named('executeScript').length, 3, `filled ${named('executeScript').length} of ${items.join(', ')}`);
});

// ---- fillFocused, from its source text --------------------------------------------------------

async function capturedFillFocused() {
  executeScript = filledOk;
  await seed(MENU_VAULT);
  await click({ menuItemId: 'acct:acc-a', pageUrl: 'https://bound.test/' });
  return named('executeScript')[0][1].func.toString();
}

// A context with nothing but a tiny DOM and the document's location.origin: a reference to
// anything in the worker module fails here.
function page(origin = 'https://bound.test') {
  class Element {
    constructor(tag, attrs = {}) {
      this.tag = tag;
      this.children = [];
      this.parentElement = null;
      this.shadowRoot = null;
      this.events = [];
      this.value = attrs.value ?? '';
      this.disabled = Boolean(attrs.disabled);
      this.readOnly = Boolean(attrs.readonly);
    }
    append(...children) {
      for (const child of children) {
        child.parentElement = this;
        this.children.push(child);
      }
      return this;
    }
    querySelectorAll(selector) {
      const out = [];
      const walk = (node) => {
        for (const child of node.children) {
          if (child.tag === selector) out.push(child);
          walk(child);
        }
      };
      walk(this);
      return out;
    }
    matches(selector) {
      return selector === ':disabled' && this.disabled;
    }
    dispatchEvent(event) {
      this.events.push(`${event.type}${event.bubbles ? '' : ' (not bubbling)'}`);
      return true;
    }
    getRootNode() {
      let node = this;
      while (node.parentElement) node = node.parentElement;
      return node;
    }
  }
  class HTMLInputElement extends Element {
    constructor(attrs = {}) {
      super('input', attrs);
      this.type = attrs.type ?? 'text';
      this.maxLength = attrs.maxlength ?? -1;
    }
  }
  class HTMLTextAreaElement extends Element {
    constructor(attrs = {}) {
      super('textarea', attrs);
      this.type = 'textarea';
    }
  }
  class Event {
    constructor(type, init = {}) {
      this.type = type;
      this.bubbles = Boolean(init.bubbles);
    }
  }
  const document = { activeElement: null };
  const location = { origin };
  const context = vm.createContext({ HTMLInputElement, HTMLTextAreaElement, Event, document, location });
  return { context, document, origin, root: new Element('#document'), Element, HTMLInputElement, HTMLTextAreaElement };
}
// Runs the injected source as executeScript does: fillFocused(code, the clicked frame's origin).
const runIn = (p, source, code, expected = p.origin) =>
  vm.runInContext(`(${source})(${JSON.stringify(code)}, ${JSON.stringify(expected)})`, p.context);

test('fillFocused, run from its source alone: fills the focused field with input and change, replacing its value', async () => {
  const source = await capturedFillFocused();
  const p = page();
  const field = new p.HTMLInputElement({ value: 'stale' });
  const other = new p.HTMLInputElement();
  p.root.append(new p.Element('form').append(field, other));
  p.document.activeElement = field;
  // It answers with the origin it checked.
  assert.equal(runIn(p, source, '123456'), 'https://bound.test');
  assert.equal(field.value, '123456');
  assert.deepEqual(field.events, ['input', 'change']);
  assert.deepEqual(other.events, []);
  const area = new p.HTMLTextAreaElement();
  p.root.append(area);
  p.document.activeElement = area;
  assert.equal(runIn(p, source, '12345678'), 'https://bound.test');
  assert.equal(area.value, '12345678');
});

test('fillFocused: a focused box of a split code fills the whole run, one digit each', async () => {
  const source = await capturedFillFocused();
  const p = page();
  const boxes = Array.from({ length: 6 }, () => new p.HTMLInputElement({ type: 'tel', maxlength: 1 }));
  const row = new p.Element('div');
  for (const box of boxes) row.append(new p.Element('span').append(box));
  p.root.append(new p.HTMLInputElement({ maxlength: 1 }), row);
  p.document.activeElement = boxes[3];
  assert.equal(runIn(p, source, '135790'), 'https://bound.test');
  assert.deepEqual(boxes.map((b) => b.value), ['1', '3', '5', '7', '9', '0']);
  assert.deepEqual(boxes[0].events, ['input', 'change']);
});

test('fillFocused: follows focus into a shadow root', async () => {
  const source = await capturedFillFocused();
  const p = page();
  const host = new p.Element('otp-input');
  const inner = new p.HTMLInputElement();
  host.shadowRoot = { activeElement: inner };
  p.document.activeElement = host;
  assert.equal(runIn(p, source, '246810'), 'https://bound.test');
  assert.equal(inner.value, '246810');
});

test('fillFocused: a document of another origin than the clicked frame (it navigated) → false, nothing written', async () => {
  const source = await capturedFillFocused();
  const p = page('https://elsewhere.test');
  const field = new p.HTMLInputElement();
  const boxes = Array.from({ length: 6 }, () => new p.HTMLInputElement({ maxlength: 1 }));
  p.root.append(field, new p.Element('div').append(...boxes));
  for (const [focused, expected] of [
    [field, 'https://bound.test'],
    [boxes[0], 'https://bound.test'],
    [field, 'https://elsewhere.test:8443'],
    [field, 'http://elsewhere.test'],
  ]) {
    p.document.activeElement = focused;
    assert.equal(runIn(p, source, '123456', expected), false, String(expected));
  }
  // Called without an origin at all.
  assert.equal(vm.runInContext(`(${source})("123456")`, p.context), false);
  assert.equal(field.value, '');
  assert.deepEqual(field.events, []);
  assert.ok(boxes.every((b) => b.value === '' && b.events.length === 0));
  // The origin it was given: filled.
  p.document.activeElement = field;
  assert.equal(runIn(p, source, '123456', 'https://elsewhere.test'), 'https://elsewhere.test');
  assert.equal(field.value, '123456');
});

test('fillFocused: nothing editable focused → false and nothing written', async () => {
  const source = await capturedFillFocused();
  const p = page();
  const cases = [
    null,
    new p.Element('div'),
    new p.HTMLInputElement({ type: 'checkbox' }),
    new p.HTMLInputElement({ type: 'hidden' }),
    new p.HTMLInputElement({ readonly: true }),
    new p.HTMLInputElement({ disabled: true }),
  ];
  for (const el of cases) {
    p.document.activeElement = el;
    assert.equal(runIn(p, source, '123456'), false);
    if (el) assert.equal(el.value ?? '', '');
  }
});

// ---- reconciler (S2, S4) ----------------------------------------------------------------------

const SYNC_VAULT = {
  accounts: [A, B],
  bindings: [binding('https://b.test', 'acc-b'), binding('https://a.test', 'acc-a'), binding('https://orphan.test', 'acc-gone')],
};
const SCRIPT = (matches) => ({
  id: 'autofill',
  matches,
  js: ['lib/fieldfind.js', 'content/autofill.js'],
  allFrames: true,
  runAt: 'document_idle',
  // Registered again on every unlock; nothing is left registered across a browser restart.
  persistAcrossSessions: false,
});

test('sync: registers the content script for exactly the bound origins whose account exists', async () => {
  await seed(SYNC_VAULT);
  await worker.syncRegistrations();
  assert.deepEqual(named('register').map((c) => c[1]), [[SCRIPT(['https://a.test/*', 'https://b.test/*'])]]);
  assert.deepEqual(registered, [SCRIPT(['https://a.test/*', 'https://b.test/*'])]);
  // Already registered: updated in place.
  await worker.syncRegistrations();
  assert.deepEqual(named('update').map((c) => c[1]), [[SCRIPT(['https://a.test/*', 'https://b.test/*'])]]);
});

test('sync: no binding left → the registration is removed', async () => {
  await seed({ accounts: [A] });
  registered = [SCRIPT(['https://a.test/*'])];
  await worker.syncRegistrations();
  assert.deepEqual(named('unregister'), [['unregister', ['autofill']]]);
  assert.deepEqual(registered, []);
  // Nothing registered and nothing bound: no call at all.
  calls.length = 0;
  await worker.syncRegistrations();
  assert.deepEqual(named('unregister').concat(named('register'), named('update')), []);
});

test('sync: removes granted site access no binding uses; keeps manifest host_permissions and a pending offer', async () => {
  await seed(SYNC_VAULT);
  await store.setPendingBind({ origin: 'https://pending.test', accountId: 'acc-a' });
  granted = ['https://a.test/*', 'https://b.test/*', 'https://stale.test/*', REQUIRED, 'https://*/*', 'https://pending.test/*', 'https://orphan.test/*'];
  await worker.syncRegistrations();
  const removed = named('permissions.remove').map((c) => c[1]);
  assert.deepEqual(removed.flat().sort(), ['https://*/*', 'https://orphan.test/*', 'https://stale.test/*']);
  assert.ok(!removed.flat().includes(REQUIRED), 'a manifest permission is never asked to be removed');
  assert.deepEqual(granted.sort(), ['https://a.test/*', 'https://b.test/*', 'https://pending.test/*', REQUIRED]);
});

test('sync: a stored offer keeps its origin at any age (the bind window may still store it); one refused removal does not stop the others', async () => {
  await seed({ accounts: [A] });
  areas.session.set('pendingBind', { origin: 'https://old.test', accountId: 'acc-a', at: Date.now() - 30 * 60 * 1000 });
  granted = ['https://old.test/*', 'https://x.test/*', 'https://y.test/*'];
  refused = new Set(['https://x.test/*']);
  await worker.syncRegistrations();
  assert.deepEqual(granted, ['https://old.test/*', 'https://x.test/*']);
  // Once the offer is gone, its origin's access goes too.
  areas.session.delete('pendingBind');
  await worker.syncRegistrations();
  assert.deepEqual(granted, ['https://x.test/*']);
});

test('sync while locked or idle: the auto-fill script is unregistered and site access is left as it is', async () => {
  for (const options of [{ locked: true }, { lastActive: Date.now() - IDLE_MS }]) {
    await seed(SYNC_VAULT, options);
    registered = [SCRIPT(['https://a.test/*'])];
    granted = ['https://a.test/*', 'https://stale.test/*'];
    calls.length = 0;
    await worker.syncRegistrations();
    assert.deepEqual(calls, [['unregister', ['autofill']]], JSON.stringify(options));
    assert.deepEqual(registered, []);
    assert.deepEqual(granted, ['https://a.test/*', 'https://stale.test/*']);
    // Nothing registered: nothing to do.
    calls.length = 0;
    await worker.syncRegistrations();
    assert.deepEqual(calls, []);
  }
});

test('lock → unregistered; unlock (the key written) → registered again, not persisted across sessions', async () => {
  const key = await seed(SYNC_VAULT);
  await worker.syncRegistrations();
  assert.deepEqual(registered, [SCRIPT(['https://a.test/*', 'https://b.test/*'])]);
  assert.equal(registered[0].persistAcrossSessions, false);
  await store.clearSessionKey();
  await worker.onStorageChanged({ vaultKey: { oldValue: 'x' } }, 'session');
  assert.deepEqual(registered, []);
  calls.length = 0;
  await store.setSessionKey(key);
  await worker.onStorageChanged({ vaultKey: { newValue: 'x' }, lastActiveAt: { newValue: 1 } }, 'session');
  assert.deepEqual(named('register').map((c) => c[1]), [[SCRIPT(['https://a.test/*', 'https://b.test/*'])]]);
});

test('sync: a binding stored (and its offer cleared) while the reconciler runs keeps its site access', async () => {
  // The bind window: the browser granted the site, then the page stores the binding and only then
  // clears the offer, all after the reconciler read the vault without that binding.
  await seed({ accounts: [A] });
  await store.setPendingBind({ origin: 'https://new.test', accountId: 'acc-a' });
  granted = ['https://new.test/*', 'https://stale.test/*'];
  const bindPage = await import('../extension/popup/session.js?bind-window');
  assert.equal(await bindPage.resume(), 'list');
  beforeRegistration = async () => {
    await bindPage.addBinding('https://new.test', 'acc-a');
    await bindPage.clearPendingBind();
  };
  await worker.syncRegistrations();
  assert.equal(beforeRegistration, null, 'the bind window ran between the read and the removal');
  assert.deepEqual(granted, ['https://new.test/*']);
  // The next run (the vault change) registers it.
  await worker.syncRegistrations();
  assert.deepEqual(registered, [SCRIPT(['https://new.test/*'])]);
});

test('the worker pins session storage to trusted contexts (never content scripts) when it loads', () => {
  assert.deepEqual(accessLevels, [{ accessLevel: 'TRUSTED_CONTEXTS' }]);
});

// ---- storage triggers --------------------------------------------------------------------------

test('vault change → menu and registration follow the stored bindings (S4 removal)', async () => {
  await seed(SYNC_VAULT);
  granted = ['https://a.test/*', 'https://b.test/*'];
  await worker.syncRegistrations();
  await rewrite((data) => {
    data.bindings = data.bindings.filter((b) => b.origin !== 'https://a.test');
  });
  calls.length = 0;
  await worker.onStorageChanged({ vault: { newValue: {} } }, 'local');
  assert.deepEqual(registered, [SCRIPT(['https://b.test/*'])]);
  assert.deepEqual(granted, ['https://b.test/*']);
  assert.deepEqual([...menu.keys()], ['zauthenticator', 'acct:acc-a', 'acct:acc-b']);
});

test('session key removed (lock) → unlock item; key written (unlock) → accounts', async () => {
  const key = await seed({ accounts: [A] });
  await worker.rebuildMenu();
  await store.clearSessionKey();
  await worker.onStorageChanged({ vaultKey: { oldValue: 'x' } }, 'session');
  assert.deepEqual([...menu.keys()], ['zauthenticator', 'unlock']);
  await store.setSessionKey(key);
  await worker.onStorageChanged({ vaultKey: { newValue: 'x' }, lastActiveAt: { newValue: 1 } }, 'session');
  assert.deepEqual([...menu.keys()], ['zauthenticator', 'acct:acc-a']);
});

test('a dropped offer reconciles; activity writes and a new offer do not', async () => {
  await seed({ accounts: [A] });
  granted = ['https://offer.test/*'];
  await worker.onStorageChanged({ lastActiveAt: { newValue: 1 } }, 'session');
  await worker.onStorageChanged({ pendingBind: { newValue: { origin: 'https://offer.test' } } }, 'session');
  await worker.onStorageChanged({ other: { newValue: 1 } }, 'local');
  await worker.onStorageChanged({ vaultKey: { newValue: 'x' } }, 'local');
  assert.deepEqual(calls, []);
  await worker.onStorageChanged({ pendingBind: { oldValue: { origin: 'https://offer.test' } } }, 'session');
  assert.deepEqual(granted, []);
});
