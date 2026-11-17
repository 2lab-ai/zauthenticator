// popup/session.js against mocked chrome.storage and Web Locks. Each page() call loads a fresh
// instance of session.js, so two instances act as two extension pages sharing one storage.
import test from 'node:test';
import assert from 'node:assert/strict';

// chrome.storage mock: two areas, async with a macrotask hop per call.
const areas = { local: new Map(), session: new Map() };
const hop = () => new Promise((r) => setTimeout(r, 1));
function area(m) {
  return {
    async get(keys) {
      await hop();
      const list = Array.isArray(keys) ? keys : [keys];
      const out = {};
      for (const k of list) if (m.has(k)) out[k] = structuredClone(m.get(k));
      return out;
    },
    async set(obj) { await hop(); for (const [k, v] of Object.entries(obj)) m.set(k, structuredClone(v)); },
    async remove(keys) { await hop(); for (const k of (Array.isArray(keys) ? keys : [keys])) m.delete(k); },
  };
}
const listeners = new Set();
globalThis.chrome = {
  storage: { local: area(areas.local), session: area(areas.session), onChanged: { addListener(fn) { listeners.add(fn); }, removeListener(fn) { listeners.delete(fn); } } },
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
const totp = await import('../extension/lib/totp.js');
// A namespace import: one missing helper fails its own case, not the whole file.
const format = await import('../extension/popup/format.js');
let n = 0;
const page = () => import(`../extension/popup/session.js?page=${++n}`);
const PASS = 'correct horse battery';
const STALE = () => Date.now() - 16 * 60 * 1000;
const ACC = { issuer: 'Ex', label: 'a@b', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 };

async function seed(data = { accounts: [] }) {
  areas.local.clear();
  areas.session.clear();
  const { record, rawKey } = await vault.create(PASS, data, { iterations: 1000 });
  await store.saveRecord(record);
  await store.setSessionKey(rawKey, { v: 1 });
  return record;
}
async function reopen() {
  return vault.open((await store.getSessionKey()).key, await store.getRecord());
}
// Holds the vault Web Lock until release() is called.
function holdLock() {
  let release;
  const held = new Promise((r) => { release = r; });
  let acquired;
  const ready = new Promise((r) => { acquired = r; });
  navigator.locks.request('zauthenticator-vault', () => { acquired(); return held; });
  return { ready, release };
}

test('session keys carry vault identity and legacy strings are rejected', async () => {
  areas.session.clear();
  const key = new Uint8Array(32).fill(7);
  await store.setSessionKey(key, { v: 1 });
  assert.deepEqual(await store.getSessionKey(), { key, v: 1 });
  areas.session.set('vaultKey', btoa('x'.repeat(32)));
  assert.equal(await store.getSessionKey(), null);
});

test('every lock replaces shared lock generation', async () => {
  areas.session.clear();
  assert.equal(await store.getLockGen(), null);
  await store.clearSessionKey();
  const first = await store.getLockGen();
  assert.equal(atob(first).length, 16);
  await store.clearSessionKey();
  assert.notEqual(await store.getLockGen(), first);
});

test('ceremony capture is invalidated by another page edit or lock cycle', async () => {
  await seed();
  const a = await page();
  const b = await page();
  assert.equal(await a.resume(), 'list');
  assert.equal(await b.resume(), 'list');
  const editCapture = await a.captureForCeremony();
  await b.addAccounts([ACC]);
  await assert.rejects(a.enrollPasskey(editCapture, PASS, {}), (e) => e.code === 'changed');
  const lockCapture = await a.captureForCeremony();
  await b.lock();
  await b.unlock(PASS);
  await b.lock();
  await assert.rejects(a.enrollPasskey(lockCapture, PASS, {}), (e) => e.code === 'changed');
});

test('enrollment precheck rejects bad passphrase without changing stored record', async () => {
  const record = await seed();
  const a = await page();
  assert.equal(await a.resume(), 'list');
  await assert.rejects(a.checkPassphrase('incorrect'), (e) => e.code === 'bad-passphrase');
  assert.equal(await a.checkPassphrase(PASS), true);
  assert.deepEqual(await store.getRecord(), record);
});

test('worker refuses and clears mismatched session identity', async () => {
  await seed();
  const value = areas.session.get('vaultKey');
  areas.session.set('vaultKey', { ...value, v: 2, id: btoa('x'.repeat(16)) });
  assert.equal(await (await page()).readUnlocked(), null);
  assert.equal(areas.session.has('vaultKey'), false);
});

const PASSKEY = { cred: new Uint8Array([1, 2, 3]), prfSalt: new Uint8Array(32).fill(4), prf: new Uint8Array(32).fill(5), label: 'phone' };

test('migration invalidates an old page resume and export excludes passkeys', async () => {
  await seed();
  const a = await page();
  const b = await page();
  await a.resume(); await b.resume();
  const capture = await b.captureForCeremony();
  const g = a.generation();
  // Queued in page a with the old v1 key behind page b's migration.
  const enrolling = b.enrollPasskey(capture, PASS, PASSKEY);
  const stale = a.addAccounts([ACC]);
  await enrolling;
  await assert.rejects(stale, (e) => e.code === 'locked');
  assert.equal((await store.getRecord()).v, 2);
  assert.equal(await a.resume(), 'list');
  assert.notEqual(a.generation(), g, 'the old key is dropped');
  assert.deepEqual(await a.addAccounts([ACC]), { added: 1, duplicates: 0, invalid: 0 });
  assert.equal((await store.getRecord()).v, 2);
  const live = await store.getRecord();
  const exported = await b.exportRecord();
  assert.equal(live.slots.length, 2);
  assert.equal(exported.slots.length, 1);
  // readBackup stays passphrase-only and reads a v2 record through its passphrase slot.
  assert.equal((await b.readBackup(live, PASS)).length, 1);
  assert.deepEqual(live.slots[1].type, 'passkey');
  assert.equal(exported.id, live.id);
  await b.lock();
  const unlockCapture = await b.captureForCeremony();
  await b.unlockWithPasskey(unlockCapture, PASSKEY.prf);
  assert.equal(b.isUnlocked(), true);
});

test('a remote slot removal refreshes an unchanged ciphertext', async () => {
  await seed();
  const a = await page(); const b = await page();
  await a.resume();
  await a.enrollPasskey(await a.captureForCeremony(), PASS, PASSKEY);
  await b.resume();
  const slot = (await b.passkeyState()).slot;
  await b.removePasskey(slot.cred);
  assert.equal(await a.refresh(), 'changed');
  assert.equal((await a.passkeyState()).slot, null);
});

test('unlock ceremony is rejected after an idle lock in another page', async () => {
  await seed();
  const a = await page(); const b = await page();
  await a.resume();
  await a.enrollPasskey(await a.captureForCeremony(), PASS, PASSKEY);
  await b.resume();
  const capture = await a.captureForCeremony();
  areas.session.set('lastActiveAt', STALE());
  assert.equal(await b.lockIfIdle(), true);
  await assert.rejects(a.unlockWithPasskey(capture, PASSKEY.prf), (e) => e.code === 'changed');
});

test('a failed lock generation write still removes the key', async (t) => {
  await seed();
  const original = chrome.storage.session.set;
  t.after(() => { chrome.storage.session.set = original; });
  chrome.storage.session.set = async () => { throw new Error('set failed'); };
  await assert.rejects(store.clearSessionKey(), /set failed/);
  assert.equal(areas.session.has('vaultKey'), false);
});

test('a failed removal invalidates the stored key and changes generation', async (t) => {
  await seed();
  const original = chrome.storage.session.remove;
  t.after(() => { chrome.storage.session.remove = original; });
  chrome.storage.session.remove = async () => { throw new Error('remove failed'); };
  await assert.rejects(store.clearSessionKey(), /remove failed/);
  assert.equal(await store.getSessionKey(), null);
  assert.equal(atob(await store.getLockGen()).length, 16);
});

// A3: the unlock window (page a, locked) waits in get() while another window (page b) acts.
test('unlock capture is invalidated by edit, removal, manual/idle lock, import merge and lock-unlock-lock elsewhere', async () => {
  const backup = (await vault.create('backup pass 123', { accounts: [{ ...ACC, issuer: 'Imported' }] }, { iterations: 1000 })).record;
  const actions = {
    edit: (b) => b.addAccounts([ACC]),
    remove: async (b) => b.removePasskey((await b.passkeyState()).slot.cred),
    manualLock: (b) => b.lock(),
    idleLock: async (b) => {
      areas.session.set('lastActiveAt', STALE());
      assert.equal(await b.lockIfIdle(), true);
    },
    importMerge: async (b) => b.addAccounts(await b.readBackup(backup, 'backup pass 123')),
    lockUnlockLock: async (b) => { await b.lock(); await b.unlock(PASS); await b.lock(); },
  };
  for (const [name, act] of Object.entries(actions)) {
    await seed();
    const a = await page(); const b = await page();
    await a.resume();
    await a.enrollPasskey(await a.captureForCeremony(), PASS, PASSKEY);
    await a.lock();
    await b.unlock(PASS);
    const capture = await a.captureForCeremony();
    assert.ok(capture.slot, name);
    await act(b);
    const before = structuredClone([...areas.local]);
    const sessionBefore = areas.session.get('vaultKey');
    await assert.rejects(a.unlockWithPasskey(capture, PASSKEY.prf), (e) => e.code === 'changed', name);
    assert.deepEqual([...areas.local], before, `${name}: nothing written`);
    assert.deepEqual(areas.session.get('vaultKey'), sessionBefore, `${name}: session untouched`);
    assert.equal(a.isUnlocked(), false, name);
  }
});

test('unlock with the passkey from a locked window with nothing changed: unlocked with the record identity; a wrong PRF stays locked', async () => {
  await seed();
  const a = await page();
  await a.resume();
  await a.enrollPasskey(await a.captureForCeremony(), PASS, PASSKEY);
  await a.lock();
  const capture = await a.captureForCeremony();
  await assert.rejects(a.unlockWithPasskey(capture, new Uint8Array(32)), (e) => e.code === 'bad-passkey');
  assert.equal(areas.session.has('vaultKey'), false);
  await a.unlockWithPasskey(capture, PASSKEY.prf);
  assert.equal(a.isUnlocked(), true);
  const stored = await store.getSessionKey();
  assert.deepEqual({ v: stored.v, id: stored.id }, vault.identity(await store.getRecord()));
});

test('stale unlocked sessions cannot enroll and wrong passphrase cannot add a slot', async () => {
  await seed();
  const a = await page();
  await a.resume();
  const capture = await a.captureForCeremony();
  const before = await store.getRecord();
  await assert.rejects(a.enrollPasskey(capture, 'wrong', PASSKEY), (e) => e.code === 'bad-passphrase');
  assert.deepEqual(await store.getRecord(), before);
  areas.session.set('lastActiveAt', STALE());
  await assert.rejects(a.enrollPasskey(capture, PASS, PASSKEY), (e) => e.code === 'changed');
  assert.deepEqual(await store.getRecord(), before);
});

test('watch reports both session unlock and lock', () => {
  const changes = [];
  const unwatch = store.watch((change) => changes.push(change));
  for (const listener of listeners) listener({ vaultKey: { newValue: { v: 1, key: 'x' } } }, 'session');
  for (const listener of listeners) listener({ vaultKey: { oldValue: { v: 1, key: 'x' } } }, 'session');
  unwatch();
  assert.deepEqual(changes, [{ locked: false }, { locked: true }]);
});

test('malformed session envelopes never unlock a page or worker', async () => {
  for (const value of [null, {}, { key: btoa('x'.repeat(32)), v: 1, extra: true }, { key: '!!!', v: 1 }, { key: btoa('x'.repeat(32)), v: 2, id: 'bad' }]) {
    await seed();
    areas.session.set('vaultKey', value);
    assert.equal(await (await page()).readUnlocked(), null);
    assert.equal(areas.session.has('vaultKey'), false);
  }
});

test('refresh reports locked when another record invalidates its identity', async () => {
  await seed();
  const a = await page(); const b = await page();
  await a.resume(); await b.resume();
  await b.enrollPasskey(await b.captureForCeremony(), PASS, PASSKEY);
  // Crash between saving the migrated record and replacing the old envelope.
  areas.session.set('vaultKey', { key: btoa('x'.repeat(32)), v: 1 });
  assert.equal(await a.refresh(), 'locked');
  assert.equal(a.isUnlocked(), false);
});

test('ceremony is rejected when generation write fails during a lock', async (t) => {
  await seed();
  const a = await page(); const b = await page();
  await a.resume(); await b.resume();
  await a.enrollPasskey(await a.captureForCeremony(), PASS, PASSKEY);
  await a.lock();
  const capture = await a.captureForCeremony();
  const before = await store.getRecord();
  const original = chrome.storage.session.set;
  t.after(() => { chrome.storage.session.set = original; });
  chrome.storage.session.set = async () => { throw new Error('set failed'); };
  await assert.rejects(b.lock(), /set failed/);
  chrome.storage.session.set = original;
  await assert.rejects(a.unlockWithPasskey(capture, PASSKEY.prf), (e) => e.code === 'changed');
  assert.deepEqual(await store.getRecord(), before);
});

test('activity recorded by another page while the idle decision waits keeps the session', async () => {
  await seed();
  const a = await page();
  assert.equal(await a.resume(), 'list');
  areas.session.set('lastActiveAt', STALE());
  const h = holdLock();
  await h.ready;
  const decision = a.lockIfIdle();
  await hop(); await hop(); await hop();
  // Another page unlocks meanwhile (writes the key with a fresh activity time).
  areas.session.set('lastActiveAt', Date.now());
  h.release();
  assert.equal(await decision, false);
  assert.ok(areas.session.has('vaultKey'), 'stored key survives');
  assert.equal(a.isUnlocked(), true);
});

test('still idle under the lock: locks, removes the key, forgets', async () => {
  await seed();
  const a = await page();
  assert.equal(await a.resume(), 'list');
  areas.session.set('lastActiveAt', STALE());
  assert.equal(await a.lockIfIdle(), true);
  assert.equal(areas.session.has('vaultKey'), false);
  assert.equal(areas.session.has('lastActiveAt'), false);
  assert.equal(a.isUnlocked(), false);
});

test('key already removed by another page: this page ends up locked', async () => {
  await seed();
  const a = await page();
  assert.equal(await a.resume(), 'list');
  await store.clearSessionKey();
  await a.lockIfIdle();
  assert.equal(a.isUnlocked(), false);
});

test('a lock in this page while the decision waits: no second decision', async () => {
  await seed();
  const a = await page();
  assert.equal(await a.resume(), 'list');
  areas.session.set('lastActiveAt', STALE());
  const h = holdLock();
  await h.ready;
  const decision = a.lockIfIdle();
  const g = a.generation();
  const locking = a.lock();
  assert.notEqual(a.generation(), g);
  h.release();
  assert.equal(await decision, false);
  await locking;
});

test('not idle: nothing happens', async () => {
  await seed();
  const a = await page();
  assert.equal(await a.resume(), 'list');
  assert.equal(await a.lockIfIdle(), false);
  assert.ok(areas.session.has('vaultKey'));
  assert.equal(a.isUnlocked(), true);
});

test('two pages adding at once keep both changes', async () => {
  await seed();
  const a = await page();
  const b = await page();
  assert.equal(await a.resume(), 'list');
  assert.equal(await b.resume(), 'list');
  const [fromA, fromB] = await Promise.all([
    a.addAccounts([{ ...ACC, issuer: 'A' }]),
    b.addAccounts([{ ...ACC, issuer: 'B' }]),
  ]);
  assert.deepEqual(fromA, { added: 1, duplicates: 0, invalid: 0 });
  assert.deepEqual(fromB, { added: 1, duplicates: 0, invalid: 0 });
  assert.deepEqual((await reopen()).accounts.map((x) => x.issuer).sort(), ['A', 'B']);
  // The page that saved first catches up with the other page's save.
  assert.equal(await a.refresh(), 'changed');
  assert.equal(a.accounts().length, 2);
});

for (const [name, bad] of [
  ['null', null],
  ['number', 5],
  ['string', 'x'],
  ['array', ['x', { secret: 'JBSWY3DPEHPK3PXP' }]],
  ['object secret without toString', { id: 'bad', issuer: 'Bad', secret: { toString: 1 } }],
]) {
  test(`a malformed stored entry (${name}) does not block adding`, async () => {
    await seed({ accounts: [bad, { id: 'keep', ...ACC, issuer: 'Other' }] });
    const a = await page();
    assert.equal(await a.resume(), 'list');
    const result = await a.addAccounts([ACC]);
    assert.deepEqual(result, { added: 1, duplicates: 0, invalid: 0 });
    // The malformed entry is kept as stored.
    const reopened = await reopen();
    assert.equal(reopened.accounts.length, 3);
    assert.deepEqual(reopened.accounts[0], bad);
    // Duplicates of valid stored entries are still found.
    assert.deepEqual(await a.addAccounts([{ ...ACC, issuer: 'Other' }]), { added: 0, duplicates: 1, invalid: 0 });
  });
}

test('stored entries with object-valued fields show, search and survive without throwing', async () => {
  // Only a hand-edited vault holds these: imports normalize every entry. { toString: 1 } is an
  // object that String() and template literals cannot convert.
  const odd = [
    { id: 'odd-1', issuer: { toString: 1 }, label: { toString: 1 }, secret: { toString: 1 }, period: { toString: 1 } },
    { id: 'odd-2', issuer: {}, label: ['x'], secret: 'JBSWY3DPEHPK3PXP' },
    { id: 'odd-3', issuer: 42, label: 'n', secret: 'JBSWY3DPEHPK3PXP' },
  ];
  await seed({ accounts: odd });
  const a = await page();
  assert.equal(await a.resume(), 'list');
  const shown = a.accounts();
  assert.deepEqual(shown.map((x) => x.id), ['odd-1', 'odd-2', 'odd-3']);

  // What the list renders: names as text, search, the duplicate key.
  assert.deepEqual(shown.map((x) => format.displayName(x)), ['', '', '42 (n)']);
  assert.deepEqual(shown.map((x) => [format.text(x.issuer), format.text(x.label)]), [['', ''], ['', ''], ['42', 'n']]);
  assert.deepEqual(shown.map((x) => format.matchesQuery(x, 'object')), [false, false, false]);
  assert.equal(format.matchesQuery(shown[2], '42'), true);
  for (const x of shown) assert.equal(typeof format.duplicateKey(x), 'string');
  // A secret that is not a string has no code: the row shows "Invalid key".
  await assert.rejects(totp.totp(shown[0]));

  // Adding still works, duplicates are matched against the names as shown, and the odd
  // entries are sealed back exactly as stored.
  assert.deepEqual(await a.addAccounts([ACC]), { added: 1, duplicates: 0, invalid: 0 });
  assert.deepEqual(
    await a.addAccounts([{ issuer: '42', label: 'n', secret: 'JBSWY3DPEHPK3PXP' }, { secret: 'JBSWY3DPEHPK3PXP' }]),
    { added: 0, duplicates: 2, invalid: 0 },
  );
  const reopened = await reopen();
  assert.equal(reopened.accounts.length, 4);
  assert.deepEqual(reopened.accounts.slice(0, 3), odd);
  assert.deepEqual(a.accounts().map((x) => x.id).slice(0, 3), ['odd-1', 'odd-2', 'odd-3']);
});

// Only a hand-edited vault holds an entry without a usable id: the app writes crypto.randomUUID().
const named = (issuer, extra = {}) => ({ ...extra, ...ACC, issuer });
const withoutId = (entry) => {
  if (entry === null || typeof entry !== 'object') return entry;
  const { id, ...rest } = entry;
  return rest;
};
const isId = (id) => typeof id === 'string' && id !== '';
const idLessVault = () => [named('A'), named('B'), named('C', { id: 7 })];

test('entries without a usable id are shown with distinct string ids', async () => {
  await seed({ accounts: idLessVault() });
  const a = await page();
  assert.equal(await a.resume(), 'list');
  const ids = a.accounts().map((x) => x.id);
  assert.deepEqual(a.accounts().map((x) => x.issuer), ['A', 'B', 'C']);
  assert.ok(ids.every(isId), JSON.stringify(ids));
  assert.equal(new Set(ids).size, 3);
  // A passphrase unlock shows them the same way.
  const b = await page();
  await b.unlock(PASS);
  const unlocked = b.accounts().map((x) => x.id);
  assert.ok(unlocked.every(isId), JSON.stringify(unlocked));
  assert.equal(new Set(unlocked).size, 3);
});

test('an entry without a stored id is deleted by the id it was shown with, and only it', async () => {
  await seed({ accounts: idLessVault() });
  const a = await page();
  assert.equal(await a.resume(), 'list');
  const shown = a.accounts().map((x) => x.id);
  assert.equal(await a.deleteAccount(shown[0]), true);
  assert.deepEqual(a.accounts().map((x) => x.issuer), ['B', 'C']);
  const reopened = await reopen();
  assert.deepEqual(reopened.accounts.map((x) => x.issuer), ['B', 'C']);
  // The other two keep the ids they were shown with, now stored.
  assert.deepEqual(reopened.accounts.map((x) => x.id), shown.slice(1));
  assert.deepEqual(a.accounts().map((x) => x.id), shown.slice(1));
});

test('the next seal stores the assigned ids and leaves everything else as it was', async () => {
  const stored = [...idLessVault(), 'not an entry'];
  await seed({ accounts: stored });
  const a = await page();
  assert.equal(await a.resume(), 'list');
  const shown = a.accounts().map((x) => x.id);
  assert.deepEqual(await a.addAccounts([named('D')]), { added: 1, duplicates: 0, invalid: 0 });
  const reopened = await reopen();
  assert.equal(reopened.accounts.length, 5);
  assert.deepEqual(reopened.accounts.slice(0, 4).map(withoutId), stored.map(withoutId));
  const kept = reopened.accounts.slice(0, 3).map((x) => x.id);
  assert.ok(kept.every(isId), JSON.stringify(kept));
  assert.deepEqual(kept, shown);
  // Every later open shows the stored ids.
  const b = await page();
  assert.equal(await b.resume(), 'list');
  assert.deepEqual(b.accounts().map((x) => x.id).slice(0, 3), shown);
});

test('a repeated or empty id is replaced; the first entry with an id keeps it', async () => {
  await seed({ accounts: [named('A', { id: 'dup' }), named('B', { id: 'dup' }), named('C', { id: '' })] });
  const a = await page();
  assert.equal(await a.resume(), 'list');
  const ids = a.accounts().map((x) => x.id);
  assert.equal(ids[0], 'dup');
  assert.ok(ids.every(isId), JSON.stringify(ids));
  assert.equal(new Set(ids).size, 3);
  assert.equal(await a.deleteAccount(ids[1]), true);
  const reopened = await reopen();
  assert.deepEqual(reopened.accounts.map((x) => x.issuer), ['A', 'C']);
  assert.deepEqual(reopened.accounts.map((x) => x.id), ['dup', ids[2]]);
});

test('an id given to an entry without one is the same in every page and every read, and deletes it from any page', async () => {
  await seed({ accounts: idLessVault() });
  const stored = (await reopen()).accounts;
  // The service worker reads without ever holding the record: two reads, the same ids.
  const w = await page();
  const first = (await w.readUnlocked()).accounts.map((x) => x.id);
  const second = (await w.readUnlocked()).accounts.map((x) => x.id);
  assert.deepEqual(second, first);
  assert.ok(first.every((id) => /^h[0-9a-f]{16}-\d+$/.test(id)), JSON.stringify(first));
  assert.equal(new Set(first).size, 3);
  // Pages that unlock by session key or by passphrase show the same ones.
  const a = await page();
  assert.equal(await a.resume(), 'list');
  assert.deepEqual(a.accounts().map((x) => x.id), first);
  const b = await page();
  await b.unlock(PASS);
  assert.deepEqual(b.accounts().map((x) => x.id), first);
  // Nothing is stored by reading.
  assert.deepEqual((await reopen()).accounts, stored);
  // Another page deletes by the id the worker read; the others keep theirs, now stored.
  assert.equal(await b.deleteAccount(first[1]), true);
  assert.deepEqual((await reopen()).accounts.map((x) => [x.issuer, x.id]), [['A', first[0]], ['C', first[2]]]);
  assert.equal(await a.deleteAccount(first[0]), true);
  assert.deepEqual((await reopen()).accounts.map((x) => x.id), [first[2]]);
});

test('identical entries without ids get distinct ids by their order; a stored id is never taken from its entry', async () => {
  const twin = named('Twin');
  await seed({ accounts: [twin, structuredClone(twin), named('Other')] });
  const ids = (await (await page()).readUnlocked()).accounts.map((x) => x.id);
  const base = ids[0].slice(0, -2);
  assert.deepEqual(ids.slice(0, 2), [`${base}-0`, `${base}-1`]);
  assert.notEqual(ids[2].slice(0, -2), base);
  // A later entry that already stores the id the first twin would get keeps it; the twin moves on.
  await seed({ accounts: [twin, named('Later', { id: `${base}-0` })] });
  const again = (await (await page()).readUnlocked()).accounts.map((x) => x.id);
  assert.deepEqual(again, [`${base}-1`, `${base}-0`]);
  // Key order in the stored entry does not change its id.
  const reordered = Object.fromEntries(Object.entries(twin).reverse());
  await seed({ accounts: [reordered] });
  assert.deepEqual((await (await page()).readUnlocked()).accounts.map((x) => x.id), [`${base}-0`]);
});

test('deleting an entry another page already deleted returns false and changes nothing', async () => {
  // Stored ids throughout: an entry without one would get it stored by this seal too.
  await seed({ accounts: [named('A', { id: 'a' }), named('B', { id: 'b' })] });
  const a = await page();
  const b = await page();
  assert.equal(await a.resume(), 'list');
  assert.equal(await b.resume(), 'list');
  assert.equal(await b.deleteAccount('a'), true);
  const before = await reopen();
  // Page a still shows 'a'; its delete finds nothing to remove.
  assert.equal(await a.deleteAccount('a'), false);
  assert.deepEqual(await reopen(), before);
  // Page a now shows the stored list, which is what the list re-renders.
  assert.deepEqual(a.accounts().map((x) => x.id), ['b']);
  for (const id of ['', 7, undefined]) assert.equal(await a.deleteAccount(id), false);
  assert.deepEqual(await reopen(), before);
});

test('an array entry is never an account and every seal keeps it as stored', async () => {
  // Only a hand-edited vault holds one. Between id-less entries, which get ids from their
  // content, so an array never gets or shifts one.
  const arrays = [['x', 1], [], [{ id: 'inner', ...ACC }]];
  const stored = [named('A'), arrays[0], named('B'), arrays[1], named('C', { id: 'c' }), arrays[2]];
  const json = arrays.map((x) => JSON.stringify(x));
  // Each array is where it was, with the same JSON; the objects around it are the same entries.
  const keptAsStored = (accounts) => {
    assert.equal(accounts.length, stored.length);
    stored.forEach((x, i) => {
      if (Array.isArray(x)) assert.equal(JSON.stringify(accounts[i]), JSON.stringify(x));
      else assert.equal(accounts[i].issuer, x.issuer);
    });
  };
  await seed({ accounts: stored });
  const a = await page();
  assert.equal(await a.resume(), 'list');
  assert.deepEqual(a.accounts().map((x) => x.issuer), ['A', 'B', 'C']);
  assert.ok(a.accounts().every((x) => !Array.isArray(x)));
  const shown = a.accounts().map((x) => x.id);
  assert.ok(shown.every(isId), JSON.stringify(shown));

  // A delete that finds nothing, an add, a delete that removes A: each one seals.
  assert.equal(await a.deleteAccount('no such id'), false);
  keptAsStored((await reopen()).accounts);
  assert.deepEqual(await a.addAccounts([named('D')]), { added: 1, duplicates: 0, invalid: 0 });
  // An incoming array is not an account either.
  assert.deepEqual(await a.addAccounts([['x', 1]]), { added: 0, duplicates: 0, invalid: 1 });
  let reopened = await reopen();
  assert.equal(reopened.accounts.length, stored.length + 1);
  keptAsStored(reopened.accounts.slice(0, stored.length));
  assert.equal(await a.deleteAccount(shown[0]), true);
  reopened = await reopen();
  assert.deepEqual(reopened.accounts.filter((x) => !Array.isArray(x)).map((x) => x.issuer), ['B', 'C', 'D']);
  assert.deepEqual(reopened.accounts.filter((x) => Array.isArray(x)).map((x) => JSON.stringify(x)), json);
  assert.deepEqual(a.accounts().map((x) => x.issuer), ['B', 'C', 'D']);

  // Another page, by session key or passphrase, does not show them either.
  const b = await page();
  assert.equal(await b.resume(), 'list');
  assert.deepEqual(b.accounts().map((x) => x.issuer), ['B', 'C', 'D']);
  const c = await page();
  await c.unlock(PASS);
  assert.deepEqual(c.accounts().map((x) => x.issuer), ['B', 'C', 'D']);
});

test('readBackup that finishes after a lock hands nothing back', async () => {
  await seed();
  const a = await page();
  assert.equal(await a.resume(), 'list');
  const backup = (await vault.create('backup pass 123', { accounts: [ACC] }, { iterations: 200000 })).record;
  const reading = a.readBackup(backup, 'backup pass 123');
  await a.lock();
  await assert.rejects(reading, (e) => e.code === 'locked');
});

test('readBackup while unlocked still returns the entries', async () => {
  await seed();
  const a = await page();
  assert.equal(await a.resume(), 'list');
  const backup = (await vault.create('backup pass 123', { accounts: [ACC] }, { iterations: 1000 })).record;
  const list = await a.readBackup(backup, 'backup pass 123');
  assert.equal(list.length, 1);
});

// Auto-fill: bindings in the vault data, the worker's read path, the pending bind offer.
const OTP = 'https://otp.test';
const SESSION_KEYS = ['vaultKey', 'lastActiveAt', 'pendingBind'];
const twoAccounts = () => ({ accounts: [named('A', { id: 'a' }), named('B', { id: 'b' })] });
const storedBindings = async () => (await reopen()).bindings;
const pairs = (list) => list.map((x) => [x.origin, x.accountId]);

test('addBinding persists, survives later seals and shows in another page', async () => {
  await seed(twoAccounts());
  const a = await page();
  assert.equal(await a.resume(), 'list');
  const before = Date.now();
  await a.addBinding(OTP, 'a');
  const [shown] = a.bindings();
  assert.deepEqual([shown.origin, shown.accountId], [OTP, 'a']);
  assert.ok(shown.createdAt >= before && shown.createdAt <= Date.now());
  assert.deepEqual(await storedBindings(), [shown]);
  // Another page reads it from the sealed record.
  const b = await page();
  assert.equal(await b.resume(), 'list');
  assert.deepEqual(b.bindings(), [shown]);
  // Seals that change accounts keep it.
  assert.deepEqual(await b.addAccounts([named('C')]), { added: 1, duplicates: 0, invalid: 0 });
  assert.equal(await b.deleteAccount('b'), true);
  assert.deepEqual(await storedBindings(), [shown]);
  assert.equal(await a.refresh(), 'changed');
  assert.deepEqual(a.bindings(), [shown]);
});

test('addBinding replaces the binding of the same origin and leaves other origins alone', async () => {
  await seed(twoAccounts());
  const a = await page();
  assert.equal(await a.resume(), 'list');
  await a.addBinding(OTP, 'a');
  await a.addBinding('https://other.test', 'a');
  await a.addBinding(OTP, 'b');
  // The replacement goes to the end of the list.
  assert.deepEqual(pairs(await storedBindings()), [['https://other.test', 'a'], [OTP, 'b']]);
  assert.deepEqual(pairs(a.bindings()), [['https://other.test', 'a'], [OTP, 'b']]);
});

test('addBinding accepts what new URL(..).origin gives, refuses anything else, stores nothing on refusal', async () => {
  await seed(twoAccounts());
  const a = await page();
  assert.equal(await a.resume(), 'list');
  const ct = (await store.getRecord()).ct;
  for (const origin of ['http://otp.test', 'https://otp.test/', 'https://otp.test/login', 'https://OTP.test', 'data:text/html,x', '', null]) {
    await assert.rejects(a.addBinding(origin, 'a'), (e) => e instanceof a.SessionError && e.code === 'bad-origin', String(origin));
  }
  for (const id of ['nope', '', 7, undefined]) {
    await assert.rejects(a.addBinding(OTP, id), (e) => e instanceof a.SessionError && e.code === 'no-account', String(id));
  }
  assert.equal((await store.getRecord()).ct, ct);
  for (const url of ['https://otp.test:8443/login', 'https://[::1]/x', 'https://bücher.example/']) {
    await a.addBinding(new URL(url).origin, 'a');
  }
  assert.deepEqual(pairs(await storedBindings()).map(([o]) => o).sort(), ['https://[::1]', 'https://otp.test:8443', 'https://xn--bcher-kva.example']);
});

test('addBinding while locked is refused', async () => {
  await seed(twoAccounts());
  const ct = (await store.getRecord()).ct;
  const a = await page();
  await assert.rejects(a.addBinding(OTP, 'a'), (e) => e.code === 'locked');
  assert.equal(await a.resume(), 'list');
  await a.lock();
  await assert.rejects(a.addBinding(OTP, 'a'), (e) => e.code === 'locked');
  assert.equal((await store.getRecord()).ct, ct);
});

test('removeBinding removes that origin only and reports whether it found one', async () => {
  await seed(twoAccounts());
  const a = await page();
  assert.equal(await a.resume(), 'list');
  await a.addBinding(OTP, 'a');
  await a.addBinding('https://other.test', 'b');
  assert.equal(await a.removeBinding(OTP), true);
  assert.deepEqual(pairs(await storedBindings()), [['https://other.test', 'b']]);
  assert.deepEqual(pairs(a.bindings()), [['https://other.test', 'b']]);
  assert.equal(await a.removeBinding(OTP), false);
  assert.equal(await a.removeBinding('https://sub.other.test'), false);
  assert.equal(await a.removeBinding('nonsense'), false);
  assert.deepEqual(pairs(await storedBindings()), [['https://other.test', 'b']]);
  // Another page removes the last one.
  const b = await page();
  assert.equal(await b.resume(), 'list');
  assert.equal(await b.removeBinding('https://other.test'), true);
  assert.deepEqual(await storedBindings(), []);
});

test("deleteAccount removes that account's bindings in the same seal", async () => {
  await seed({
    accounts: [named('A', { id: 'a' }), named('B', { id: 'b' })],
    bindings: [
      { origin: OTP, accountId: 'a', createdAt: 1 },
      { origin: 'https://b.test', accountId: 'b', createdAt: 2 },
      'kept as stored',
      { origin: 'https://a2.test', accountId: 'a', createdAt: 3 },
    ],
  });
  const a = await page();
  assert.equal(await a.resume(), 'list');
  assert.equal(await a.deleteAccount('a'), true);
  const reopened = await reopen();
  assert.deepEqual(reopened.accounts.map((x) => x.id), ['b']);
  assert.deepEqual(reopened.bindings, [{ origin: 'https://b.test', accountId: 'b', createdAt: 2 }, 'kept as stored']);
  assert.deepEqual(pairs(a.bindings()), [['https://b.test', 'b']]);
});

test('deleteAccount on a vault without bindings stores no bindings key', async () => {
  await seed(twoAccounts());
  const a = await page();
  assert.equal(await a.resume(), 'list');
  assert.equal(await a.deleteAccount('a'), true);
  assert.equal('bindings' in (await reopen()), false);
});

test('a malformed stored bindings value does not block the vault and reads as none', async () => {
  await seed({ ...twoAccounts(), bindings: { not: 'a list' } });
  const a = await page();
  assert.equal(await a.resume(), 'list');
  assert.deepEqual(a.bindings(), []);
  assert.equal(a.accounts().length, 2);
  assert.deepEqual(await a.addAccounts([named('C')]), { added: 1, duplicates: 0, invalid: 0 });
  assert.deepEqual((await reopen()).bindings, { not: 'a list' });
  assert.equal(await a.removeBinding(OTP), false);
  assert.deepEqual((await reopen()).bindings, { not: 'a list' });
});

test('bindings() is empty while locked', async () => {
  await seed({ ...twoAccounts(), bindings: [{ origin: OTP, accountId: 'a', createdAt: 1 }] });
  const a = await page();
  assert.deepEqual(a.bindings(), []);
  assert.equal(await a.resume(), 'list');
  assert.equal(a.bindings().length, 1);
  await a.lock();
  assert.deepEqual(a.bindings(), []);
});

test('readUnlocked in an instance that never unlocked (the worker) reads storage and publishes nothing', async () => {
  await seed({ ...twoAccounts(), bindings: [{ origin: OTP, accountId: 'a', createdAt: 1 }] });
  const w = await page();
  const data = await w.readUnlocked();
  assert.deepEqual(data.accounts.map((x) => x.id), ['a', 'b']);
  assert.deepEqual(data.bindings, [{ origin: OTP, accountId: 'a', createdAt: 1 }]);
  assert.equal(w.isUnlocked(), false);
  assert.deepEqual(w.accounts(), []);
  assert.deepEqual(w.bindings(), []);
  // Each call reads storage again: a binding another page added shows at once.
  const a = await page();
  assert.equal(await a.resume(), 'list');
  await a.addBinding('https://other.test', 'b');
  assert.deepEqual(pairs((await w.readUnlocked()).bindings), [[OTP, 'a'], ['https://other.test', 'b']]);
  // A lock elsewhere: nothing to read.
  await a.lock();
  assert.equal(await w.readUnlocked(), null);
});

test('readUnlocked gives entries ids, the same ones a page holding that record shows', async () => {
  await seed({ accounts: idLessVault() });
  const w = await page();
  const ids = (await w.readUnlocked()).accounts.map((x) => x.id);
  assert.ok(ids.every(isId), JSON.stringify(ids));
  assert.equal(new Set(ids).size, 3);
  const a = await page();
  assert.equal(await a.resume(), 'list');
  assert.deepEqual((await a.readUnlocked()).accounts.map((x) => x.id), a.accounts().map((x) => x.id));
});

test('readUnlocked leaves out stored entries that are not accounts, as accounts() does', async () => {
  const stored = [null, 'x', ['arr', 1], named('A', { id: 'a' }), 5, named('B', { id: 'b' })];
  await seed({ accounts: stored, bindings: [{ origin: OTP, accountId: 'a', createdAt: 1 }] });
  const w = await page();
  assert.deepEqual((await w.readUnlocked()).accounts.map((x) => x.id), ['a', 'b']);
  // Nothing stored changes.
  assert.deepEqual((await reopen()).accounts, stored);
});

test('readUnlocked does not touch lastActiveAt unless asked', async () => {
  await seed(twoAccounts());
  const w = await page();
  const known = Date.now() - 60 * 1000;
  areas.session.set('lastActiveAt', known);
  assert.ok(await w.readUnlocked());
  assert.equal(areas.session.get('lastActiveAt'), known);
  assert.ok(await w.readUnlocked({ touch: false }));
  assert.equal(areas.session.get('lastActiveAt'), known);
  assert.ok(await w.readUnlocked({ touch: true }));
  assert.ok(areas.session.get('lastActiveAt') > known);
});

test('readUnlocked on a stale session clears all three session keys and returns null', async () => {
  await seed(twoAccounts());
  await store.setPendingBind({ origin: OTP, accountId: 'a' });
  areas.session.set('lastActiveAt', STALE());
  const w = await page();
  assert.equal(await w.readUnlocked({ touch: true }), null);
  for (const k of SESSION_KEYS) assert.equal(areas.session.has(k), false, k);
  // A page holding the key drops it too.
  await seed(twoAccounts());
  const a = await page();
  assert.equal(await a.resume(), 'list');
  areas.session.set('lastActiveAt', STALE());
  assert.equal(await a.readUnlocked(), null);
  assert.equal(a.isUnlocked(), false);
  assert.equal(areas.session.has('vaultKey'), false);
});

test('readUnlocked: no vault, no key, or a key that does not open the record → null', async () => {
  await seed(twoAccounts());
  const w = await page();
  // A key that does not open the stored record is cleared, like resume() does.
  areas.session.set('vaultKey', { key: btoa('x'.repeat(32)), v: 1 });
  await store.setPendingBind({ origin: OTP, accountId: 'a' });
  assert.equal(await w.readUnlocked(), null);
  for (const k of SESSION_KEYS) assert.equal(areas.session.has(k), false, k);
  assert.equal(await w.readUnlocked(), null);
  areas.local.clear();
  assert.equal(await w.readUnlocked(), null);
});

test('readUnlocked that finishes after a lock in this page hands nothing back', async () => {
  await seed(twoAccounts());
  const a = await page();
  assert.equal(await a.resume(), 'list');
  const h = holdLock();
  await h.ready;
  let reading;
  let locking;
  try {
    reading = a.readUnlocked();
    locking = a.lock();
  } finally {
    // Released even when a call throws, so later cases do not wait on a held lock.
    h.release();
  }
  assert.equal(await reading, null);
  await locking;
});

test('pendingBind: set while unlocked, taken (and kept) until cleared', async () => {
  await seed(twoAccounts());
  const w = await page();
  const before = Date.now();
  assert.equal(await w.setPendingBind({ origin: OTP, accountId: 'a' }), true);
  const stored = areas.session.get('pendingBind');
  assert.deepEqual(Object.keys(stored).sort(), ['accountId', 'at', 'origin']);
  assert.deepEqual([stored.origin, stored.accountId], [OTP, 'a']);
  assert.ok(stored.at >= before && stored.at <= Date.now());
  // The bind window is another page.
  const p = await page();
  assert.deepEqual(await p.takePendingBind(), stored);
  assert.deepEqual(await p.takePendingBind(), stored);
  await p.clearPendingBind();
  assert.equal(await p.takePendingBind(), null);
  assert.equal(areas.session.has('pendingBind'), false);
  assert.ok(areas.session.has('vaultKey'), 'clearing the offer keeps the session');
});

test('pendingBind: an old or future offer is expired', async () => {
  await seed(twoAccounts());
  const p = await page();
  await store.setPendingBind({ origin: OTP, accountId: 'a' }, Date.now() - 121 * 1000);
  assert.equal((await p.takePendingBind(300 * 1000)).origin, OTP);
  assert.equal(await p.takePendingBind(), null);
  assert.equal(areas.session.has('pendingBind'), false);
  await store.setPendingBind({ origin: OTP, accountId: 'a' }, Date.now() - 30 * 1000);
  assert.equal(await p.takePendingBind(10 * 1000), null);
  await store.setPendingBind({ origin: OTP, accountId: 'a' }, Date.now() + 10 * 60 * 1000);
  assert.equal(await p.takePendingBind(), null);
  areas.session.set('pendingBind', { origin: OTP, accountId: 7, at: Date.now() });
  assert.equal(await p.takePendingBind(), null);
});

test('pendingBind is not written while locked, idle, or with a bad origin', async () => {
  await seed(twoAccounts());
  const w = await page();
  assert.equal(await w.setPendingBind({ origin: 'http://otp.test', accountId: 'a' }), false);
  assert.equal(await w.setPendingBind({ origin: 'https://otp.test/login', accountId: 'a' }), false);
  assert.equal(await w.setPendingBind({ origin: OTP, accountId: '' }), false);
  assert.equal(await w.setPendingBind(), false);
  assert.equal(areas.session.has('pendingBind'), false);
  areas.session.set('lastActiveAt', STALE());
  assert.equal(await w.setPendingBind({ origin: OTP, accountId: 'a' }), false);
  await store.clearSessionKey();
  assert.equal(await w.setPendingBind({ origin: OTP, accountId: 'a' }), false);
  assert.equal(areas.session.has('pendingBind'), false);
});

test('every lock path removes pendingBind with the key', async () => {
  const offer = { origin: OTP, accountId: 'a' };
  // Manual lock.
  await seed(twoAccounts());
  let a = await page();
  assert.equal(await a.resume(), 'list');
  assert.equal(await a.setPendingBind(offer), true);
  await a.lock();
  for (const k of SESSION_KEYS) assert.equal(areas.session.has(k), false, k);
  // Idle lock decided under the vault lock.
  await seed(twoAccounts());
  a = await page();
  assert.equal(await a.resume(), 'list');
  assert.equal(await a.setPendingBind(offer), true);
  areas.session.set('lastActiveAt', STALE());
  assert.equal(await a.lockIfIdle(), true);
  for (const k of SESSION_KEYS) assert.equal(areas.session.has(k), false, k);
  // A page opening on an idle session.
  await seed(twoAccounts());
  await store.setPendingBind(offer);
  areas.session.set('lastActiveAt', STALE());
  a = await page();
  assert.equal(await a.resume(), 'locked');
  for (const k of SESSION_KEYS) assert.equal(areas.session.has(k), false, k);
  // store.clearSessionKey() itself.
  await seed(twoAccounts());
  await store.setPendingBind(offer);
  await store.clearSessionKey();
  for (const k of SESSION_KEYS) assert.equal(areas.session.has(k), false, k);
});

// The worker's auto-fill record (lib/autofill-worker.js: which tab got which code counter, never a
// code) goes with every lock, like the offer.
test('every lock path removes the auto-fill record with the key', async () => {
  const record = () => areas.session.set('autofillServed', [{ tab: 1, origin: OTP, account: 'a', counter: 1, at: Date.now() }]);
  // Manual lock.
  await seed(twoAccounts());
  let a = await page();
  assert.equal(await a.resume(), 'list');
  record();
  await a.lock();
  assert.equal(areas.session.has('autofillServed'), false, 'manual lock');
  // Idle lock decided under the vault lock.
  await seed(twoAccounts());
  a = await page();
  assert.equal(await a.resume(), 'list');
  record();
  areas.session.set('lastActiveAt', STALE());
  assert.equal(await a.lockIfIdle(), true);
  assert.equal(areas.session.has('autofillServed'), false, 'lockIfIdle');
  // A page opening on an idle session.
  await seed(twoAccounts());
  record();
  areas.session.set('lastActiveAt', STALE());
  a = await page();
  assert.equal(await a.resume(), 'locked');
  assert.equal(areas.session.has('autofillServed'), false, 'resume on an idle session');
  // The worker's read on an idle session.
  await seed(twoAccounts());
  record();
  areas.session.set('lastActiveAt', STALE());
  assert.equal(await (await page()).readUnlocked(), null);
  assert.equal(areas.session.has('autofillServed'), false, 'readUnlocked on an idle session');
  // store.clearSessionKey() itself.
  await seed(twoAccounts());
  record();
  await store.clearSessionKey();
  assert.equal(areas.session.has('autofillServed'), false, 'clearSessionKey');
});

test('the id given to an entry without one says nothing about its secret or fields the app does not know', async () => {
  // The id leaves the encrypted record (menu item ids, the session's bind offer): only the fields
  // the menu already shows or that are no secret go into it.
  const one = named('Same', { notes: 'backup codes 1111 2222' });
  const other = { ...named('Same', { notes: 'something else' }), secret: 'GEZDGNBVGY3TQOJQ' };
  await seed({ accounts: [one, other] });
  const ids = (await (await page()).readUnlocked()).accounts.map((x) => x.id);
  const base = ids[0].slice(0, -2);
  assert.deepEqual(ids, [`${base}-0`, `${base}-1`]);
  // A different issuer, label or code parameter does give another id.
  for (const change of [{ issuer: 'Else' }, { label: 'else@b' }, { digits: 8 }, { period: 60 }, { algorithm: 'SHA256' }]) {
    await seed({ accounts: [{ ...one, ...change }] });
    const [id] = (await (await page()).readUnlocked()).accounts.map((x) => x.id);
    assert.notEqual(id.slice(0, -2), base, JSON.stringify(change));
  }
});

test('clearPendingBind(offer) removes only that exact offer: a window showing an older one leaves a newer one', async () => {
  await seed(twoAccounts());
  const shown = await page();
  await store.setPendingBind({ origin: OTP, accountId: 'a' }, Date.now() - 5000);
  const older = await shown.takePendingBind();
  // A newer menu fill replaces the offer while the older window is still open.
  await store.setPendingBind({ origin: 'https://newer.test', accountId: 'b' });
  const newer = areas.session.get('pendingBind');
  const result = await shown.clearPendingBind(older);
  assert.deepEqual(areas.session.get('pendingBind'), newer, 'the newer offer stays');
  assert.equal(result, false);
  // Every field must match.
  for (const near of [{ ...newer, at: newer.at + 1 }, { ...newer, accountId: 'a' }, { ...newer, origin: OTP }, { origin: newer.origin }, {}]) {
    assert.equal(await shown.clearPendingBind(near), false, JSON.stringify(near));
    assert.deepEqual(areas.session.get('pendingBind'), newer);
  }
  assert.equal(await shown.clearPendingBind({ ...newer }), true);
  assert.equal(areas.session.has('pendingBind'), false);
  assert.ok(areas.session.has('vaultKey'), 'clearing the offer keeps the session');
  assert.equal(await shown.clearPendingBind(newer), false);
});

test('withVaultState hands fresh data and the stored offer (any age) to fn while holding the vault lock', async () => {
  await seed({ ...twoAccounts(), bindings: [{ origin: OTP, accountId: 'a', createdAt: 1 }] });
  await store.setPendingBind({ origin: 'https://old-offer.test', accountId: 'b' }, Date.now() - 60 * 60 * 1000);
  const w = await page();
  const a = await page();
  assert.equal(await a.resume(), 'list');
  const order = [];
  let release;
  const held = new Promise((r) => { release = r; });
  const running = w.withVaultState(async (state) => {
    order.push('fn');
    await held;
    order.push('fn done');
    return state;
  });
  // A page's change queued behind fn waits for it.
  while (!order.includes('fn')) await hop();
  const adding = a.addBinding('https://other.test', 'b').then(() => order.push('addBinding'));
  await hop(); await hop(); await hop();
  assert.deepEqual(order, ['fn']);
  release();
  const { data, pending } = await running;
  await adding;
  assert.deepEqual(order, ['fn', 'fn done', 'addBinding']);
  assert.deepEqual(data.accounts.map((x) => x.id), ['a', 'b']);
  assert.deepEqual(pairs(data.bindings), [[OTP, 'a']]);
  assert.deepEqual([pending.origin, pending.accountId], ['https://old-offer.test', 'b']);
  assert.equal(w.isUnlocked(), false, 'the worker instance publishes nothing');
  // The next call sees the binding the page stored.
  const next = await w.withVaultState(async (state) => state);
  assert.deepEqual(pairs(next.data.bindings), [[OTP, 'a'], ['https://other.test', 'b']]);
});

test('withVaultState: locked → data null; idle or a key that does not open the record → keys cleared, data and pending null', async () => {
  await seed(twoAccounts());
  const w = await page();
  await store.setPendingBind({ origin: OTP, accountId: 'a' });
  areas.session.delete('vaultKey');
  assert.equal((await w.withVaultState(async (state) => state)).data, null);
  for (const spoil of [() => areas.session.set('lastActiveAt', STALE()), () => areas.session.set('vaultKey', { key: btoa('x'.repeat(32)), v: 1 })]) {
    await seed(twoAccounts());
    await store.setPendingBind({ origin: OTP, accountId: 'a' });
    spoil();
    assert.deepEqual(await w.withVaultState(async (state) => state), { data: null, pending: null });
    for (const k of SESSION_KEYS) assert.equal(areas.session.has(k), false, k);
  }
  // fn's result and error pass through.
  await seed(twoAccounts());
  assert.equal(await w.withVaultState(async () => 42), 42);
  await assert.rejects(w.withVaultState(async () => { throw new Error('boom'); }), /boom/);
});
