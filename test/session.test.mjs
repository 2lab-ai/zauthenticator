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
globalThis.chrome = {
  storage: { local: area(areas.local), session: area(areas.session), onChanged: { addListener() {}, removeListener() {} } },
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
  await store.setSessionKey(rawKey);
  return record;
}
async function reopen() {
  return vault.open(await store.getSessionKey(), await store.getRecord());
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
  ['object secret without toString', { issuer: 'Bad', secret: { toString: 1 } }],
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
