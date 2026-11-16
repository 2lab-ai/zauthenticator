// The unlocked vault as seen by this page: the raw key and the decrypted data live in memory
// only; storage holds the sealed record (local) and the raw key (session, see lib/store.js).
//
// Every read-modify-write of stored vault state runs under one Web Lock. All extension pages
// of this origin share it (the popup and a full tab), so two pages never interleave
// read → change → seal → save, and a lock never lands between an unlock's checks and its
// session-key write. Locking bumps a generation counter at once, before waiting for that
// Web Lock; async work captures the generation and key when it starts and publishes its
// result (the in-memory key and data, the session key) only if neither changed meanwhile.
import * as vault from '../lib/vault.js';
import * as store from '../lib/store.js';
import { normalize } from '../lib/otpauth.js';
import { duplicateKey } from './format.js';

const LOCK_NAME = 'zauthenticator-vault';

// Locks after this long without user activity in any extension page (fixed in v0.1).
export const IDLE_LOCK_MS = 15 * 60 * 1000;
// An activity time this far in the future means the clock was set back: treat it as idle.
const CLOCK_SLACK_MS = 60 * 1000;

let rawKey = null;   // Uint8Array while unlocked
let data = null;     // { accounts: [...] } as stored plus the ids withIds() gave, while unlocked
let recordCt = null; // ciphertext of the record `data` was read from or sealed into
let epoch = 0;       // the generation; forget() bumps it

function exclusive(task) {
  return navigator.locks.request(LOCK_NAME, () => task());
}

export function isUnlocked() {
  return rawKey !== null;
}

// Changes whenever this page locks or forgets the vault. UI work that awaits compares it
// before writing anything back into the page.
export function generation() {
  return epoch;
}

// The stored entries, for display; empty while locked. Each has an id no other entry has (a
// non-empty string). An entry that is not an object, or is an array (only a hand-made vault could
// hold one), stays stored but is not shown.
export function accounts() {
  if (rawKey === null || data === null) return [];
  return data.accounts.filter(isEntry);
}

// → 'setup' | 'locked' | 'list'. Locks first when the session sat idle too long.
// Runs while this page holds no key (startup, or re-checking a locked page), so finding the
// vault locked must not bump the generation: that would cancel an unlock queued behind it.
export function resume() {
  const gen = epoch;
  return exclusive(async () => {
    const record = await store.getRecord();
    if (!record) {
      drop();
      return 'setup';
    }
    const key = await store.getSessionKey();
    if (!key) {
      drop();
      return 'locked';
    }
    if (isStale(await store.getLastActive())) {
      drop();
      await store.clearSessionKey();
      return 'locked';
    }
    let current;
    try {
      current = loaded(record, await vault.open(key, record));
    } catch {
      // The session key does not open the stored record; ask for the passphrase again.
      drop();
      await store.clearSessionKey();
      return 'locked';
    }
    if (epoch !== gen) return 'locked';
    // Opening a page is activity.
    await store.touch();
    if (epoch !== gen) return 'locked';
    remember(key, record, current);
    return 'list';
  });
}

export function create(passphrase) {
  const gen = epoch;
  return exclusive(async () => {
    if (await store.getRecord()) throw new SessionError('vault-exists');
    const empty = { accounts: [] };
    const { record, rawKey: key } = await vault.create(passphrase, empty);
    if (epoch !== gen) throw new SessionError('locked');
    await store.saveRecord(record);
    if (epoch !== gen) throw new SessionError('locked');
    await store.setSessionKey(key);
    // A lock() that arrived meanwhile clears the session key as soon as this returns.
    if (epoch !== gen) throw new SessionError('locked');
    remember(key, record, normalizeData(empty));
  });
}

// Throws whatever vault.unlock throws for a wrong passphrase.
export function unlock(passphrase) {
  const gen = epoch;
  return exclusive(async () => {
    const record = await store.getRecord();
    if (!record) throw new SessionError('no-vault');
    const opened = await vault.unlock(record, passphrase);
    const current = loaded(record, opened.data);
    if (epoch !== gen) throw new SessionError('locked');
    await store.setSessionKey(opened.rawKey);
    if (epoch !== gen) throw new SessionError('locked');
    remember(opened.rawKey, record, current);
  });
}

export async function lock() {
  forget();
  await exclusive(() => store.clearSessionKey());
}

// Drops the in-memory key and data and invalidates in-flight work. The key bytes are not
// zeroed: an in-flight seal may still hold the same array, and sealing with a wiped key
// would make the vault undecryptable.
function forget() {
  epoch++;
  rawKey = null;
  data = null;
  recordCt = null;
}

// forget(), but only when this page holds a key: nothing else is in flight to invalidate.
function drop() {
  if (rawKey !== null) forget();
}

// Re-checks this page against storage after a change notification: another page saved or
// locked, or the notification is the echo of this page's own write.
// → 'unchanged' | 'changed' (data re-read) | 'locked' | 'setup' (this call dropped the key)
//   | 'stale' (this page locked or changed while the check ran; nothing to do)
export function refresh() {
  const gen = epoch;
  const key = rawKey;
  if (!key) return Promise.resolve('stale');
  return exclusive(async () => {
    const live = () => epoch === gen && rawKey === key;
    if (!live()) return 'stale';
    const record = await store.getRecord();
    if (!live()) return 'stale';
    if (!record) {
      forget();
      return 'setup';
    }
    const stored = await store.getSessionKey();
    if (!live()) return 'stale';
    if (!stored || !sameBytes(stored, key)) {
      forget();
      return 'locked';
    }
    if (record.ct === recordCt) return 'unchanged';
    let current;
    try {
      current = loaded(record, await vault.open(key, record));
    } catch {
      if (!live()) return 'stale';
      forget();
      return 'locked';
    }
    if (!live()) return 'stale';
    remember(key, record, current);
    return 'changed';
  });
}

// Records user activity. → 'touched' | 'idle' (the session already sat idle past the
// limit; the caller decides with lockIfIdle()) | 'locked' (nothing to refresh)
export function touch() {
  const gen = epoch;
  if (!rawKey) return Promise.resolve('locked');
  return exclusive(async () => {
    if (epoch !== gen) return 'locked';
    const [last, key] = await Promise.all([store.getLastActive(), store.getSessionKey()]);
    if (epoch !== gen || !key) return 'locked';
    if (isStale(last)) return 'idle';
    await store.touch();
    return 'touched';
  });
}

// Locks when the shared activity time is past the limit, decided under the vault lock: activity
// another page recorded (or an unlock it finished) while this call waited keeps the session,
// and so does a lock or unlock in this page since the call. A missing stored key has no
// activity time either, so this page drops its own. → true when this call locked this page
export function lockIfIdle() {
  const gen = epoch;
  const key = rawKey;
  if (!key) return Promise.resolve(false);
  return exclusive(async () => {
    const live = () => epoch === gen && rawKey === key;
    if (!live()) return false;
    const [last, stored] = await Promise.all([store.getLastActive(), store.getSessionKey()]);
    if (!live() || !isStale(last)) return false;
    forget();
    if (stored) await store.clearSessionKey();
    return true;
  });
}

// Decrypts another vault record (an imported backup) with its own passphrase. → its raw
// account entries; addAccounts() validates them. Throws SessionError('locked') when this page
// is locked or locked meanwhile: decrypted entries are never handed out after a lock.
export async function readBackup(record, passphrase) {
  const gen = epoch;
  if (!rawKey) throw new SessionError('locked');
  const opened = await vault.unlock(record, passphrase);
  if (epoch !== gen || !rawKey) throw new SessionError('locked');
  const list = opened.data && typeof opened.data === 'object' ? opened.data.accounts : undefined;
  if (!Array.isArray(list)) throw new SessionError('not-backup');
  return list;
}

// Adds entries (otpauth.parse() results or backup entries), each validated with
// otpauth.normalize. Invalid entries and duplicates (of a stored or an earlier entry) are
// skipped and counted. → { added, duplicates, invalid }
export function addAccounts(incoming) {
  const entries = Array.isArray(incoming) ? incoming : [];
  return mutate((current) => {
    // A malformed stored entry (only a hand-made vault could hold one) stays stored and never
    // blocks adding: non-objects and arrays are left out, and duplicateKey() never throws.
    const stored = current.accounts.filter(isEntry);
    const seenKeys = new Set(stored.map((a) => duplicateKey(a)));
    const seenIds = new Set(stored.map((a) => a.id));
    let added = 0;
    let duplicates = 0;
    let invalid = 0;
    for (const entry of entries) {
      let account;
      try {
        account = normalize(entry);
      } catch {
        invalid++;
        continue;
      }
      const key = duplicateKey(account);
      if (seenKeys.has(key)) {
        duplicates++;
        continue;
      }
      // normalize() keeps the key fields only; a backup entry's id and creation time carry over.
      const id = typeof entry.id === 'string' && entry.id && !seenIds.has(entry.id)
        ? entry.id
        : crypto.randomUUID();
      current.accounts.push({
        id,
        ...account,
        createdAt: Number.isFinite(entry.createdAt) ? entry.createdAt : Date.now(),
      });
      seenKeys.add(key);
      seenIds.add(id);
      added++;
    }
    return { added, duplicates, invalid };
  });
}

export function deleteAccount(id) {
  return mutate((current) => {
    if (typeof id !== 'string' || id === '') return false;
    const before = current.accounts.length;
    current.accounts = current.accounts.filter((a) => !(isEntry(a) && a.id === id));
    return before !== current.accounts.length;
  });
}

// One read → change → seal → save against the freshest stored record, under the vault lock.
// Throws SessionError('locked') when this page locked at any point, or when another page
// locked first (its notification then locks this page); if this page locked while the save
// was in flight, the change is stored but nothing is published here.
function mutate(change) {
  const gen = epoch;
  const key = rawKey;
  if (!key) return Promise.reject(new SessionError('locked'));
  return exclusive(async () => {
    const check = () => {
      if (epoch !== gen || rawKey !== key) throw new SessionError('locked');
    };
    check();
    const [record, stored] = await Promise.all([store.getRecord(), store.getSessionKey()]);
    check();
    if (!stored || !sameBytes(stored, key)) throw new SessionError('locked');
    if (!record) throw new SessionError('no-vault');
    // While the stored record is the one this page shows, the ids it showed carry over.
    const current = loaded(record, await vault.open(key, record));
    check();
    const result = change(current);
    const sealed = await vault.seal(key, record, current);
    check();
    await store.saveRecord(sealed);
    check();
    remember(key, sealed, current);
    return result;
  });
}

function remember(key, record, current) {
  rawKey = key;
  data = current;
  recordCt = record.ct ?? null;
}

// The decrypted data of `record`, ready to show: normalizeData(), then withIds(). When `record`
// is the one this page already holds, the ids this page gave its entries are given again, so an
// id this page showed still finds its entry in a later read → change → seal.
function loaded(record, value) {
  const current = normalizeData(value);
  const previous = data !== null && record.ct === recordCt ? data.accounts : [];
  return withIds(current, previous);
}

// The decrypted data as stored. Entries are kept as they are (withIds() may add an id): one
// that is not a valid account still shows (as "Invalid key") and survives every later seal.
// Only a missing list is filled in; anything else that is not { accounts: [...] } is refused,
// never overwritten.
function normalizeData(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new SessionError('bad-data');
  if (value.accounts === undefined) return { ...value, accounts: [] };
  if (!Array.isArray(value.accounts)) throw new SessionError('bad-data');
  return value;
}

// Gives each entry whose id is not a non-empty string, or repeats an earlier entry's id, a new
// one: the id at the same place in `previous` (this page's read of the same record) if no
// earlier entry has it, else crypto.randomUUID(). Only a hand-edited vault needs this, since
// the app writes every entry with crypto.randomUUID(). The id lives in memory until the next
// seal stores it; nothing else in an entry changes, and an entry that is not an object, or is an
// array, is left alone (JSON would drop an id on an array, so it could never be stored).
function withIds(current, previous) {
  const seen = new Set();
  const usable = (id) => typeof id === 'string' && id !== '' && !seen.has(id);
  current.accounts.forEach((entry, i) => {
    if (!isEntry(entry)) return;
    if (!usable(entry.id)) {
      const before = previous[i]?.id;
      entry.id = usable(before) ? before : crypto.randomUUID();
    }
    seen.add(entry.id);
  });
  return current;
}

// → true for a stored entry that can be an account: an object that is not an array.
function isEntry(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isStale(lastActiveAt, now = Date.now()) {
  return lastActiveAt === null || now - lastActiveAt >= IDLE_LOCK_MS || lastActiveAt - now > CLOCK_SLACK_MS;
}

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// vault.unlock rejects a wrong passphrase with VaultError('bad-passphrase').
export function isBadPassphrase(error) {
  return Boolean(error) && error.code === 'bad-passphrase';
}

export class SessionError extends Error {
  constructor(code) {
    super(code);
    this.name = 'SessionError';
    this.code = code;
  }
}
