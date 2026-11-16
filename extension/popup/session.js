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
let data = null;     // { accounts: [...] } exactly as stored, while unlocked
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

// The stored entries, for display; empty while locked. A non-object entry (only a hand-made
// vault could hold one) stays stored but is not shown.
export function accounts() {
  if (rawKey === null || data === null) return [];
  return data.accounts.filter((a) => a !== null && typeof a === 'object');
}

// → 'setup' | 'locked' | 'list'. Locks first when the session sat idle too long.
export function resume() {
  const gen = epoch;
  return exclusive(async () => {
    const record = await store.getRecord();
    if (!record) {
      forget();
      return 'setup';
    }
    const key = await store.getSessionKey();
    if (!key) {
      forget();
      return 'locked';
    }
    if (isStale(await store.getLastActive())) {
      forget();
      await store.clearSessionKey();
      return 'locked';
    }
    let current;
    try {
      current = normalizeData(await vault.open(key, record));
    } catch {
      // The session key does not open the stored record; ask for the passphrase again.
      forget();
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
    const current = normalizeData(opened.data);
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
      current = normalizeData(await vault.open(key, record));
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
// limit; the caller locks) | 'locked' (nothing to refresh)
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

// → true when this page is unlocked and the shared activity time is past the limit.
export async function idleExpired() {
  if (!rawKey) return false;
  const last = await store.getLastActive();
  return rawKey !== null && isStale(last);
}

// Decrypts another vault record (an imported backup) with its own passphrase. → its raw
// account entries; addAccounts() validates them.
export async function readBackup(record, passphrase) {
  const opened = await vault.unlock(record, passphrase);
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
    const seenKeys = new Set(current.accounts.map(duplicateKey));
    const seenIds = new Set(current.accounts.map((a) => a?.id));
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
    current.accounts = current.accounts.filter((a) => !(a !== null && typeof a === 'object' && a.id === id));
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
    const current = normalizeData(await vault.open(key, record));
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

// The decrypted data as stored. Entries are kept exactly as they are: one that is not a valid
// account still shows (as "Invalid key") and survives every later seal. Only a missing list
// is filled in; anything else that is not { accounts: [...] } is refused, never overwritten.
function normalizeData(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new SessionError('bad-data');
  if (value.accounts === undefined) return { ...value, accounts: [] };
  if (!Array.isArray(value.accounts)) throw new SessionError('bad-data');
  return value;
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
