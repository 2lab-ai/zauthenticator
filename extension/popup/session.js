// The unlocked vault as seen by this page: the raw key and the decrypted data live in memory
// only; storage holds the sealed record (local) and the raw key (session, see lib/store.js).
//
// Every read-modify-write of stored vault state runs under one Web Lock. All extension pages
// of this origin share it (the popup and a full tab), so two pages never interleave
// read → change → seal → save, and a lock never lands between an unlock's checks and its
// session-key write. Locking bumps a generation counter at once, before waiting for that
// Web Lock; async work captures the generation and key when it starts and publishes its
// result (the in-memory key and data, the session key) only if neither changed meanwhile.
//
// The service worker imports this module too, so it imports nothing that needs a document or
// a window. The worker never unlocks its instance: it reads with readUnlocked() and
// withVaultState(), which go to storage every time, and writes only the auto-fill offer
// (setPendingBind()).
import * as vault from '../lib/vault.js';
import * as store from '../lib/store.js';
import { normalize } from '../lib/otpauth.js';
import { bindingsOf, normalizeOrigin, withBinding, withoutAccountBindings, withoutBinding } from '../lib/bindings.js';
import { duplicateKey } from './format.js';

const LOCK_NAME = 'zauthenticator-vault';

// Locks after this long without user activity in any extension page (fixed in v0.1). Opening or
// using a page is activity, so it always leaves at least this long.
export const IDLE_LOCK_MS = 15 * 60 * 1000;
// The lengths a manual extension may have (the list view's Extend): 1 hour, 24 hours, 7 days from
// the moment it is chosen. The vault then locks at the later of that end and the idle limit.
export const EXTEND_CHOICES_MS = Object.freeze([60 * 60 * 1000, 24 * 60 * 60 * 1000, 7 * 24 * 60 * 60 * 1000]);
const MAX_EXTEND_MS = EXTEND_CHOICES_MS[EXTEND_CHOICES_MS.length - 1];
// An activity time this far in the future means the clock was set back: treat it as idle.
const CLOCK_SLACK_MS = 60 * 1000;
// The auto-fill offer a menu fill leaves for the bind window is good for this long.
export const PENDING_BIND_MS = 2 * 60 * 1000;

let rawKey = null;   // Uint8Array while unlocked
let data = null;     // { accounts: [...], bindings?: [...] } as stored plus the ids withIds() gives, while unlocked
let recordCt = null; // ciphertext of the record `data` was read from or sealed into
let recordRev = null;
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

// The auto-fill bindings, for display: [{ origin, accountId, createdAt }] (lib/bindings.js
// bindingsOf()); empty while locked.
export function bindings() {
  if (rawKey === null || data === null) return [];
  return bindingsOf(data);
}

// → 'setup' | 'locked' | 'list'. Locks first when the session sat idle too long.
// Runs while this page holds no key (startup, or re-checking a locked page), so finding the
// vault locked must not bump the generation: that would cancel an unlock queued behind it.
export function resume() {
  let gen = epoch;
  return exclusive(async () => {
    const record = await store.getRecord();
    if (!record) {
      drop();
      return 'setup';
    }
    const session = await checkedSession(record);
    if (!session) {
      drop();
      return 'locked';
    }
    const key = session.key;
    // Another page replaced the key (a v1 → v2 migration): in-flight work with the old one ends
    // here, and this page reads with the stored key below.
    if (epoch === gen && rawKey !== null && !sameBytes(rawKey, key)) {
      forget();
      gen = epoch;
    }
    if (isStale(await readActivity())) {
      drop();
      await store.clearSessionKey();
      return 'locked';
    }
    let current;
    try {
      current = loaded(await vault.open(key, record));
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
    await store.setSessionKey(key, vault.identity(record));
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
    const current = loaded(opened.data);
    if (epoch !== gen) throw new SessionError('locked');
    await store.setSessionKey(opened.rawKey, vault.identity(record));
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
  recordRev = null;
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
    const stored = await checkedSession(record);
    if (!live()) return 'stale';
    if (!stored || !sameBytes(stored.key, key)) {
      forget();
      return 'locked';
    }
    if (ciphertext(record) === recordCt && JSON.stringify(record) === recordRev) return 'unchanged';
    let current;
    try {
      current = loaded(await vault.open(key, record));
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
  const key = rawKey;
  if (!key) return Promise.resolve('locked');
  return exclusive(async () => {
    if (epoch !== gen) return 'locked';
    const [activity, record] = await Promise.all([readActivity(), store.getRecord()]);
    const stored = await checkedSession(record);
    if (epoch !== gen || rawKey !== key) return 'locked';
    if (!stored || !sameBytes(stored.key, key)) {
      forget();
      return 'locked';
    }
    if (isStale(activity)) return 'idle';
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
    const [activity, record] = await Promise.all([readActivity(), store.getRecord()]);
    const stored = await checkedSession(record);
    if (!live()) return false;
    if (!stored || !sameBytes(stored.key, key)) {
      forget();
      return true;
    }
    if (!isStale(activity)) return false;
    forget();
    await store.clearSessionKey();
    return true;
  });
}

// The vault data, read from storage under the vault lock, or null while locked. This is the
// service worker's read path (with withVaultState()), and it publishes nothing into this instance
// (no key, no data): every call reads the stored record, key and activity time again, so a lock
// in any page is seen by the next call. Like resume(), an idle session and a key that does not
// open the record are locked here: every session key is removed (the pending offer too), and this
// page, if it holds a key, drops it. accounts are what accounts() would show (an entry that is not
// an object, or is an array, is left out; nothing seals this result), with the ids withIds() gives
// them, the same in every page and every read of the same record. touch: true records activity (a
// menu fill); auto-fill reads without. A lock in this page while the call waits or reads makes it
// return null.
export function readUnlocked({ touch: active = false } = {}) {
  const gen = epoch;
  return exclusive(async () => {
    const { data: current } = await openStored(gen);
    if (!current || epoch !== gen) return null;
    if (active) {
      await store.touch();
      if (epoch !== gen) return null;
    }
    return current;
  });
}

// Reads the stored record, session key, activity time and auto-fill offer and calls
// fn({ data, pending }) while still holding the vault lock, so nothing another page stores (a
// binding, a cleared offer) lands between this read and what fn does with it. data is what
// readUnlocked() returns, null while locked or idle (and an idle session, or a key that does not
// open the record, is locked here as readUnlocked() locks it, which removes the offer too);
// pending is the stored offer { origin, accountId, at } at any age, or null. fn must not call
// anything in this module: the lock is held. → what fn returns
export function withVaultState(fn) {
  const gen = epoch;
  return exclusive(async () => {
    const state = await openStored(gen);
    return fn(epoch === gen ? state : { data: null, pending: state.pending });
  });
}

// The vault-lock body of readUnlocked() and withVaultState(); call only while holding the lock.
// → { data: vault data | null, pending: offer | null }
async function openStored(gen) {
  if (epoch !== gen) return { data: null, pending: null };
  const [record, activity, pending] = await Promise.all([
    store.getRecord(),
    readActivity(),
    store.getPendingBind(),
  ]);
  const session = await checkedSession(record);
  if (epoch !== gen) return { data: null, pending: null };
  if (!record || !session) {
    // Only reached when the stored key is missing, malformed or not this record's: locked.
    drop();
    return { data: null, pending: await store.getPendingBind() };
  }
  const key = session.key;
  if (isStale(activity)) {
    drop();
    await store.clearSessionKey();
    return { data: null, pending: null };
  }
  let current;
  try {
    current = loaded(await vault.open(key, record));
  } catch {
    drop();
    await store.clearSessionKey();
    return { data: null, pending: null };
  }
  return { data: { ...current, accounts: current.accounts.filter(isEntry) }, pending };
}

// Leaves the auto-fill offer { origin, accountId } for the bind window, after a menu fill on
// origin (exactly as normalizeOrigin() gives it). Written under the vault lock and only while a
// session key is stored and not idle, so an offer never exists without the key: every lock
// removes both. → true when stored; false (nothing written) for a bad origin or account id, a
// locked or idle session, or a lock in this page meanwhile.
export function setPendingBind(offer) {
  const { origin, accountId } = offer ?? {};
  if (!isOrigin(origin) || !isId(accountId)) return Promise.resolve(false);
  const gen = epoch;
  return exclusive(async () => {
    if (epoch !== gen) return false;
    const [record, activity] = await Promise.all([store.getRecord(), readActivity()]);
    const key = await checkedSession(record);
    if (epoch !== gen || !key || isStale(activity)) return false;
    await store.setPendingBind({ origin, accountId });
    return true;
  });
}

// → the stored offer { origin, accountId, at } while it is younger than maxAgeMs, else null. It
// stays stored (the bind window may read it again) until clearPendingBind() or a lock. An expired
// offer, or one dated in the future past the clock slack (the clock was set back), is removed.
export function takePendingBind(maxAgeMs = PENDING_BIND_MS) {
  const limit = Number.isFinite(maxAgeMs) && maxAgeMs >= 0 ? maxAgeMs : PENDING_BIND_MS;
  return exclusive(async () => {
    const offer = await store.getPendingBind();
    if (!offer) return null;
    const age = Date.now() - offer.at;
    if (age < limit && -age <= CLOCK_SLACK_MS) return offer;
    await store.clearPendingBind();
    return null;
  });
}

// Removes the stored offer. With expected ({ origin, accountId, at }, the offer a bind window
// shows), only when the stored offer is exactly that one: a newer menu fill's offer stays.
// → true when an offer was removed (without expected: always true)
export function clearPendingBind(expected) {
  return exclusive(async () => {
    if (expected !== undefined) {
      const offer = await store.getPendingBind();
      if (!offer || !sameOffer(offer, expected)) return false;
    }
    await store.clearPendingBind();
    return true;
  });
}

function sameOffer(offer, expected) {
  return Boolean(expected) && typeof expected === 'object' &&
    offer.origin === expected.origin && offer.accountId === expected.accountId && offer.at === expected.at;
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

// Removes the entry and, in the same seal, every binding to its id. → true when an entry went
export function deleteAccount(id) {
  return mutate((current) => {
    if (typeof id !== 'string' || id === '') return false;
    const before = current.accounts.length;
    current.accounts = current.accounts.filter((a) => !(isEntry(a) && a.id === id));
    adoptBindings(current, withoutAccountBindings(current, id));
    return before !== current.accounts.length;
  });
}

// Binds origin to the entry with id accountId, replacing origin's earlier binding, in one
// read → change → seal → save. origin must be exactly what normalizeOrigin() returns for it (the
// origin the worker put in the offer): anything else is SessionError('bad-origin'), and an id no
// stored entry has is SessionError('no-account'); either way nothing is stored.
// → the stored binding { origin, accountId, createdAt }
export function addBinding(origin, accountId) {
  if (!isOrigin(origin)) return Promise.reject(new SessionError('bad-origin'));
  return mutate((current) => {
    if (!isId(accountId) || !current.accounts.some((a) => isEntry(a) && a.id === accountId)) {
      throw new SessionError('no-account');
    }
    const createdAt = Date.now();
    adoptBindings(current, withBinding(current, origin, accountId, createdAt));
    return { origin, accountId, createdAt };
  });
}

// Removes the binding of origin (any URL of that origin). → true when there was one
export function removeBinding(origin) {
  return mutate((current) => {
    const key = normalizeOrigin(origin);
    const found = key !== null && bindingsOf(current).some((b) => b.origin === key);
    adoptBindings(current, withoutBinding(current, origin));
    return found;
  });
}

// mutate() seals the object it hands to its change: a lib/bindings.js result (new data) is
// copied back into it. A result without a bindings key (none was stored) adds none.
function adoptBindings(current, next) {
  if (Object.hasOwn(next, 'bindings')) current.bindings = next.bindings;
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
    const record = await store.getRecord();
    const stored = await checkedSession(record);
    check();
    if (!stored || !sameBytes(stored.key, key)) throw new SessionError('locked');
    if (!record) throw new SessionError('no-vault');
    // withIds() gives the same ids this page showed for the same record.
    const current = loaded(await vault.open(key, record));
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

function ciphertext(record) {
  return record.v === 2 ? record.data.ct : record.ct;
}

function sameIdentity(a, b) {
  return Boolean(a && b && a.v === b.v && a.id === b.id);
}

// Call only under the vault lock. A malformed or legacy key, or one whose { v, id } does not
// belong to the stored record, is cleared like a lock; callers decide what this page forgets.
async function checkedSession(record) {
  const stored = await store.getSessionKey();
  if (!stored) {
    const item = await chrome.storage.session.get(store.SESSION_KEY);
    if (item[store.SESSION_KEY] !== undefined) await store.clearSessionKey();
    return null;
  }
  let matches = false;
  try { matches = Boolean(record) && sameIdentity(stored, vault.identity(record)); } catch { /* malformed record */ }
  if (!matches) {
    await store.clearSessionKey();
    return null;
  }
  return stored;
}

// The unlock time of the stored session, for display: { lockAt, until } in ms (until is null
// without a manual extension), or null while this page is locked, its key is no longer the stored
// one, or the session is already past its lock time. Read under the vault lock.
export function unlockState() {
  const gen = epoch;
  const key = rawKey;
  if (!key) return Promise.resolve(null);
  return exclusive(async () => {
    const [activity, record] = await Promise.all([readActivity(), store.getRecord()]);
    const stored = await checkedSession(record);
    if (epoch !== gen || rawKey !== key || !stored || !sameBytes(stored.key, key) || isStale(activity)) return null;
    return { lockAt: lockTime(activity), until: activity.until };
  });
}

// Keeps the vault unlocked for ms from now (one of EXTEND_CHOICES_MS; the caller has the user
// confirm it), or with 0 drops a manual extension (back to the idle limit after the last use).
// Choosing is activity. Under the vault lock, only while this page holds the stored key and the
// session has not passed its lock time; a lock in this page meanwhile throws, and the lock queued
// behind this call removes what was written. → the new unlockState() value
export function extendUnlock(ms) {
  if (ms !== 0 && !EXTEND_CHOICES_MS.includes(ms)) return Promise.reject(new TypeError('extendUnlock: unsupported length'));
  const gen = epoch;
  const key = rawKey;
  if (!key) return Promise.reject(new SessionError('locked'));
  return exclusive(async () => {
    const [activity, record] = await Promise.all([readActivity(), store.getRecord()]);
    const stored = await checkedSession(record);
    if (epoch !== gen || rawKey !== key || !stored || !sameBytes(stored.key, key) || isStale(activity)) {
      throw new SessionError('locked');
    }
    const now = Date.now();
    const until = ms === 0 ? null : now + ms;
    await store.setUnlockedUntil(until, now);
    if (epoch !== gen || rawKey !== key) throw new SessionError('locked');
    return { lockAt: lockTime({ last: now, until }), until };
  });
}

const captures = new WeakMap();

export function passkeyState() {
  return exclusive(async () => {
    const record = await store.getRecord();
    return { slot: record ? vault.passkeySlot(record) : null };
  });
}

export function captureForCeremony() {
  const gen = epoch;
  return exclusive(async () => {
    const record = await store.getRecord();
    if (!record) throw new SessionError('no-vault');
    const identity = vault.identity(record);
    const stored = await checkedSession(record);
    // Never null (store.ensureLockGen()); when it cannot be written no capture is issued.
    const capture = { rev: await vault.revision(record), lockGen: await store.ensureLockGen(), identity, slot: vault.passkeySlot(record) };
    captures.set(capture, { gen, key: rawKey, rev: capture.rev, lockGen: capture.lockGen, identity: { ...identity }, session: stored && !isStale(await readActivity()) && rawKey && sameBytes(stored.key, rawKey) });
    return capture;
  });
}

async function ceremonyRecord(capture, enroll) {
  const initial = captures.get(capture);
  if (!initial || typeof initial.lockGen !== 'string' || initial.gen !== epoch ||
      (enroll && (!initial.session || rawKey !== initial.key))) {
    throw new SessionError('changed');
  }
  const record = await store.getRecord();
  if (!record || await vault.revision(record) !== initial.rev || await store.getLockGen() !== initial.lockGen ||
      !sameIdentity(vault.identity(record), initial.identity) || initial.gen !== epoch) throw new SessionError('changed');
  if (enroll) {
    const stored = await checkedSession(record);
    if (!stored || !sameBytes(stored.key, initial.key) || isStale(await readActivity()) || rawKey !== initial.key || initial.gen !== epoch) {
      throw new SessionError('changed');
    }
  }
  return record;
}

export function checkPassphrase(passphrase) {
  const gen = epoch;
  const key = rawKey;
  if (!key) return Promise.reject(new SessionError('locked'));
  return exclusive(async () => {
    const record = await store.getRecord();
    const stored = await checkedSession(record);
    if (!stored || !sameBytes(stored.key, key) || isStale(await readActivity()) || epoch !== gen || rawKey !== key) throw new SessionError('locked');
    await vault.unlock(record, passphrase);
    if (epoch !== gen || rawKey !== key) throw new SessionError('locked');
    return true;
  });
}

export function enrollPasskey(capture, passphrase, options) {
  return exclusive(async () => {
    const record = await ceremonyRecord(capture, true);
    const result = await vault.addPasskeySlot(record, passphrase, options);
    const current = loaded(await vault.open(result.rawKey, result.record));
    // The last check before anything is written: 'changed' always means nothing was stored.
    await ceremonyRecord(capture, true);
    const { gen } = captures.get(capture);
    await store.saveRecord(result.record);
    // The slot is stored from here on, so nothing below rejects. A lock of this page meanwhile ends
    // it locked: no session key is written, or the one just written goes with the lock queued
    // behind this call.
    if (gen !== epoch) return { saved: true, locked: true };
    try {
      await store.setSessionKey(result.rawKey, vault.identity(result.record));
    } catch {
      // locked: true means this page dropped its key and a lock of the shared session was
      // attempted. If that lock also fails, the shared session is left no more open than before
      // the enrollment: unchanged when nothing could be written, or already cleared when the lock
      // got partway; after a v1 → v2 migration an unchanged key no longer matches the record and
      // every reader treats it as locked; after a v2 enrollment (same DEK, same id) it still opens
      // the vault, as it did before.
      if (gen === epoch) forget();
      try { await store.clearSessionKey(); } catch { /* no more open than before; see above */ }
      return { saved: true, locked: true };
    }
    if (gen !== epoch) return { saved: true, locked: true };
    remember(result.rawKey, result.record, current);
    return { saved: true, locked: false };
  });
}

export function unlockWithPasskey(capture, prf) {
  return exclusive(async () => {
    const record = await ceremonyRecord(capture, false);
    const opened = await vault.unlockWithPasskey(record, prf);
    await ceremonyRecord(capture, false);
    await store.setSessionKey(opened.rawKey, vault.identity(record));
    if (captures.get(capture).gen !== epoch) throw new SessionError('changed');
    remember(opened.rawKey, record, loaded(opened.data));
  });
}

export function removePasskey(cred) {
  const gen = epoch;
  const key = rawKey;
  if (!key) return Promise.reject(new SessionError('locked'));
  return exclusive(async () => {
    const record = await store.getRecord();
    const stored = await checkedSession(record);
    if (!stored || !sameBytes(stored.key, key) || isStale(await readActivity()) || gen !== epoch || rawKey !== key) throw new SessionError('locked');
    const next = vault.removePasskeySlot(record, cred);
    const current = loaded(await vault.open(key, next));
    if (gen !== epoch || rawKey !== key) throw new SessionError('locked');
    await store.saveRecord(next);
    if (gen !== epoch || rawKey !== key) throw new SessionError('locked');
    remember(key, next, current);
  });
}

export function exportRecord() {
  return exclusive(async () => {
    const record = await store.getRecord();
    return record ? vault.exportCopy(record) : null;
  });
}

function remember(key, record, current) {
  rawKey = key;
  data = current;
  recordCt = ciphertext(record);
  recordRev = JSON.stringify(record);
}

// The decrypted data of a record, ready to show: normalizeData(), then withIds().
function loaded(value) {
  return withIds(normalizeData(value));
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

// The fields of an entry a repaired id is made from: what the menu shows and the code parameters.
const ID_FIELDS = ['issuer', 'label', 'algorithm', 'digits', 'period', 'createdAt'];

// Gives each entry whose id is not a non-empty string, or repeats an earlier entry's id, a new
// one. Only a hand-edited vault needs this, since the app writes every entry with
// crypto.randomUUID(). The new id depends on the stored record alone, so every page and the
// service worker give the same one in every read (a menu item or a row found again by its id):
// 'h' + the FNV-1a 64-bit hash (hex) of the JSON, with sorted keys, of the entry's ID_FIELDS, then
// '-' and the count of entries before it with the same hash, skipping any id an entry stores.
// Entries that store a usable id keep it, first come first. The id is no secret and needs no
// crypto; it leaves the encrypted record (menu item ids, the bind offer in session storage), and
// FNV-1a can be run backwards, so the secret and any field the app does not know stay out of it.
// The id lives in memory until the next seal stores it; nothing else in an entry changes, and an
// entry that is not an object, or is an array, is left alone (JSON would drop an id on an array,
// so it could never be stored).
function withIds(current) {
  const taken = new Set();
  const repair = [];
  for (const entry of current.accounts) {
    if (!isEntry(entry)) continue;
    if (typeof entry.id === 'string' && entry.id !== '' && !taken.has(entry.id)) taken.add(entry.id);
    else repair.push(entry);
  }
  for (const entry of repair) {
    const shown = {};
    for (const field of ID_FIELDS) if (Object.hasOwn(entry, field)) shown[field] = entry[field];
    const base = `h${fnv1a64(canonicalJson(shown))}`;
    let n = 0;
    while (taken.has(`${base}-${n}`)) n++;
    entry.id = `${base}-${n}`;
    taken.add(entry.id);
  }
  return current;
}

// JSON with every object's keys in sorted order (decrypted vault data holds JSON values only).
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

const FNV_OFFSET = 0xcbf29ce484222325n;
const FNV_PRIME = 0x100000001b3n;
const MASK_64 = (1n << 64n) - 1n;

// FNV-1a, 64 bits, over the UTF-8 bytes of text. → 16 hex digits
function fnv1a64(text) {
  let hash = FNV_OFFSET;
  for (const byte of new TextEncoder().encode(text)) {
    hash = ((hash ^ BigInt(byte)) * FNV_PRIME) & MASK_64;
  }
  return hash.toString(16).padStart(16, '0');
}

// → true for a stored entry that can be an account: an object that is not an array.
function isEntry(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// → true for a string that is exactly an origin normalizeOrigin() returns.
function isOrigin(value) {
  return typeof value === 'string' && normalizeOrigin(value) === value;
}

function isId(value) {
  return typeof value === 'string' && value !== '';
}

// The stored activity time and manual extension: { last, until } (ms or null). Call under the
// vault lock.
async function readActivity() {
  const [last, until] = await Promise.all([store.getLastActive(), store.getUnlockedUntil()]);
  return { last, until };
}

// When the session locks: the idle limit after the last activity, or a manual extension's end when
// that is later.
function lockTime({ last, until }) {
  const idle = last + IDLE_LOCK_MS;
  return until !== null && until > idle ? until : idle;
}

// → true when the session must lock now: no activity time, the lock time has passed, or the clock
// was set back (an activity time in the future past the slack, or an extension ending further away
// than the longest choice allows).
function isStale(activity, now = Date.now()) {
  const { last, until } = activity;
  if (last === null || last - now > CLOCK_SLACK_MS) return true;
  if (until !== null && until - now > MAX_EXTEND_MS + CLOCK_SLACK_MS) return true;
  return now >= lockTime(activity);
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
