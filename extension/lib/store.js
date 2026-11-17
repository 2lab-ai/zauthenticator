// chrome.storage glue. Six keys exist:
//   chrome.storage.local.vault             the encrypted vault record (ciphertext + KDF params)
//   chrome.storage.session.vaultKey        { key: base64, v, id? }
//   chrome.storage.session.lockGen         random generation replaced by every lock
//   chrome.storage.session.lastActiveAt    last user activity while unlocked (ms since the epoch)
//   chrome.storage.session.pendingBind     { origin, accountId, at }: the auto-fill offer the
//                                          service worker makes after a menu fill (lib/bindings.js)
//   chrome.storage.session.autofillServed  [{ tab, origin, account, counter, at }]: which code
//                                          counter of which account the service worker gave the
//                                          auto-fill script in each tab and origin in the last
//                                          5 minutes (lib/autofill-worker.js); never a code
// Session storage lives in memory only, is cleared when the browser session ends, and is readable
// from trusted extension contexts only (never from content scripts; pinSessionAccess()). The key
// and its activity time are written together, and an offer and the auto-fill record are written
// only while a key is stored (checked under the vault lock). clearSessionKey() first writes a new
// lockGen with vaultKey set to null, then removes vaultKey and the other three, so none of those
// four outlives a lock. lockGen does outlive a lock, by design: it holds no secret, only random
// bytes that let a passkey ceremony see that a lock happened while it ran. It is absent after a
// browser start until the first lock. If writing the new lockGen fails, the removal takes lockGen
// too, so a ceremony captured with a lockGen no longer matches.

export const RECORD_KEY = 'vault';
export const SESSION_KEY = 'vaultKey';
export const ACTIVE_KEY = 'lastActiveAt';
export const PENDING_KEY = 'pendingBind';
export const SERVED_KEY = 'autofillServed';
export const LOCK_GEN_KEY = 'lockGen';

export async function getRecord() {
  const items = await chrome.storage.local.get(RECORD_KEY);
  return items[RECORD_KEY] ?? null;
}

export async function saveRecord(record) {
  if (!record || typeof record !== 'object') throw new TypeError('saveRecord: record must be an object');
  await chrome.storage.local.set({ [RECORD_KEY]: record });
}

export async function getSessionKey() {
  const items = await chrome.storage.session.get(SESSION_KEY);
  const value = items[SESSION_KEY];
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.key !== 'string') return null;
  if (value.v !== 1 && value.v !== 2) return null;
  if (Object.keys(value).some((k) => !['key', 'v', ...(value.v === 2 ? ['id'] : [])].includes(k))) return null;
  if (value.v === 1 && value.id !== undefined) return null;
  if (value.v === 2 && typeof value.id !== 'string') return null;
  try {
    const key = bytesFromBase64(value.key);
    if (key.length !== 32 || base64FromBytes(key) !== value.key) return null;
    if (value.v === 2 && (bytesFromBase64(value.id).length !== 16 || base64FromBytes(bytesFromBase64(value.id)) !== value.id)) return null;
    return value.v === 1 ? { key, v: 1 } : { key, v: 2, id: value.id };
  } catch {
    return null;
  }
}

// Unlocking counts as activity: the key and its activity time go out in one write.
export async function setSessionKey(bytes, identity, activeAt = Date.now()) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32 || !identity ||
      (identity.v !== 1 && identity.v !== 2) ||
      (identity.v === 1 && identity.id !== undefined) ||
      (identity.v === 2 && typeof identity.id !== 'string')) {
    throw new TypeError('setSessionKey: expected a key and identity');
  }
  const value = identity.v === 1 ? { key: base64FromBytes(bytes), v: 1 } : { key: base64FromBytes(bytes), v: 2, id: identity.id };
  await chrome.storage.session.set({ [SESSION_KEY]: value, [ACTIVE_KEY]: activeAt });
}

// Keeps session storage readable from trusted extension contexts only (pages and the service
// worker, never a content script). That is the browser's default; the service worker sets it once
// when it loads so the raw key's safety never rests on the default. A browser without
// setAccessLevel already has only that level. Never throws.
export async function pinSessionAccess() {
  try {
    await chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
  } catch {
    // not available: the default (trusted contexts only) holds
  }
}

// Every lock goes through here: the key, its activity time, any pending offer and the auto-fill
// record go together.
export async function clearSessionKey() {
  // Attempt both operations even if either fails; never report a successful lock on failure.
  let failure;
  try {
    await chrome.storage.session.set({ [LOCK_GEN_KEY]: base64FromBytes(crypto.getRandomValues(new Uint8Array(16))), [SESSION_KEY]: null });
  } catch (error) {
    failure = error;
  }
  try {
    // A failed generation write must not let an older capture match.
    await chrome.storage.session.remove([SESSION_KEY, ACTIVE_KEY, PENDING_KEY, SERVED_KEY, ...(failure ? [LOCK_GEN_KEY] : [])]);
  } catch (error) {
    failure ??= error;
  }
  if (failure) throw failure;
}

export async function getLockGen() {
  const items = await chrome.storage.session.get(LOCK_GEN_KEY);
  const value = items[LOCK_GEN_KEY];
  if (value === undefined) return null;
  try {
    if (typeof value === 'string' && bytesFromBase64(value).length === 16 && base64FromBytes(bytesFromBase64(value)) === value) return value;
  } catch { /* malformed generation fails closed */ }
  throw new TypeError('invalid lock generation');
}

// → ms timestamp of the last recorded activity, or null when none is stored.
export async function getLastActive() {
  const items = await chrome.storage.session.get(ACTIVE_KEY);
  const value = items[ACTIVE_KEY];
  return Number.isFinite(value) ? value : null;
}

export async function touch(now = Date.now()) {
  await chrome.storage.session.set({ [ACTIVE_KEY]: now });
}

// Stores the auto-fill offer { origin, accountId } with its time. Writes whatever it is given
// (strings only); popup/session.js validates the origin and that a key is stored.
export async function setPendingBind({ origin, accountId } = {}, at = Date.now()) {
  if (typeof origin !== 'string' || origin === '' || typeof accountId !== 'string' || accountId === '') {
    throw new TypeError('setPendingBind: origin and accountId must be non-empty strings');
  }
  if (!Number.isFinite(at)) throw new TypeError('setPendingBind: at must be a finite number');
  await chrome.storage.session.set({ [PENDING_KEY]: { origin, accountId, at } });
}

// → { origin, accountId, at } as stored, or null when none (or something malformed) is stored.
export async function getPendingBind() {
  const items = await chrome.storage.session.get(PENDING_KEY);
  const value = items[PENDING_KEY];
  if (!value || typeof value !== 'object') return null;
  const { origin, accountId, at } = value;
  if (typeof origin !== 'string' || origin === '' || typeof accountId !== 'string' || accountId === '') return null;
  if (!Number.isFinite(at)) return null;
  return { origin, accountId, at };
}

export async function clearPendingBind() {
  await chrome.storage.session.remove(PENDING_KEY);
}

// → the auto-fill record: its well-formed entries { tab, origin, account, counter, at } (tab an
// integer, origin and account non-empty strings, counter a non-negative integer, at finite), []
// when none is stored.
export async function getServed() {
  const items = await chrome.storage.session.get(SERVED_KEY);
  const list = items[SERVED_KEY];
  if (!Array.isArray(list)) return [];
  return list.filter(
    (e) =>
      e !== null &&
      typeof e === 'object' &&
      Number.isInteger(e.tab) &&
      typeof e.origin === 'string' &&
      e.origin !== '' &&
      typeof e.account === 'string' &&
      e.account !== '' &&
      Number.isSafeInteger(e.counter) &&
      e.counter >= 0 &&
      Number.isFinite(e.at),
  ).map(({ tab, origin, account, counter, at }) => ({ tab, origin, account, counter, at }));
}

// Replaces the auto-fill record. lib/autofill-worker.js writes it under the vault lock while a key
// is stored, so a lock removes it like the other session keys.
export async function setServed(list) {
  if (!Array.isArray(list)) throw new TypeError('setServed: expected an array');
  await chrome.storage.session.set({ [SERVED_KEY]: list });
}

// Calls back with { record?, locked? } when another extension page (popup or tab) changes
// the vault record or locks the session. Returns an unsubscribe function.
export function watch(callback) {
  const listener = (changes, areaName) => {
    if (areaName === 'local' && RECORD_KEY in changes) {
      callback({ record: changes[RECORD_KEY].newValue ?? null });
    }
    if (areaName === 'session' && SESSION_KEY in changes) {
      callback({ locked: !changes[SESSION_KEY].newValue });
    }
  };
  chrome.storage.onChanged.addListener(listener);
  return () => chrome.storage.onChanged.removeListener(listener);
}

function base64FromBytes(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function bytesFromBase64(text) {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
