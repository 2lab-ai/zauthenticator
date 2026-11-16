// chrome.storage glue. Exactly two keys exist, and nothing else is ever written:
//   chrome.storage.local.vault       the encrypted vault record (ciphertext + KDF params)
//   chrome.storage.session.vaultKey  the unlocked raw AES key, base64
// Session storage lives in memory only, is cleared when the browser session ends, and by
// default is readable from trusted extension contexts only (never from content scripts).

export const RECORD_KEY = 'vault';
export const SESSION_KEY = 'vaultKey';

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
  if (typeof value !== 'string' || value === '') return null;
  try {
    return bytesFromBase64(value);
  } catch {
    return null;
  }
}

export async function setSessionKey(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    throw new TypeError('setSessionKey: expected a non-empty Uint8Array');
  }
  await chrome.storage.session.set({ [SESSION_KEY]: base64FromBytes(bytes) });
}

export async function clearSessionKey() {
  await chrome.storage.session.remove(SESSION_KEY);
}

// Calls back with { record?, locked? } when another extension page (popup or tab) changes
// the vault record or locks the session. Returns an unsubscribe function.
export function watch(callback) {
  const listener = (changes, areaName) => {
    if (areaName === 'local' && RECORD_KEY in changes) {
      callback({ record: changes[RECORD_KEY].newValue ?? null });
    }
    if (areaName === 'session' && SESSION_KEY in changes && !changes[SESSION_KEY].newValue) {
      callback({ locked: true });
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
