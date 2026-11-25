// The device key: what opens the vault once its owner removed the passphrase. An AES-GCM-256 key
// made with WebCrypto as non-extractable, so page code (this extension's included) can encrypt and
// decrypt with it but can never read its bytes, and kept by this browser in this extension's
// IndexedDB, in this profile on this computer. It never leaves it: backups and exports never
// carry it, and another browser or computer cannot open a record wrapped by it.
//
// Why not a disk serial or a computer fingerprint: an extension page cannot read a disk serial
// without a native helper (more permissions and native code, which this project refuses), and a
// fingerprint made of what a page can see (screen, GPU, fonts, versions) changes with a driver
// update or a new monitor, after which the vault would never open again.
//
// What protects it is the profile: anyone who can use this browser profile, or copy it whole, can
// use the key. The record in chrome.storage.local alone does not open without it.

const DB_NAME = 'zauthenticator-device';
const STORE = 'keys';

function request(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB request failed'));
  });
}

function openDb() {
  if (typeof indexedDB === 'undefined') return Promise.reject(new Error('IndexedDB is not available'));
  const req = indexedDB.open(DB_NAME, 1);
  req.onupgradeneeded = () => {
    if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
  };
  return request(req);
}

// Runs fn(store) in one transaction and resolves with its request's result once the transaction
// has committed (so a key reported as saved is on disk as far as IndexedDB is concerned).
async function inStore(mode, fn) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      let result;
      const req = fn(tx.objectStore(STORE));
      req.onsuccess = () => { result = req.result; };
      tx.oncomplete = () => resolve(result);
      tx.onerror = () => reject(tx.error ?? new Error('IndexedDB transaction failed'));
      tx.onabort = () => reject(tx.error ?? new Error('IndexedDB transaction aborted'));
    });
  } finally {
    db.close();
  }
}

function newId() {
  let binary = '';
  for (const byte of crypto.getRandomValues(new Uint8Array(16))) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Makes and stores a new device key. → { id, key } (key: a non-extractable CryptoKey) */
export async function createDeviceKey() {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const id = newId();
  await inStore('readwrite', (store) => store.put(key, id));
  return { id, key };
}

/** → the stored device key named id, or null when there is none. */
export async function getDeviceKey(id) {
  const key = await inStore('readonly', (store) => store.get(id));
  return key && typeof key === 'object' && key.type === 'secret' ? key : null;
}

/** Deletes every stored device key except the one named keep (none kept when keep is null). */
export async function deleteDeviceKeys(keep = null) {
  const ids = await inStore('readonly', (store) => store.getAllKeys());
  for (const id of ids ?? []) {
    if (id !== keep) await inStore('readwrite', (store) => store.delete(id));
  }
}

/** Deletes the stored device key named id (nothing when there is none). */
export async function deleteDeviceKey(id) {
  await inStore('readwrite', (store) => store.delete(id));
}
