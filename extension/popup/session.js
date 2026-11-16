// The unlocked vault as seen by this page: the raw key and the decrypted data live in memory
// only; storage holds the sealed record (local) and the raw key (session, see lib/store.js).
import * as vault from '../lib/vault.js';
import * as store from '../lib/store.js';
import { duplicateKey } from './format.js';

let rawKey = null;   // Uint8Array while unlocked
let data = null;     // { accounts: [...] } while unlocked
let recordCt = null; // ciphertext of the record `data` was read from

export function isUnlocked() {
  return rawKey !== null;
}

export function accounts() {
  return data ? data.accounts : [];
}

// True when `record` is the one this page last read or wrote (ignore our own storage echo).
export function isCurrentRecord(record) {
  return Boolean(record && recordCt !== null && record.ct === recordCt);
}

// → 'setup' | 'locked' | 'list'
export async function resume() {
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
  try {
    const opened = await vault.open(key, record);
    remember(key, record, opened);
    return 'list';
  } catch {
    // The session key does not open the stored record; ask for the passphrase again.
    await store.clearSessionKey();
    forget();
    return 'locked';
  }
}

export async function create(passphrase) {
  if (await store.getRecord()) throw new SessionError('vault-exists');
  const empty = { accounts: [] };
  const { record, rawKey: key } = await vault.create(passphrase, empty);
  await store.saveRecord(record);
  await store.setSessionKey(key);
  remember(key, record, empty);
}

// Throws whatever vault.unlock throws for a wrong passphrase.
export async function unlock(passphrase) {
  const record = await store.getRecord();
  if (!record) throw new SessionError('no-vault');
  const opened = await vault.unlock(record, passphrase);
  await store.setSessionKey(opened.rawKey);
  remember(opened.rawKey, record, opened.data);
}

export async function lock() {
  forget();
  await store.clearSessionKey();
}

// Drop the in-memory key and data without touching storage (another page locked).
// The key bytes are not zeroed: an in-flight seal may still hold the same array, and sealing
// with a wiped key would make the vault undecryptable.
export function forget() {
  rawKey = null;
  data = null;
  recordCt = null;
}

// Re-read the stored record after another page changed it.
export async function reload() {
  const record = await store.getRecord();
  if (!record || !rawKey) {
    forget();
    return false;
  }
  try {
    remember(rawKey, record, await vault.open(rawKey, record));
    return true;
  } catch {
    forget();
    return false;
  }
}

// Decrypts the data of another vault record (an imported backup) with its own passphrase.
export async function readBackup(record, passphrase) {
  const opened = await vault.unlock(record, passphrase);
  return normalizeData(opened.data).accounts;
}

// Adds accounts (shape of otpauth.parse()), skipping duplicates. → { added, skipped }
export function addAccounts(incoming) {
  return mutate((current) => {
    const seenKeys = new Set(current.accounts.map(duplicateKey));
    const seenIds = new Set(current.accounts.map((a) => a.id));
    let added = 0;
    let skipped = 0;
    for (const account of incoming) {
      const key = duplicateKey(account);
      if (seenKeys.has(key)) {
        skipped++;
        continue;
      }
      const id = typeof account.id === 'string' && account.id && !seenIds.has(account.id)
        ? account.id
        : crypto.randomUUID();
      current.accounts.push({
        id,
        issuer: account.issuer ?? '',
        label: account.label ?? '',
        secret: account.secret,
        algorithm: account.algorithm,
        digits: account.digits,
        period: account.period,
        createdAt: Number.isFinite(account.createdAt) ? account.createdAt : Date.now(),
      });
      seenKeys.add(key);
      seenIds.add(id);
      added++;
    }
    return { added, skipped };
  });
}

export function deleteAccount(id) {
  return mutate((current) => {
    const before = current.accounts.length;
    current.accounts = current.accounts.filter((a) => a.id !== id);
    return before !== current.accounts.length;
  });
}

// Mutations run one at a time, each against the freshest stored record, so a popup and a tab
// open at the same time cannot overwrite each other's changes.
let queue = Promise.resolve();

function mutate(change) {
  const run = queue.then(() => applyChange(change));
  queue = run.catch(() => {});
  return run;
}

async function applyChange(change) {
  if (!rawKey) throw new SessionError('locked');
  const record = await store.getRecord();
  if (!record) throw new SessionError('no-vault');
  const current = normalizeData(await vault.open(rawKey, record));
  const result = change(current);
  const sealed = await vault.seal(rawKey, record, current);
  // Recognise our own storage echo even if it arrives before saveRecord resolves.
  recordCt = sealed.ct ?? null;
  try {
    await store.saveRecord(sealed);
  } catch (error) {
    recordCt = record.ct ?? null;
    throw error;
  }
  remember(rawKey, sealed, current);
  return result;
}

function remember(key, record, opened) {
  rawKey = key;
  data = normalizeData(opened);
  recordCt = record.ct ?? null;
}

function normalizeData(value) {
  const base = value && typeof value === 'object' ? value : {};
  const list = Array.isArray(base.accounts) ? base.accounts : [];
  return { ...base, accounts: list.filter((a) => a && typeof a === 'object' && a.secret) };
}

// vault.unlock rejects a wrong passphrase with VaultError('bad-passphrase'); a raw AES-GCM
// authentication failure would surface as an OperationError.
export function isBadPassphrase(error) {
  if (!error) return false;
  if ([error.code, error.message, error.reason].includes('bad-passphrase')) return true;
  return error.name === 'OperationError';
}

export class SessionError extends Error {
  constructor(code) {
    super(code);
    this.name = 'SessionError';
    this.code = code;
  }
}
