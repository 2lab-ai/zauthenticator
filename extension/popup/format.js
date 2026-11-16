// Small pure helpers shared by the popup views.
import * as base32 from '../lib/base32.js';
import { normalize } from '../lib/otpauth.js';

// "123456" → "123 456", "12345678" → "1234 5678", "1234567" → "1234 567".
export function groupCode(code) {
  if (typeof code !== 'string' || code.length < 6) return code ?? '';
  const cut = Math.ceil(code.length / 2);
  return `${code.slice(0, cut)} ${code.slice(cut)}`;
}

// Canonical form of a base32 secret, so "jbsw y3dp" and "JBSWY3DP" compare equal.
export function canonicalSecret(secret) {
  const text = String(secret ?? '');
  try {
    return base32.encode(base32.decode(text));
  } catch {
    return text.replace(/[\s=-]/g, '').toUpperCase();
  }
}

// Two entries are duplicates when secret, issuer, label, algorithm, digits and period all
// match, compared in canonical form ('sha-256' = 'SHA256', '8' = 8, missing = the default).
// An entry that is not a valid account is compared by its raw fields.
export function duplicateKey(account) {
  let a = account !== null && typeof account === 'object' ? account : {};
  try {
    a = normalize(a);
  } catch {
    // keep the raw fields
  }
  return JSON.stringify([
    canonicalSecret(a.secret),
    a.issuer ?? '',
    a.label ?? '',
    a.algorithm ?? '',
    a.digits ?? '',
    a.period ?? '',
  ]);
}

export function matchesQuery(account, query) {
  const q = query.trim().toLocaleLowerCase();
  if (!q) return true;
  return `${account.issuer ?? ''}\n${account.label ?? ''}`.toLocaleLowerCase().includes(q);
}

export function displayName(account) {
  const issuer = account.issuer ?? '';
  const label = account.label ?? '';
  if (issuer && label) return `${issuer} (${label})`;
  return issuer || label;
}

// zauthenticator-backup-YYYY-MM-DD.json in local time.
export function backupFileName(date = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  return `zauthenticator-backup-${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}.json`;
}

// Shape check for an imported file before asking the vault to open it.
export function looksLikeRecord(value) {
  return Boolean(
    value && typeof value === 'object' &&
    value.kdf && typeof value.kdf === 'object' &&
    typeof value.iv === 'string' && typeof value.ct === 'string'
  );
}
