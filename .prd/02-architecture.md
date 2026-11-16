# 02 — Architecture

Status: planned (2026-11-16)

## Layout

```text
extension/                 # the unpacked extension root (Load unpacked → this folder)
  manifest.json
  lib/base32.js            # RFC 4648 base32 encode/decode            (pure, Node-testable)
  lib/totp.js              # RFC 6238 TOTP over WebCrypto HMAC          (pure)
  lib/otpauth.js           # otpauth:// URI parse/format + validation   (pure)
  lib/vault.js             # PBKDF2 → AES-GCM vault seal/open           (pure)
  lib/store.js             # chrome.storage glue (local = vault record, session = unlocked key)
  lib/qr.js                # image/dataURL → otpauth string via vendored jsQR
  popup/popup.html|css|js  # the only UI (also opened as a full tab for file import)
  vendor/jsQR.js           # pinned upstream build + vendor/jsQR.LICENSE + vendor/SHA256SUMS
  icons/16.png 32.png 48.png 128.png   # original artwork
test/*.test.mjs            # node --test (pure modules only)
e2e/popup.e2e.mjs          # Playwright: real Chromium + unpacked extension
scripts/check-policy.mjs   # static trust gate (npm run check)
scripts/build-zip.mjs      # dist/zauthenticator-<version>.zip
.github/workflows/ci.yml   # test + check on push/PR
.github/workflows/release.yml  # tag v* → zip → GitHub release
```

No bundler, no transpiler, no runtime npm dependencies. `package.json` carries scripts and the
`playwright` dev dependency only.

## Module contracts (ES modules, all async where WebCrypto is used)

```js
// lib/base32.js
export function decode(str)   // → Uint8Array; case-insensitive; ignores spaces, '-', trailing '='; throws Error on bad chars or empty
export function encode(bytes) // → uppercase base32 without padding

// lib/totp.js
export async function hotp(keyBytes, counter, { algorithm = 'SHA1', digits = 6 } = {}) // → zero-padded string
export async function totp(account, nowMs = Date.now())  // account = { secret(base32), algorithm, digits, period } → string
export function remainingSeconds(period, nowMs = Date.now()) // → integer 1..period
// algorithm ∈ 'SHA1' | 'SHA256' | 'SHA512' (maps to WebCrypto 'SHA-1' | 'SHA-256' | 'SHA-512')

// lib/otpauth.js
export function parse(uri)          // → { issuer, label, secret, algorithm, digits, period }; throws on hotp / bad secret / bad params
export function format(account)     // → otpauth://totp/... URI (round-trips through parse)
export function normalize(input)    // manual-entry validation → same shape as parse(); defaults SHA1/6/30

// lib/vault.js   (record is plain JSON, safe to store)
export const DEFAULT_ITERATIONS = 600000
export async function create(passphrase, data, { iterations } = {}) // → { record, rawKey: Uint8Array }
export async function unlock(record, passphrase)                   // → { data, rawKey }; throws VaultError('bad-passphrase')
export async function seal(rawKey, record, data)                   // → new record (same kdf params, fresh 12-byte IV)
export async function open(rawKey, record)                         // → data
// record = { v: 1, kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: b64 }, iv: b64, ct: b64 }
// data   = { accounts: [ { id, issuer, label, secret, algorithm, digits, period, createdAt } ] }
```

`lib/store.js` keeps exactly two keys: `chrome.storage.local.vault` (the record) and
`chrome.storage.session.vaultKey` (base64 raw key, default access level = trusted contexts
only, cleared when the browser session ends or on Lock).

## Manifest (v0.1)

```json
{
  "manifest_version": 3,
  "name": "zauthenticator",
  "version": "0.1.0",
  "permissions": ["storage", "activeTab"],
  "action": { "default_popup": "popup/popup.html" },
  "content_security_policy": {
    "extension_pages": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
  }
}
```

No background service worker in v0.1. `connect-src 'none'` also blocks `fetch(dataURL)`, so
images are decoded with `createImageBitmap` on a Blob (never `fetch`, never `<img>`), and only formats whose size is read from the header first (see Round 3).

## Popup DOM contract (the e2e test drives these ids)

| State | Elements |
|---|---|
| setup | `#setup-pass`, `#setup-pass2`, `#setup-submit`, error `#setup-error` |
| locked | `#unlock-pass`, `#unlock-submit`, error `#unlock-error` |
| list | `#search`, `#add-btn`, `#lock-btn`, `#settings-btn`; rows `.account[data-id]` containing `.code[data-code]` (raw digits) and `.issuer`, `.label`, `.remaining` |
| add | `#add-uri` (textarea, one URI per line), `#add-uri-submit`; `#manual-issuer`, `#manual-label`, `#manual-secret`, `#manual-submit`; `#scan-tab-btn`; `#scan-file-btn`; error `#add-error`; `#add-cancel` |
| settings | `#export-btn`, `#import-file`, `#import-pass`, `#import-submit`, per-row delete in list edit mode `.account .delete` |
| global | `body[data-state]` ∈ `setup` `locked` `list` `add` `settings` |

## Trust gate (`scripts/check-policy.mjs`)

Fails (exit 1) when any of these holds:
- manifest `permissions` ⊄ {`storage`, `activeTab`}; any `host_permissions`, `optional_host_permissions`, `content_scripts`, `externally_connectable`, `update_url`, `key`.
- CSP missing `connect-src 'none'` or `script-src 'self'` or has `unsafe-eval`/`unsafe-inline`/`wasm-unsafe-eval`.
- Any `extension/**/*.{js,html}` outside `vendor/` contains `fetch(`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`, `eval(`, `new Function`, `importScripts`, `http://`, `https://` (except in comments of license headers — none expected), or an inline `<script>` body / `on*=` attribute.
- `vendor/SHA256SUMS` does not match the vendored files.

## Round 2 contract changes (2026-11-16, from the R1 review: 3-engine panel + 3 reviewers, all REJECT on the same defects)

State and storage
- **Cross-page exclusion.** Every vault read-modify-write (`create`, every mutation, `unlock` → session key write, `lock` → session key clear) runs inside `navigator.locks.request('zauthenticator-vault', …)` (Web Locks are shared by all extension pages of the same origin: popup + full tab). Inside the lock a mutation re-reads the stored record, opens it, applies the change, seals, saves.
- **Lock invalidates in-flight work.** `session.js` keeps a generation counter; `forget()`/`lock()` bump it. Every async path (`resume`, `unlock`, `reload`, mutations) captures the generation (and key) at start and publishes results (`remember`, session-key write) only if both are unchanged. `accounts()` returns `[]` while locked.
- **Lock clears sensitive inputs** (setup/unlock passphrases, backup passphrase + file, otpauth textarea, manual issuer/label/secret) on local and propagated locks.
- **Idle auto-lock (15 min, fixed in v0.1).** Session storage may hold exactly `vaultKey` and `lastActiveAt` (ms). Opening a page whose `lastActiveAt` is older than 15 minutes locks before showing codes; user activity in an open page refreshes it.
- Stored accounts are never dropped by a seal; invalid stored entries render as "Invalid key". Imported entries are validated with `otpauth.normalize`; invalid ones are skipped and counted in the result message. Duplicate identity = canonical secret + issuer + label + algorithm + digits + period.

Inputs and crypto
- Passphrases are NFC-normalized before PBKDF2 (pre-release, no existing vaults). Vault structural checks (sizes of salt ≤ 64 B, iv = 12 B, ct ≤ 1 MiB) run before key derivation; iterations 1..2,000,000.
- Backup files > 1 MiB are rejected before reading. Images > 20 MiB are rejected before decoding; PNG/JPEG/GIF/WebP/BMP headers are sniffed and images above 50 megapixels rejected before decoding; decoding uses `createImageBitmap` with resize options so no full-resolution canvas exists above 4096 px per side.
- `otpauth.parse` rejects a non-empty `issuer` parameter that conflicts with a non-empty label prefix, duplicate `secret/issuer/algorithm/digits/period` parameters, and malformed percent-encoding in the query.
- Copy recomputes the code at click time (never copies a cached code from an expired period).

Network claim and gate
- The claim is stated precisely: CSP blocks every connection and remote resource load from extension pages (`default-src 'none'` + explicit directives); the static gate additionally bans URL strings, navigation sinks (`window.open`, `location` assignment/`assign`/`replace`, `chrome.tabs.create/update` with anything but `chrome.runtime.getURL(...)`), and CSS `url(http…)`/`@import`. The settings "Source code" button is removed (the extensions page already links `homepage_url`).
- The gate requires the CSP to equal the approved policy exactly (directive set and values), rejects duplicate SHA256SUMS paths, and its self-test pins the policy constants against an independently written literal copy.
- Release publishing reuses the CI verification (unit, gate + self-test, Chromium e2e) and actions are pinned by commit SHA.

## Round 3 contract changes (2026-11-16, from the R2 review)

- `extension/lib/nav.js` is the only code that opens a tab (`openOwnView('add-file' | 'settings')` → this extension's `popup/popup.html#<view>`). The trust gate rejects every tab/window-opening call (`chrome.tabs.create/update/duplicate/goBack/goForward`, `chrome.windows.create/update`, `window.open`, …) outside it and pins `nav.js` by sha256.
- The gate tokenizes the CSP with ASCII whitespace only and rejects any non-ASCII character in it; SHA256SUMS lines must be canonical (`<sha256>  <name>` with a plain relative name, no `./`, `..`, `\`, or `vendor/` prefix).
- QR images: only formats whose dimensions are read from the header before decoding (PNG, JPEG, GIF, WebP, BMP) are decoded; every other format is rejected before any decoder runs (`QRError('unsupported-format')`).
- Idle lock decisions are re-checked under the vault Web Lock against the current `lastActiveAt` and generation before the key is removed. Backup import accepts files up to 2 MiB (a vault at its 1 MiB ciphertext cap exports ~1.37 MiB).
