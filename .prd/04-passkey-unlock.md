# 04 — Passkey unlock

Status: shipped to main 2026-11-17 (v0.3, untagged). A0–A5 and the A6 gates/review/disclosures
are met (receipts in v0-3-passkey/loop.done.md R1); the A6 owner hand test and the v0.3.0 tag are
open. Workstream: [v0-3-passkey/](v0-3-passkey/ssot.md).
Revision 3 (2026-11-17): R1 3×REJECT (same holes, envelope kept) → rev 2 → R2 grok APPROVE,
fable APPROVE, gpt-6 REJECT (record revision vs identity; storage-writer wording) → rev 3 →
**R3 unanimous APPROVE** (non-blocking notes folded: rev encoding, lockGen absent at start).
Revision 4 (2026-11-17, after gate A0 passed): the measured A0 result, the ceremony surface moved
onto views that already exist (lib/nav.js unchanged), a fresh passphrase salt on migration, a
passphrase pre-check before the ceremony, and the frozen module contracts below.

## Problem

The vault opens only with the passphrase. The owner wants to unlock it with a passkey
(owner directive 2026-11-17, verbatim in the ssot). The vault is local: nothing checks an
assertion on a server, so a passkey protects the vault only if it **produces key material**.
A plain `get()` whose result the extension "checks" in JS protects nothing — anyone who can read
the stored record skips the check. The key material comes from the WebAuthn `prf` extension
(CTAP2 `hmac-secret`): 32 bytes the authenticator computes from a per-credential secret. With
user verification (required here) the value cannot be reproduced without that verification.

## Goals / non-goals

- Goal: after one enrollment, the locked vault opens with a passkey (a phone over QR + Bluetooth,
  a security key with a PIN, Touch ID on a Mac) instead of typing the passphrase.
- Goal: the passphrase keeps working (lost passkey, another install, backups).
- Non-goal: removing the passphrase (one lost authenticator would lose every code; owner decision,
  irreversible class). Non-goal: face unlock on Linux (nothing exposes the IR camera to browser
  WebAuthn). Non-goal: syncing; pages still make no network requests. Non-goal (v0.3): changing
  the passphrase (no such flow exists today; when added it must draw a new DEK **and a new `id`**,
  re-encrypt, and drop every passkey slot, so a session holding the old DEK no longer matches).

## Platform facts (measured or sourced 2026-11-17; receipts in v0-3-passkey/loop.md)

| Fact | Evidence |
|---|---|
| An extension page can call `create()`/`get()`; with `rp.id` omitted (or = the bare extension ID) the RP ID that reaches the authenticator is the string `chrome-extension://<id>`; a web domain or the full `chrome-extension://` string as `rp.id` is a SecurityError | spike, Chromium 159, CDP virtual authenticator; Chromium `chrome_web_authentication_delegate.cc` L116-124, L231 @7d2c6b8 |
| PRF returns 32 bytes on `get()` (and on `create()` for native-PRF / hmac-secret-mc authenticators); same salt → same bytes | spike (hasPrf; hasHmacSecret without -mc: `enabled` on create, bytes on get) |
| Credentials are bound to one extension ID; Chrome Web Store, Edge Add-ons and the unpacked install differ | spike; Microsoft Q&A 1508048 |
| Edge 153 on the Z13 (CachyOS): no platform authenticator (`isUserVerifyingPlatformAuthenticatorAvailable()` false), `hybridTransport` true, `extension:prf` true | z13 probe, headless fresh profile |
| Linux has no OS passkey store in Chromium; Edge's passkey sync is documented for Windows/iOS/Android only | Chromium `crypto/user_verifying_key.cc` @7d2c6b8; microsoft.com/edge/features/passkeys |
| The Z13 has a 5 MP IR camera (`/dev/video2`); no face/fingerprint software installed; Howdy is PAM-only (WebAuthn PR #1125 closed unmerged 2026-11-14); credentialsd v0.4.0 has no platform authenticator and no native Chromium support | z13 probe; howdy #782/#1125; credentialsd #6/#8/#245 |
| iCloud Keychain gives PRF in Chromium on macOS 15+ (M132); phones give PRF over hybrid in Chromium; iOS fixed a hybrid vs on-device PRF mismatch in 18.4, one open mismatch report remains | `icloud_keychain.mm` L256-258; blink-dev msg11227; Apple forum 764730/774112 |
| YubiKey 5 / Bio: hmac-secret; PRF requires UV, so a FIDO2 PIN (or the Bio fingerprint) | Yubico PRF guide; WebAuthn L3 §prf |
| The toolbar popup is only protected against Chrome's own web-modal dialogs; Bitwarden tells Linux users to pop the extension out first | `extension_popup.cc` L379-383; bitwarden.com/help/login-with-passkeys |
| Gate A0, measured: from Edge 153 on Linux over hybrid, an iPhone saving to Apple Passwords accepts the `chrome-extension://` RP ID and returns PRF 32 B on create and on both gets, all equal (create 23.4 s, gets 10.3 s and 15.4 s). An Android phone saving to Samsung Pass accepts the RP ID but returns no PRF on create (`enabled` false) or on either get (create 15 s, gets 8.3 s and 8.6 s). Google Password Manager over hybrid is not measured | owner probe 0.0.2 (v0-3-passkey/loop.md P2, P3) |

## Threat model (what this does and does not change)

- **At rest, strength = the passphrase.** The passphrase slot stays, so an attacker with a copy
  of the stored record still attacks PBKDF2 (600k). The passkey is a convenience; its security
  gain is that a long passphrase stops being a burden.
- **Session = DEK.** Like v1's session key, whoever holds it reads the codes now. Re-entering the
  passphrase before enrollment guards against the person at an unlocked screen; it is not a
  boundary against code running in an extension context, which can wrap its own slots.
- **The DEK is long-lived.** Removing a passkey slot removes it from this record only; earlier
  copies (backups, disk images) keep their slots. Nothing here revokes a copy.
- **Storage-only writers** can cause denial of service, remove slots, or replay older valid
  records (reviving a removed slot); this design does not provide rollback resistance. Storage
  write alone does not bypass AES-GCM confidentiality: it yields no DEK, KEK or PRF output.
- The UV flag check in the extension is auxiliary; the protection is the authenticator's
  UV-bound PRF secret.

## Design

### Vault record v2 (lib/vault.js)

```
{ v: 2, id: <16 random bytes, b64>,
  data: { iv, ct },                          // AES-256-GCM under the DEK, 128-bit tag
  slots: [
    { type: 'passphrase', kdf: { name:'PBKDF2', hash:'SHA-256', iterations, salt }, iv, wrapped },
    { type: 'passkey', cred: <rawId b64url>, prfSalt: <32 B b64>, label, createdAt, iv, wrapped }
  ] }
```

- DEK = 32 random bytes. `wrapped` = AES-256-GCM(KEK, iv 12 B random, DEK) = 48 bytes.
- Passphrase KEK = PBKDF2 exactly as v1 (bounds of v1: salt 16..64 B, iterations 1..2,000,000).
- Passkey KEK = HKDF-SHA-256(ikm = PRF `first` 32 B, salt = empty, info =
  "zauthenticator vault v2 passkey kek", length 32). PRF input = the slot's random `prfSalt`.
- AAD = UTF-8 of canonical JSON with this exact key order, no whitespace:
  data `{"v":2,"id":…}`; passphrase slot `{"v":2,"id":…,"type":"passphrase","kdf":{"name","hash","iterations","salt"}}`;
  passkey slot `{"v":2,"id":…,"type":"passkey","cred":…,"prfSalt":…,"label":…,"createdAt":…}`.
- Structural check before any PBKDF2 or WebAuthn call; reject otherwise: `v` = 2 exactly; `id`
  16 B; `data.iv` 12 B; `data.ct` 16 B..1 MiB; `slots[0]` is the one and only passphrase slot;
  0..1 passkey slots (cap 1 until a second authenticator is a measured need); `cred` 1..1023 B;
  `prfSalt` 32 B; `wrapped` 48 B; slot `iv` 12 B; `label` ≤ 64 chars; `createdAt` integer; no
  unknown `type`. A record without a passphrase slot is never accepted or written.
- `seal(dek, record, data)` for v2 copies `id` and `slots` unchanged and replaces only
  `data.iv` (fresh random 12 B every call) and `data.ct`. `open()` dispatches on `v`.
- Slot operations exist only as these functions:
  - `addPasskeySlot(record, passphrase, {cred, prfSalt, prf, label})` — verifies the passphrase
    by unwrapping the passphrase slot (or by v1 `unlock` when migrating) **inside the function**;
    there is no DEK-only writer. Migrating a v1 record draws a fresh DEK, a fresh `id` and a fresh
    16 B passphrase salt (same iteration count as the v1 record, never below it), so the old v1
    key, which may still sit in memory or an old session, is not the new passphrase KEK.
  - `removePasskeySlot(record, cred)` — by `cred`; never touches the passphrase slot.
  - `exportCopy(record)` — returns a new object without passkey slots; the live record is not
    modified or re-saved.
- **Verify before save:** unwrap the passphrase slot → dekP and the passkey slot → dekK
  independently from the new record's bytes; require dekP = dekK = the DEK used to seal, and
  `open(dekP)` payload deep-equal to the source payload. Only then may it reach storage.

### Session key

`chrome.storage.session` keeps the key with its record identity: `{ key, v, id }` (v1: `id`
absent). Identity answers only "does this key belong to this vault". Every reader (pages and the
auto-fill worker, both already under the `zauthenticator-vault` Web Lock via `withVaultState` /
`readUnlocked`) compares it with the stored record; on mismatch it clears the session and treats
the vault as locked. A crash between save and session update therefore ends in "locked", never
in a wrong key.

Two more values decide whether a ceremony result may still be used:
- `rev` = SHA-256 of the canonical serialization of the **whole** stored record (`data`,
  `slots`, headers): the same fixed-key-order, no-whitespace JSON as the AAD, covering every
  field. Computed when needed, never stored. Every `seal` changes it (new `data.iv`), so any edit,
  slot removal or import merge in any window changes `rev`; `id` does not. A v1 record hashes the
  same way over `{v,kdf,iv,ct}`.
- `lockGen` = 16 random bytes in `chrome.storage.session`, replaced by every lock path inside
  `store.clearSessionKey()` — manual, idle, and the mismatch clear above — in the same write that
  nulls `vaultKey`. It is shared by all windows and the worker, unlike the page-local `epoch`.
  After a browser start it is absent until the first lock or the first ceremony capture:
  `store.ensureLockGen()` writes one under the vault lock before a capture is issued, and no
  capture is issued when that write fails, so a capture never holds "absent". If a lock's write
  fails, its removal step deletes `lockGen` too, so every issued capture stops matching
  (trinity T2, 2026-11-17).

### Flows

- **Ceremony surface:** never the toolbar popup (it closes when focus moves to the browser's
  passkey dialog). Enroll and remove run in the Settings **tab** (`openOwnView('settings')`); in
  the toolbar popup that section only offers "Open in a tab". Unlock runs in the `#unlock` window
  (`openOwnWindow('unlock')`, which closes itself after an unlock): the toolbar popup's "Unlock
  with passkey" opens that window, and the same button inside the window starts the ceremony.
  Both views already exist in lib/nav.js, so nav.js and its sha256 pin do not change.
  A ceremony starts only from a user click inside an extension page; no message (content script,
  worker) starts one. Each ceremony captures `rev` and `lockGen` (and, for enrollment, the session
  identity) at its start.
- **Enroll** (Settings → "Unlock with a passkey" → "Add"; the text says the browser will ask
  twice): re-enter the passphrase; it is checked before `create()` (a wrong one costs no phone
  round trip) and checked again inside `addPasskeySlot`. `create()`
  with `rp: {name}` (no `id`), random user id, `residentKey:'required'`,
  `userVerification:'required'`, `authenticatorAttachment:'cross-platform'` when UVPA is false,
  `hints: ['hybrid','security-key']`, algs [-8, -7, -257], `prf.eval.first = prfSalt`. Then
  **always** `get()` for that exact credential with the same salt; require 32 bytes; if
  `create()` also returned bytes they must be equal. Any failure: nothing stored, message says the
  passkey may remain on the phone/key and how to delete it.
- **Commit** (inside the `zauthenticator-vault` lock, before it is released): re-read the
  record, `lockGen` and the session; abort with nothing written ("the vault changed — start
  again") unless the current `rev` and `lockGen` equal the captured ones and the session still
  holds the same identity; build via `addPasskeySlot` (fresh DEK when migrating v1); verify
  before save; `saveRecord`; set the session `{key: DEK, v: 2, id}`; update the page state.
- **Unlock** (locked view shows "Unlock with passkey" when the record has a passkey slot): own
  window; `get()` with `allowCredentials` = the slot's `cred`, UV required,
  `prf.eval.first = prfSalt`. Then, inside the vault lock: abort with nothing written unless the
  current `rev` and `lockGen` equal the captured ones; unwrap; open; set the session; the toolbar
  popup refreshes. Failure leaves it locked with a message; the passphrase field stays.
- **Remove** (Settings, unlocked): `removePasskeySlot`, saved under the vault lock like every
  mutation; text: "Removed from this browser. Old backups are not affected. Delete the passkey on
  your phone or key too."
- **Backups:** export writes `exportCopy(record)`. The backup still shares the DEK with the live
  vault (stated in the UI help and PRIVACY). Import keeps today's semantics: while unlocked,
  decrypt the file through its passphrase slot (v1 or v2) and merge its accounts under the
  current key; the backup record is never saved. `looksLikeRecord` accepts the v2 shape.
- **Feature detection:** when `PublicKeyCredential.getClientCapabilities` exists, the passkey
  controls appear only if it reports `extension:prf` true. When that call does not exist, the
  "Add" control is shown and the enrollment ceremony decides (no PRF → the refusal message,
  nothing stored). Without `PublicKeyCredential` nothing is shown. `minimum_chrome_version`
  stays 116.

### Trust gate

`navigator.credentials` is allowed in exactly one module (`popup/passkey.js`); the gate fails it
anywhere else (content scripts, worker, lib). Pinned policy + self-test cases. Manifest: no new
permission; CSP unchanged.

## Module contracts (v0.3, frozen 2026-11-17 before code)

Every unit codes against these signatures; a change goes into this section first.

### lib/vault.js (v1 functions keep their signatures)

- `create(passphrase, data, opts)` unchanged: a new vault is v1 until a passkey is enrolled (A5).
- `unlock(record, passphrase)` → `{data, rawKey}`. v2: unwraps the passphrase slot; `rawKey` is
  the DEK. A wrong passphrase is `'bad-passphrase'`.
- `seal(rawKey, record, data)` and `open(rawKey, record)` dispatch on `v` (v2 rules above).
- `identity(record)` → `{v: 1}` or `{v: 2, id}`, after the structural check (throws as `open`
  does for a malformed record).
- `revision(record)` → `Promise<string>`: lowercase hex SHA-256 of the canonical JSON of the whole
  record. v1 key order `v, kdf{name,hash,iterations,salt}, iv, ct`; v2 `v, id, data{iv,ct},
  slots[]`, each slot in its AAD key order (without the leading `v`/`id`) followed by `iv,
  wrapped`.
- `passkeySlot(record)` → `{cred, credBytes, prfSalt, label, createdAt}` or `null` (v1 or no
  slot). `cred` is the stored base64url string; `credBytes` and `prfSalt` are `Uint8Array`.
- `addPasskeySlot(record, passphrase, {cred, prfSalt, prf, label})` → `{record, rawKey}`.
  `cred` and `prfSalt` are `Uint8Array` (stored as base64url and base64), `prf` is the 32-byte
  PRF output for `prfSalt`, `label` a string of at most 64 characters (may be empty),
  `createdAt` = `Date.now()`. Verifies the passphrase itself (above), refuses a second passkey
  slot (`'slot-exists'`), runs verify-before-save on a JSON round trip of the new record, and only
  then returns it.
- `unlockWithPasskey(record, prf)` → `{data, rawKey}`; `'no-passkey'` when the record has no
  passkey slot; `'bad-passkey'` when the unwrap fails.
- `removePasskeySlot(record, cred)` → new record without the passkey slot whose `cred` (base64url
  string) matches; `'no-passkey'` when none does; `id`, `data` and the passphrase slot unchanged.
- `exportCopy(record)` → new object: v2 without passkey slots, v1 a copy. The input is not
  modified.
- New `VaultError` codes: `'bad-passkey'`, `'no-passkey'`, `'slot-exists'`. A `prf` that is not a
  32-byte `Uint8Array` is a `TypeError`.

### lib/store.js

- `vaultKey` (session) holds `{key: <base64>, v: 1|2, id?: <base64>}`. `getSessionKey()` →
  `{key: Uint8Array, v, id}` or `null`; anything else stored there (the v0.2 bare string
  included) reads as `null`, so an update leaves the vault locked. `setSessionKey(key, {v, id},
  activeAt)`.
- `lockGen` (session, the sixth key): 16 random bytes, base64. `clearSessionKey()` writes a new
  value with `vaultKey: null` and removes the other four session keys (on a failed write it
  removes `lockGen` too); `getLockGen()` → string or `null`; `ensureLockGen()` → the stored value,
  writing a fresh one first when none is stored, throws when it cannot.

### popup/session.js (the worker imports it, so it never imports popup/passkey.js)

- Every reader that loads the session key (`resume`, `refresh`, `touch`, `lockIfIdle`,
  `openStored`, `setPendingBind`, `mutate`) compares the session `{v, id}` with
  `vault.identity(stored record)`; a mismatch clears the session (a lock) and reads as locked.
- "Same record as this page holds" compares the record's ciphertext: `data.ct` in v2, `ct` in v1.
- `passkeyState()` → `{slot}` (`vault.passkeySlot` of the stored record, or `null`); no key
  needed.
- `captureForCeremony()` → `{rev, lockGen, identity, slot}`, read under the vault lock and
  returned; the ceremony itself runs after the lock is released (it takes 10–25 s).
- `checkPassphrase(passphrase)` → `true`, or throws `'bad-passphrase'`; only while unlocked.
- `enrollPasskey(capture, passphrase, {cred, prfSalt, prf, label})` and
  `unlockWithPasskey(capture, prf)` → the commits of Flows; `SessionError('changed')` when `rev`,
  `lockGen` or (enroll) the session identity differ from `capture`; nothing is written then.
  Once the enrolled record is saved, `enrollPasskey` never rejects: it resolves
  `{saved: true, locked: false}`, or `{saved: true, locked: true}` when this page locked during
  the save or the session key could not be written. `locked: true` means this page dropped its
  key and a lock of the shared session was attempted. If that lock also fails, the shared session
  is left no more open than before the enrollment: unchanged when nothing could be written, or
  already cleared when the lock got partway; after a v1 → v2 migration an unchanged key no longer
  matches the record and every reader treats it as locked; after a v2 enrollment (same DEK, same
  id) it still opens the vault, as it did before.
- `removePasskey(cred)` → under the vault lock, only while unlocked.
- `exportRecord()` → `vault.exportCopy(stored record)` or `null`.

### popup/passkey.js (the only module that touches `navigator.credentials` or `PublicKeyCredential`)

- `support()` → `'yes'` (`getClientCapabilities` reports `extension:prf` true), `'unknown'` (no
  `getClientCapabilities`), `'no'` (no `PublicKeyCredential`, or PRF reported false).
- `enrollCeremony({prfSalt})` → `{cred: Uint8Array, prf: Uint8Array}`: `create()` then `get()`
  for that credential with the same salt, as in Flows.
- `unlockCeremony({credBytes, prfSalt})` → PRF `Uint8Array` (32 B); the UV flag of the assertion
  is checked.
- Errors are `PasskeyError` with `code` `'cancelled'` (NotAllowedError, timeout), `'no-prf'`,
  `'mismatch'` (create and get bytes differ), `'failed'`.

## Acceptance

- **A0 (gate before record-format code):** the owner's probe on the Z13 Edge with their phone:
  create ok, two gets ok, PRF 32 bytes, both equal; seconds per ceremony recorded. If it fails:
  owner chooses security key with PIN / Mac only / stop, and the phone wording is removed. If it
  works but is slow: the seconds are shown to the owner and the build proceeds; a security key or
  a longer idle lock are added only if the owner asks.
- A1 e2e (CDP virtual authenticators `hasPrf` internal and `hasHmacSecret` usb without `-mc`):
  enroll → edit an account (seal) → lock → unlock with the passkey → lock → unlock with the
  passphrase; both still work after the seal.
- A2 an authenticator without PRF is refused; the stored record is byte-identical afterwards.
- A3 during an enrollment or unlock ceremony, each of these in another window → result
  discarded, nothing written: an account edit, a passkey removal, a manual lock, an idle lock, an
  import merge just before `get()` returns; also a lock-unlock-lock cycle while the unlock window
  waits. Session `{v,id}` mismatch → locked.
- A4 unit: tamper each AAD field / `wrapped` / `iv` → unwrap fails; records with zero or two
  passphrase slots, two passkey slots, or out-of-bound sizes are rejected before any KDF; seal
  keeps `id`+`slots` and changes `data.iv` and `rev`; remove refuses the passphrase slot;
  `exportCopy` leaves the live record unchanged; importing a v2 backup that carries a passkey
  slot makes no WebAuthn call.
- A5 a v1 vault is never rewritten until a passkey is enrolled; a v2 backup imports by merge.
- A6 gates green (unit, trust gate with the new rule, self-test, e2e), external review, README /
  PRIVACY / store disclosures updated, owner hand test (enroll with the phone, lock, unlock,
  restart the browser, unlock, passphrase still works).
