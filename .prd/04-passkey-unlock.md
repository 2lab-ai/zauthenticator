# 04 — Passkey unlock

Status: planned (v0.3). Workstream: [v0-3-passkey/](v0-3-passkey/ssot.md).
Revision 2 (2026-11-17) after trinity R1 (grok-4.7, gpt-6-astra, fable: all REJECT on the same
holes, envelope kept). Record-format code waits for gate A0 (owner phone probe).

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
  the passphrase (no such flow exists today; when added it must rotate the DEK, re-encrypt, and
  drop every passkey slot).

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
| **Unverified — gate A0:** a phone accepts a `chrome-extension://` RP ID over hybrid from Edge on Linux and returns stable PRF; seconds per unlock | owner probe (v0-3-passkey/loop.md P2) |

## Threat model (what this does and does not change)

- **At rest, strength = the passphrase.** The passphrase slot stays, so an attacker with a copy
  of the stored record still attacks PBKDF2 (600k). The passkey is a convenience; its security
  gain is that a long passphrase stops being a burden.
- **Session = DEK.** Like v1's session key, whoever holds it reads the codes now. Re-entering the
  passphrase before enrollment guards against the person at an unlocked screen; it is not a
  boundary against code running in an extension context, which can wrap its own slots.
- **The DEK is long-lived.** Removing a passkey slot removes it from this record only; earlier
  copies (backups, disk images) keep their slots. Nothing here revokes a copy.
- **Out of scope: storage-write attackers.** One who can write `chrome.storage.local` can delete
  slots (forcing the passphrase) or roll the record back (reviving a removed slot); that is
  equivalent to extension compromise.
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
    there is no DEK-only writer.
  - `removePasskeySlot(record, cred)` — by `cred`; never touches the passphrase slot.
  - `exportCopy(record)` — returns a new object without passkey slots; the live record is not
    modified or re-saved.
- **Verify before save:** unwrap the passphrase slot → dekP and the passkey slot → dekK
  independently from the new record's bytes; require dekP = dekK = the DEK used to seal, and
  `open(dekP)` payload deep-equal to the source payload. Only then may it reach storage.

### Session key

`chrome.storage.session` keeps the key with its record identity: `{ key, v, id }` (v1: `id`
absent). Every reader (pages and the auto-fill worker, both already under the
`zauthenticator-vault` Web Lock) compares it with the stored record; on mismatch it clears the
session and treats the vault as locked. A crash between save and session update therefore ends
in "locked", never in a wrong key.

### Flows

- **Ceremony surface:** always the own window (`popup.html#passkey`), never the toolbar popup.
- **Enroll** (Settings → "Unlock with a passkey" → "Add"): re-enter the passphrase. `create()`
  with `rp: {name}` (no `id`), random user id, `residentKey:'required'`,
  `userVerification:'required'`, `authenticatorAttachment:'cross-platform'` when UVPA is false,
  `hints: ['hybrid','security-key']`, algs [-8, -7, -257], `prf.eval.first = prfSalt`. Then
  **always** `get()` for that exact credential with the same salt; require 32 bytes; if
  `create()` also returned bytes they must be equal. Any failure: nothing stored, message says the
  passkey may remain on the phone/key and how to delete it.
- **Commit** (inside the `zauthenticator-vault` lock, before it is released): re-read the
  record; abort ("the vault changed — start again") if it is not the record the ceremony started
  from (same `id`, or for v1 the same `ct`) or the session generation moved (lock, idle lock,
  import); build via `addPasskeySlot` (fresh DEK when migrating v1); verify before save;
  `saveRecord`; set the session `{key: DEK, v: 2, id}`; update the page state.
- **Unlock** (locked view shows "Unlock with passkey" when the record has a passkey slot): own
  window; `get()` with `allowCredentials` = the slot's `cred`, UV required,
  `prf.eval.first = prfSalt`; unwrap; open; set the session; the toolbar popup refreshes. A result
  that arrives after the window's generation moved is discarded. Failure leaves it locked with a
  message; the passphrase field stays.
- **Remove** (Settings, unlocked): `removePasskeySlot`; text: "Removed from this browser. Old
  backups are not affected. Delete the passkey on your phone or key too."
- **Backups:** export writes `exportCopy(record)`. The backup still shares the DEK with the live
  vault (stated in the UI help and PRIVACY). Import keeps today's semantics: while unlocked,
  decrypt the file through its passphrase slot (v1 or v2) and merge its accounts under the
  current key; the backup record is never saved. `looksLikeRecord` accepts the v2 shape.
- **Feature detection:** passkey controls appear only when `PublicKeyCredential` exists and
  `getClientCapabilities()['extension:prf']` is true (or the capability call is missing and a
  ceremony reports PRF). `minimum_chrome_version` stays 116.

### Trust gate

`navigator.credentials` is allowed in exactly one module (`popup/passkey.js`); the gate fails it
anywhere else (content scripts, worker, lib). Pinned policy + self-test cases. Manifest: no new
permission; CSP unchanged.

## Acceptance

- **A0 (gate before record-format code):** the owner's probe on the Z13 Edge with their phone:
  create ok, two gets ok, PRF 32 bytes, both equal; seconds per ceremony recorded. If it fails:
  owner chooses security key with PIN / Mac only / stop, and the phone wording is removed.
- A1 e2e (CDP virtual authenticators `hasPrf` internal and `hasHmacSecret` usb without `-mc`):
  enroll → edit an account (seal) → lock → unlock with the passkey → lock → unlock with the
  passphrase; both still work after the seal.
- A2 an authenticator without PRF is refused; the stored record is byte-identical afterwards.
- A3 lock (manual and idle) or a vault change during the ceremony → result discarded, record
  unchanged; session `{v,id}` mismatch → locked.
- A4 unit: tamper each AAD field / `wrapped` / `iv` → unwrap fails; records with zero or two
  passphrase slots, two passkey slots, or out-of-bound sizes are rejected before any KDF; seal
  keeps `id`+`slots` and changes `data.iv`; remove refuses the passphrase slot; `exportCopy`
  leaves the live record unchanged.
- A5 a v1 vault is never rewritten until a passkey is enrolled; a v2 backup imports by merge.
- A6 gates green (unit, trust gate with the new rule, self-test, e2e), external review, README /
  PRIVACY / store disclosures updated, owner hand test (enroll with the phone, lock, unlock,
  restart the browser, unlock, passphrase still works).
