# 04 — Passkey unlock

Status: planned (v0.3). Workstream: [v0-3-passkey/](v0-3-passkey/ssot.md).

## Problem

The vault opens only with the passphrase. The owner wants to unlock it with a passkey
(owner directive 2026-11-17, verbatim in the ssot). The vault is local: nothing checks an
assertion on a server, so a passkey can only protect the vault if it **produces key material**.
A plain `get()` whose result the extension "checks" in JS protects nothing — anyone who can read
the stored record skips the check. The key material comes from the WebAuthn `prf` extension
(CTAP2 `hmac-secret`): a 32-byte secret that only the authenticator can compute, and only after
user verification.

## Goals / non-goals

- Goal: after one enrollment, the locked vault opens with a passkey (Touch ID on a Mac, a phone
  over QR + Bluetooth, a security key with a PIN) instead of typing the passphrase.
- Goal: the passphrase keeps working: forgotten or lost passkey, a different install (another
  extension ID), backups.
- Non-goal: removing the passphrase. One lost authenticator would lose every code. Doing it
  needs the owner's explicit decision (irreversible data-loss class).
- Non-goal: face unlock on Linux (see Platform facts: nothing exposes the IR camera to browser
  WebAuthn today). Non-goal: syncing anything; the extension still makes no network requests.

## Platform facts (measured or sourced 2026-11-17; receipts in v0-3-passkey/loop.md)

| Fact | Evidence |
|---|---|
| An extension page can call `create()`/`get()`; with `rp.id` omitted (or = the bare extension ID) the RP ID that reaches the authenticator is the string `chrome-extension://<id>` (rpIdHash = SHA-256 of that string); a web domain or the full `chrome-extension://` string as `rp.id` is a SecurityError | spike, Chromium 159, CDP virtual authenticator; Chromium `chrome_web_authentication_delegate.cc` L116-124, L231 @7d2c6b8 |
| PRF returns 32 bytes on `create()` (authenticators with native PRF / hmac-secret-mc) and on `get()`; same salt → same bytes, other salt → other bytes | spike (hasPrf; hasHmacSecret without -mc gives `enabled` on create and bytes only on get) |
| Credentials are bound to one extension ID. Chrome Web Store, Edge Add-ons and the unpacked install all have different IDs | spike; Microsoft Q&A 1508048 |
| Edge on the Z13 (Edge 153, CachyOS) has no platform authenticator: `isUserVerifyingPlatformAuthenticatorAvailable()` = false; `hybridTransport` true, `extension:prf` true | z13 probe, headless fresh profile |
| Linux has no OS passkey store in Chromium (`crypto/user_verifying_key.cc` returns null off Windows/Mac). Edge's own passkey sync is documented for Windows/iOS/Android only | Chromium @7d2c6b8; microsoft.com/edge/features/passkeys |
| The Z13 has a 5 MP IR camera (`/dev/video2` "ASUS IR camera", GREY 640x360); no face/fingerprint software installed. Howdy is a PAM module only; its WebAuthn PR #1125 was closed unmerged 2026-11-14; credentialsd (v0.4.0) has no platform authenticator and no native Chromium support | z13 probe; howdy #782/#1125; credentialsd #6/#8/#245 |
| iCloud Keychain passkeys give PRF in Chromium on macOS 15+ (launched M132). Phones give PRF over hybrid in Chromium (create and get); iOS fixed hybrid/on-device PRF mismatch in 18.4 (one open report of a mismatch remains) | Chromium `icloud_keychain.mm` L256-258; blink-dev msg11227; Apple forum 764730/774112 |
| YubiKey 5 / Bio: hmac-secret; PRF requires UV, so the key needs a FIDO2 PIN | Yubico PRF guide; WebAuthn L3 §prf |
| The toolbar popup is only protected against Chrome's own web-modal dialogs; OS sheets and Linux focus changes can close it; Bitwarden tells Linux users to pop the extension out first | `extension_popup.cc` L379-383; bitwarden.com/help/login-with-passkeys |
| Unverified, owner hand test needed: a phone (iPhone, Android) accepting a `chrome-extension://` RP ID over hybrid from Edge on Linux | none yet |

What the owner gets, per device:
- **Edge on the Z13 (Linux):** a phone over QR + Bluetooth, or a security key with a PIN. Not the
  camera, not a built-in passkey.
- **MacBook (Chrome/Edge, macOS 15+):** Touch ID through an iCloud Keychain passkey [Edge on Mac
  using iCloud Keychain: unverified].
- **iPhone / Android:** the phone is the authenticator for the desktop browser (the extension
  does not run on phones).

## Design

### Vault record v2 (lib/vault.js)

A random 32-byte data key (DEK) encrypts the payload. Each unlock method is a **slot** that
wraps the DEK with AES-256-GCM under its own key-encryption key (KEK).

```
{ v: 2, id: <16 random bytes, b64>,
  data: { iv, ct },                       // AES-GCM(DEK), AAD = canonical {"v":2,"id":...}
  slots: [
    { type: 'passphrase', kdf: { name:'PBKDF2', hash:'SHA-256', iterations, salt }, iv, wrapped },
    { type: 'passkey', cred: <credential rawId, b64url>, prfSalt: <32 bytes, b64>,
      label, createdAt, iv, wrapped }      // at most 5 passkey slots
  ] }
```

- Passphrase KEK = PBKDF2 exactly as v1 (600k default, same bounds). Exactly one passphrase slot.
- Passkey KEK = HKDF-SHA-256(ikm = PRF `first` output, salt = empty, info =
  "zauthenticator vault v2 passkey kek"). PRF input = the slot's random `prfSalt` (the browser
  already domain-separates it with "WebAuthn PRF").
- Slot AAD = canonical JSON of {v, id, type, and for passkeys cred, prfSalt, label, createdAt}.
  A slot moved to another vault, or edited, fails to unwrap.
- All structural checks run before any KDF or WebAuthn call (sizes: cred ≤ 1023 bytes, prfSalt
  = 32, wrapped = 48, label ≤ 64 chars, slots ≤ 6).
- The session key (`chrome.storage.session.vaultKey`) holds the DEK for v2 (the PBKDF2 key for
  v1); `open(rawKey, record)` and `seal()` dispatch on `v`, so the service worker's auto-fill
  path is unchanged.
- v1 records keep working unchanged. A vault becomes v2 only when the first passkey is enrolled.

### Flows

- **Enroll** (Settings → "Unlock with a passkey" → "Add a passkey"): opens the own window
  (`popup.html#passkey`). Re-enter the passphrase (an unlocked session alone must not be able to
  add a permanent way in). `create()` with `rp: {name}` (no `id`), random user id,
  `userVerification:'required'`, `residentKey:'discouraged'`, algs [-8, -7, -257],
  `extensions.prf.eval.first = prfSalt`. If PRF bytes came back, use them; if `prf.enabled` but no
  bytes, run `get()` once with the same salt; if PRF is not enabled, stop with "This passkey
  can't unlock zauthenticator" and leave the vault untouched. Then, under the vault Web Lock:
  re-read the record, build the new v2 record (fresh DEK when migrating from v1), **decrypt the
  new record in memory with both the passphrase slot and the passkey KEK, compare the payload**,
  only then save it and swap the session key to the DEK.
- **Unlock**: the locked view shows "Unlock with passkey" when the record has passkey slots. It
  opens the own window, which runs `get()` with `allowCredentials` = every slot's `cred`,
  `userVerification:'required'`, `prf.evalByCredential = {cred: prfSalt}`; finds the slot by
  `rawId`; requires the UV flag; unwraps; decrypts; stores the DEK; the toolbar popup refreshes.
  Any failure (cancel, no PRF bytes, unwrap failure) leaves the vault locked with a message; the
  passphrase field stays available.
- **Remove a passkey** (Settings, unlocked): drops the slot (the credential stays in the
  authenticator; the text says how to delete it there).
- **Backups**: export writes the record with passkey slots stripped (a backup opens with the
  passphrase only, anywhere). Import accepts v1 and v2 records.
- **Auto-fill** and idle lock: unchanged (they work on the session key).

### Trust gate

- `navigator.credentials` is allowed in exactly one new module (`popup/passkey.js`); the gate
  fails it anywhere else (content scripts, worker, lib). Pinned policy + self-test cases.
- Manifest: no new permission, CSP unchanged, `minimum_chrome_version` stays 116.

## Acceptance (owner-visible)

1. Settings → Add a passkey → after the OS prompt, the list shows the passkey; lock; the locked
   view's "Unlock with passkey" opens the vault after the prompt — e2e with CDP virtual
   authenticators (`hasPrf`, and `hasHmacSecret` without `-mc`), plus owner hand test on the Z13
   with a phone.
2. An authenticator without PRF is refused at enrollment and the stored record is byte-identical.
3. The passphrase still unlocks a v2 vault; a v1 vault without passkeys is never rewritten.
4. Removing the last passkey keeps the vault openable by passphrase; exported backups contain
   no passkey slot and import into a fresh install with the passphrase.
5. All gates green (unit incl. vault v2 tamper/limits, trust gate with the new rule, self-test,
   e2e), external review, README/PRIVACY/store disclosures updated.
