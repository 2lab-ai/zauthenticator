# 01 — Spec: zauthentificator v0.1

Status: planned (2026-11-16)

## Problem

A browser 2FA (TOTP) extension holds the most valuable secrets a browser has: the seeds that
generate login codes. Closed-source store extensions ship minified builds, can phone home, and
auto-update to new code at any time. You cannot verify what you run, and you cannot pin it.

## Goal

An open-source Chrome/Edge (Chromium, Manifest V3) TOTP authenticator whose trust properties
are **mechanically checkable** from the repository:

1. **Zero network.** The extension makes no network requests. The extension-page CSP sets
   `connect-src 'none'`, the manifest has no host permissions, and a static gate fails the build
   on network APIs (`fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`).
2. **No remote or dynamic code.** No `eval`, `new Function`, remote scripts, or string timers.
   Vendored third-party code is pinned by sha256 and its license is shipped beside it.
3. **Encrypted at rest.** Secrets are stored only inside an AES-GCM-256 vault whose key is
   derived from a passphrase (PBKDF2-SHA-256, 600,000 iterations). Plaintext secrets never touch
   `chrome.storage.local` or `chrome.storage.sync`.
4. **Minimal permissions.** v0.1: `storage`, `activeTab` (QR capture of the current tab only after
   the user clicks the toolbar icon). Nothing else.
5. **Readable source.** Plain ES modules, no bundler, no minification, no runtime dependencies
   besides the pinned QR decoder.

## Non-goals (v0.1)

- Cloud backup, browser sync, accounts, telemetry, analytics, payments — never.
- Network time sync (it would break goal 1; the system clock is the time source).
- HOTP counters, Steam Guard, Google Authenticator `otpauth-migration://` import (later, if asked).
- Auto-fill into web pages — specified separately in [03-autofill.md](03-autofill.md) (planned).
- Chrome Web Store listing (the release artifact is a zip for "Load unpacked").

## Acceptance scenarios (run → observe)

| ID | Do | Observe |
|---|---|---|
| A1 | `npm test` | RFC 6238 Appendix B vectors pass for SHA-1/SHA-256/SHA-512 (each with its own seed length), base32 and otpauth parsing cases pass, vault round-trip passes, wrong passphrase fails. |
| A2 | `npm run check` | Policy gate passes: manifest permission allow-list, CSP contains `connect-src 'none'`, no network/dynamic-code APIs in `extension/` (vendored files verified by hash instead), vendored hash matches. |
| A3 | Load `extension/` unpacked in Chromium, open the popup, create a passphrase | Vault record appears in `chrome.storage.local` as ciphertext only (no base32 secret substring in storage). |
| A4 | Add an account from an `otpauth://` URI with a known secret | The popup shows a code equal to an independent TOTP implementation at the same timestamp, with a countdown. |
| A5 | Click the code | The code is copied to the clipboard. |
| A6 | Close the browser session (or press Lock), reopen popup | Popup asks for the passphrase; the wrong one is rejected, the right one shows the accounts. |
| A7 | From the extension page, attempt `fetch('https://example.com')` | Blocked by CSP (console reports a CSP violation; no request leaves). |
| A8 | Export backup → delete account → import backup with passphrase | The account comes back with the same code. |
| A9 | Scan QR from current tab (page shows an otpauth QR) | Account is added with the issuer/label from the QR. |
| A10 | Push tag `v0.1.0` | GitHub Actions publishes a release with `zauthentificator-0.1.0.zip`. |
