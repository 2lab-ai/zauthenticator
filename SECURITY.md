# Security policy

zauthentificator holds TOTP secrets, so it is built to keep a few guarantees: no network, no
remote or dynamic code, and encryption at rest. A break in any of them is a vulnerability.

## Reporting

Report privately through GitHub's private vulnerability reporting. On the repository's
**Security** tab, choose **Report a vulnerability**, or open
<https://github.com/2lab-ai/zauthentificator/security/advisories/new>.

Do not open a public issue or pull request for a vulnerability. Include the version or commit,
the browser and its version, the steps to reproduce, and what you observed.

Reports are handled on a best-effort basis. A fix ships as a new release, and the advisory is
published once that release is available.

## Scope

- The extension in `extension/` and the release zips built from it.
- The trust gate (`scripts/check-policy.mjs`), the end-to-end test, and the CI and release
  workflows, because they are what lets anyone check the guarantees.

Only the latest release is supported.

## What counts

- **Any network egress** from the extension: a request of any kind to any host, including
  through a CSP gap, a browser API that bypasses `connect-src`, or a navigation the extension
  triggers.
- **Secret exposure**: a TOTP secret, the passphrase or the vault key that is written
  unencrypted to `chrome.storage.local` or `chrome.storage.sync`, included in an export, made
  readable outside the extension's trusted contexts, or recoverable from the stored record
  without the passphrase.
- **CSP bypass or code injection**: running remote, inline or dynamically evaluated code in an
  extension page, for example through a crafted `otpauth://` URI, a QR code or a backup file.
- **Cryptographic weaknesses**: IV reuse, weakened key-derivation parameters, missing
  authentication of the ciphertext.
- **Gate or supply-chain bypass**: a change that breaks a guarantee but still passes
  `npm run check`, a vendored file that does not match `vendor/SHA256SUMS`, or a release zip
  whose contents differ from `extension/` at the tagged commit.

## Out of scope

- An attacker who already controls your operating system account, browser or browser profile,
  or who uses your session while the vault is unlocked.
- Weak or reused passphrases.
- Wrong codes caused by a wrong system clock. The system clock is the only time source.
- Codes read from the system clipboard after you copy them.
