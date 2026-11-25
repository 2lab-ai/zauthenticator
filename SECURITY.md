# Security policy

zauthenticator holds TOTP secrets, so it is built to keep a few guarantees: extension pages and
its service worker open no network connections and load no remote resources, its content script
makes no requests either, the extension opens no pages other than its own, it runs no remote or
dynamic code, secrets are encrypted at rest, and auto-fill gives a code, and only a code, to the
exact sites you allowed. A break in any of them is a vulnerability.

## Reporting

Report privately through GitHub's private vulnerability reporting. On the repository's
**Security** tab, choose **Report a vulnerability**, or open
<https://github.com/2lab-ai/zauthenticator/security/advisories/new>.

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
  through a CSP gap, a browser API that bypasses `connect-src`, a request made from the content
  script inside a web page (where the extension's CSP does not apply), or a navigation the
  extension triggers.
- **Opening a page outside the extension**: a tab, window or navigation to anything other than
  the extension's own pages, for example through a navigation sink that `npm run check` misses.
- **Secret exposure**: a TOTP secret, the passphrase or the vault key that is written
  unencrypted to `chrome.storage.local` or `chrome.storage.sync`, included in an export, made
  readable outside the extension's trusted contexts (its pages and service worker; the content
  script and web pages are outside), or recoverable from the stored record without the
  passphrase. Exceptions by design, from version 0.4: a vault whose owner removed the passphrase
  opens with the browser's device key, so anyone who can use or copy that browser profile can
  open it; and **Export accounts** shows or copies the secrets as otpauth links and QR codes when
  the owner asks.
- **Auto-fill to the wrong place**: a code delivered to a page or frame whose exact origin you did
  not bind (a look-alike or a subdomain included), a code delivered while the vault is locked or
  idle, anything other than the code (a secret, an account name, the key) reaching a page, a
  binding stored or site access granted without your **Allow** and the browser's own prompt, the
  content script running on a site that is not bound, or a form submitted by the extension.
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
- A bound site reading the code that was filled into it, which is what auto-fill is for, including
  scripts injected into that site.
- Field-detection misses: a bound page whose code field is not found, or where a different empty
  field of that page is filled. Detection is a heuristic; report these as ordinary bugs.
