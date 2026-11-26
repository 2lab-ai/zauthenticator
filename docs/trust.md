# Verifying the trust claims

zauthenticator's [README](../README.md) and [privacy policy](../PRIVACY.md) make claims you can
check from this repository. `npm run check` is a static gate (`scripts/check-policy.mjs`) that
reads the source and prints one `PASS`/`FAIL` line per rule; `npm run e2e` loads the extension
into a real Chromium and observes what it does. CI runs the unit tests, the gate, the gate's
self-test and the end-to-end test on every push and pull request, and the release workflow runs
the same job on the tagged commit before it publishes the zip.

| Claim | How it is enforced | How to check |
|---|---|---|
| No network from the extension (passkey requests are made by the browser, not the extension; see [Passkey unlock](../PRIVACY.md#passkey-unlock-from-version-03)) | The CSP of extension pages and the worker is exactly `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. The source has no `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon` or `RTCPeerConnection`, and the stylesheet no `@import` or remote `url(`. The content script runs inside web pages, where that CSP does not apply; it is held to a default-deny list instead: it reads fields, fills the code field, dispatches `input`/`change`, watches for changes, sets timers and asks the worker for a code, and creates no element, writes no `src`/`href`/style/markup, and uses no `postMessage`, worker, dynamic `import()` or `chrome` API beyond `runtime.sendMessage` and `runtime.id`. The function injected for a menu fill (`fillFocused`) is held to the same list and writes only if the frame is still on the origin the menu was opened on. | Read `content_security_policy` in `extension/manifest.json`. `npm run check` fails unless the CSP equals that policy, and on any of those APIs in any file, the content script included. `npm run e2e` calls `fetch()` from an extension page and from the worker, expects both blocked, and fails on any http(s) request during the run other than its own locally answered test pages. |
| Opens only its own pages | CSP does not govern navigation, so the gate also bans URL strings and navigation sinks (`window.open`, assigning `location`, links or forms pointing outside, frames, meta refresh). Opening a tab or window is done only in `extension/lib/nav.js` (the extension's own views), which the gate pins by sha256; elsewhere `chrome.windows` and every `chrome.tabs` method but `getCurrent` and `captureVisibleTab` are refused. | `npm run check`. `npm run e2e` records every page opened during the run and fails on any URL other than the extension's own pages, `about:blank` and its own test pages. |
| No remote or dynamic code | `script-src 'self'` without `unsafe-eval`, `unsafe-inline` or `wasm-unsafe-eval`; no `eval(`, `new Function`, `importScripts`, string timers, `javascript:` URLs, inline scripts or `on*=` handlers. | `npm run check` |
| Encrypted at rest | AES-GCM-256 with a key from PBKDF2-SHA-256 (600,000 iterations) over the NFC-normalized passphrase. A vault created with a passphrase holds only `{ v, kdf, iv, ct }` in `chrome.storage.local`. Enrolling a passkey, changing the passphrase or removing it stores `{ v: 2, id, data: { iv, ct }, slots }` instead, and the vault keeps that format: the data is encrypted under a random DEK, and each slot wraps that DEK, under the passphrase key, under an HKDF-SHA-256 key from a passkey's PRF output (next to the passkey's credential ID, PRF salt, label and creation time), or, without a passphrase, under a non-extractable AES-GCM-256 device key that the browser keeps in the extension's IndexedDB (`zauthenticator-device`). Auto-fill sites are inside the vault. Outside the vault, the browser itself records the sites the extension was granted access to and the match list of its registered content script. While unlocked, `chrome.storage.session` holds the key (`vaultKey`), `lastActiveAt`, the end of an extended unlock time (`unlockedUntil`), a pending auto-fill offer (`pendingBind`) and `autofillServed` (bound origins and account ids with tab ids, TOTP period numbers and times; no codes, no secrets), unencrypted in the browser's session memory and removed on lock; `lockGen` holds 16 random, nonsecret bytes that every lock replaces. | `npm run e2e` reads storage and the exported backup, and fails if a test secret appears in base32, hex, base64(url), as a byte list or raw bytes, if storage holds any key besides `local.vault` and `session.vaultKey`/`lastActiveAt`/`unlockedUntil`/`pendingBind`/`autofillServed`/`lockGen`, or if a lock leaves anything in session storage but a 16-byte `lockGen`. After the passphrase is removed, it checks that the vault has a single device slot and that the IndexedDB key the slot names is a non-extractable AES-GCM key whose export is refused. |
| Minimal permissions | `storage`, `activeTab`, `contextMenus`, `scripting`, and optional `https://*/*` granted one site at a time. No `host_permissions`, no content scripts in the manifest, no web-accessible resources; the one content script (`content/autofill.js` with `lib/fieldfind.js`) is registered at run time for the allowed sites only. | `npm run check` fails on any other permission or host pattern, on those manifest keys, on a background other than the `background.js` module worker, on `chrome.scripting` outside `lib/autofill-worker.js`, and on `chrome.permissions` outside that file and `popup/popup.js`. |
| Auto-fill only where you allowed it | Sites are bound by exact origin. The worker answers only this extension's own content script, from a frame whose origin is bound, while the vault is unlocked and not idle, and answers with the code and how long it stays valid, never account names or secrets. Auto-fill never submits a form and does not count as activity for the 15-minute lock. | `npm run e2e` part 3: a menu fill types the reference code; **Allow** stores the binding and registers the script for that origin only; a later visit is filled; another origin with the same page, a locked or idle vault, a removed site and a deleted account get nothing; no form is submitted. |
| Pinned third-party code | The only third-party code is two QR libraries, vendored unmodified and pinned by sha256 in `extension/vendor/SHA256SUMS`, each with its license beside it: the decoder jsQR 1.4.0 and the encoder qrcode-generator 2.0.4. | `cd extension/vendor && shasum -a 256 -c SHA256SUMS`; `npm run check` verifies the same. See [Third-party code](#third-party-code). |

## Limits of these checks

The gate reads source text: it is a tripwire for this repository's own files, not a proof, and the
vendored libraries are checked by hash only (consistency with their upstream releases, not a review
of their behaviour). Two known gaps: outside the content script, a `/` that could be division or a
regular expression is guessed rather than refused, so a contrived one could hide a `js:`, `func:`,
`files` or `css`, an alias of `chrome.scripting`, a call's options, a rebinding of `fillFocused` or
a global-object access from the scan; and an expression that yields the global object without
naming it (such as `document.defaultView`, `globalThis.valueOf()`, `event.view`, or `this` in an
event listener) can still be indexed by a computed name, which checks that read `chrome.` by its
spelling do not see. The end-to-end test, which observes the requests made and the pages opened
during its run, is the backstop.

`node scripts/check-policy.mjs --self-test` checks the gate itself: each deliberately broken copy
of the extension must fail the rule it breaks, and the gate's policy is compared with a second copy
written out separately, so it cannot be widened by editing one place.

Three things cannot be automated and are checked by hand: the browser's permission prompt after
**Allow**, the right-click menu itself (including a fill on a site the extension has no access
to), and a site's entry on the extension's details page before and after **Remove**.

## Third-party code

`extension/vendor/jsQR.js` is jsQR 1.4.0 (Apache-2.0), the QR decoder: the file `dist/jsQR.js` of
the npm package `jsqr@1.4.0`, unmodified. Its license ships as `extension/vendor/jsQR.LICENSE`.

- npm registry integrity of `jsqr@1.4.0`:
  `sha512-dxLob7q65Xg2DvstYkRpkYtmKm2sPJ9oFhrhmudT1dZvNFFTlroai3AWSpLey/w5vMcLBXRgOJsbXpdN9HzU/A==`
- sha256 of `jsQR.js`: `bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859`

`extension/vendor/qrcode.js` is qrcode-generator 2.0.4 (MIT, Kazuhiko Arase), the QR encoder that
draws export QR codes: the file `dist/qrcode.js` of the npm package `qrcode-generator@2.0.4`,
unmodified. The npm package carries no license file, so `extension/vendor/qrcode.LICENSE` is the
MIT license from the upstream repository (github.com/kazuhikoarase/qrcode-generator).

- npm registry integrity of `qrcode-generator@2.0.4`:
  `sha512-mZSiP6RnbHl4xL2Ap5HfkjLnmxfKcPWpWe/c+5XxCuetEenqmNFf1FH/ftXPCtFG5/TDobjsjz6sSNL0Sr8Z9g==`
- sha256 of `qrcode.js`: `79ec86f82856005b1c887905cfccfcfbec3821ca61c7fd5a952faa5f778f791c`

To check them yourself, from the repository root:

```sh
npm view jsqr@1.4.0 dist.integrity             # the registry's integrity, as above
npm pack jsqr@1.4.0 --json | grep integrity     # the downloaded tarball's integrity, as above
tar -xzf jsqr-1.4.0.tgz package/dist/jsQR.js package/LICENSE
shasum -a 256 package/dist/jsQR.js extension/vendor/jsQR.js           # both bc40c8a1...
shasum -a 256 package/LICENSE extension/vendor/jsQR.LICENSE           # identical
rm -r jsqr-1.4.0.tgz package

npm view qrcode-generator@2.0.4 dist.integrity                # as above
npm pack qrcode-generator@2.0.4 --json | grep integrity        # as above
tar -xzf qrcode-generator-2.0.4.tgz package/dist/qrcode.js
shasum -a 256 package/dist/qrcode.js extension/vendor/qrcode.js       # both 79ec86f8...
rm -r qrcode-generator-2.0.4.tgz package
```
