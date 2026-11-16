# zauthenticator

An open-source TOTP (2FA code) authenticator for Chromium browsers such as Chrome and Edge
(Manifest V3). Extension pages cannot open network connections or load remote resources (CSP);
the static gate additionally bans URL strings and navigation sinks; the only pages the
extension opens are its own. It runs no remote or dynamic code and keeps your secrets encrypted
at rest. Each of those properties can be checked from this repository.

You load it unpacked from a release zip or from a clone, so the code you run is the code you
read. It does not update itself.

## Trust properties and how to verify them

| Property | What it means | Verify it yourself |
|---|---|---|
| No network connections | Extension pages cannot open network connections or load remote resources: their CSP is exactly `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. The manifest has no host permissions. The source contains no `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon` or WebRTC (`RTCPeerConnection`), and the stylesheet no `@import` or remote `url(`. | Read `content_security_policy` in `extension/manifest.json`. Run `npm run check`: it fails unless the CSP equals that policy exactly. `npm run e2e` calls `fetch('https://example.com/')` from the extension page, expects a CSP block, and fails on any http(s) request made during the run. |
| Opens only its own pages | CSP does not govern top-level navigation, so the static gate additionally bans URL strings and navigation sinks: `window.open`, assigning `location` or calling `location.assign`/`replace`, links with a `target` or an `href` outside the extension, forms with an `action` or `target`, frames and `<meta http-equiv="refresh">`. Tab opening is centralized in `extension/lib/nav.js`: its `openOwnView` opens only this extension's own popup views (`popup/popup.html#add-file` and `#settings`), and the gate pins that file by sha256. Everywhere else the gate rejects `chrome.windows` and every `chrome.tabs` method except `getCurrent` and `captureVisibleTab` (which open nothing), aliases of `chrome` included. These rules read source text: they are a tripwire, not a proof, and they cover the project's own files only — the vendored decoder in `extension/vendor/` is exempt from the source rules and is checked by hash against its upstream release instead (hash consistency, not a behavioural review of that code). | `npm run check`. `npm run e2e` is the browser-observed check: it records every page opened during the run in a real Chromium and fails if any of them shows a URL other than the extension's own pages or `about:blank`. |
| No remote or dynamic code | `script-src 'self'`, with no `unsafe-eval`, `unsafe-inline` or `wasm-unsafe-eval`. The source contains no `eval(`, `new Function`, `importScripts`, string timers, `javascript:` URLs, inline `<script>` or `on*=` handlers. | `npm run check` |
| Encrypted at rest | Secrets are stored only inside an AES-GCM-256 vault. Its key is derived from your passphrase with PBKDF2-SHA-256 (600,000 iterations). `chrome.storage.local` holds only `{ v, kdf, iv, ct }`. | `npm run e2e` reads `chrome.storage` and the exported backup. It fails if a test secret appears as base32 (either case), hex, base64, base64url, a byte list or a raw byte string, or if storage holds any key besides `local.vault` and `session.vaultKey`/`session.lastActiveAt`. You can also inspect storage in DevTools on the popup page. |
| Minimal permissions | `storage` and `activeTab` only, with no optional or host permissions. `activeTab` lets the extension capture the current tab for a QR scan, and only after you click the toolbar icon. There is no background script, content script or web-accessible resource. | Read `extension/manifest.json`, or open the extension's Details page in the browser. `npm run check` fails on any other permission and on manifest keys such as `background`, `content_scripts` or `web_accessible_resources`. |
| Pinned third-party code | The only third-party code is the QR decoder (jsQR 1.4.0), vendored unmodified and pinned by sha256. Its license ships next to it. See [Third-party code](#third-party-code) for where it comes from. | `cd extension/vendor && sha256sum -c SHA256SUMS` (on macOS: `shasum -a 256 -c SHA256SUMS`). `npm run check` verifies the same hashes, one entry per file, and that every vendored `.js` has a `.LICENSE` beside it. |
| Readable source | Plain ES modules. No bundler, minifier or runtime npm dependencies. | Browse `extension/`. |

`npm run check` is the static trust gate (`scripts/check-policy.mjs`). It reads the source text
and prints one `PASS`/`FAIL` line per rule; it is a tripwire for this repository's own code, not a
sandbox. `node scripts/check-policy.mjs --self-test` checks the gate itself: it builds a clean
extension and a set of broken ones, confirms that each broken one fails the rule it breaks, and
compares the gate's policy (permissions, forbidden manifest keys, homepage URL, CSP, the sha256 of
`extension/lib/nav.js` and the `chrome.tabs` methods allowed outside it) with a second copy
written out separately, so the policy cannot be widened by editing one place. CI
runs the unit tests, the gate, its self-test and the end-to-end test on every branch push and
pull request, and the release workflow runs the same CI job before it publishes.

## Install

**From a release (recommended)**

1. Download `zauthenticator-<version>.zip` from the
   [Releases](https://github.com/2lab-ai/zauthenticator/releases) page. Check its sha256
   against the one in the release notes: `sha256sum zauthenticator-<version>.zip`.
2. Unzip it into a folder you will keep. The browser loads the extension from that folder.
3. Open `chrome://extensions` (or `edge://extensions`) and turn on **Developer mode**.
4. Click **Load unpacked** and select the unzipped folder, the one that contains `manifest.json`.

**From source**

```sh
git clone https://github.com/2lab-ai/zauthenticator.git
```

Then click **Load unpacked** and select the `extension/` folder.

To update, replace the folder's contents with a newer release and click the reload icon on the
extensions page. Your vault stays in the browser profile. Keep the same folder path: an unpacked
extension's id is derived from its path, so a different folder loads as a different extension
with an empty vault. Export a backup before you move the folder.

**Uninstalling the extension deletes its vault.** Removing it from the extensions page deletes
its storage. Export a backup first if you may want your accounts back.

## Usage

1. **Create a passphrase** the first time you open the popup. It encrypts the vault.
2. **Add accounts** with one of these methods:
   - **Scan QR from tab**: scans an `otpauth://` QR code shown on the current page.
   - **Scan QR image**: decodes a QR code from an image file.
   - **otpauth URI**: paste one or more `otpauth://totp/...` URIs, one per line.
   - **Manual entry**: enter the issuer, label and base32 secret (SHA-1, 6 digits, 30 s by default).
3. **Copy a code**: click it to copy it to the clipboard. A countdown shows when the code changes.
4. **Lock** with the lock button. The vault stays unlocked until you press Lock, 15 minutes
   without use, or the browser fully quits (on macOS: Cmd+Q; closing its windows is not enough).
   After that the popup asks for the passphrase again.
5. **Back up** from Settings. Export downloads the encrypted vault record. Import restores it with
   that backup's passphrase.

## Security model and limits

- **The passphrase cannot be recovered.** If you forget it, the vault and every backup made with
  it are unreadable. Keep an exported backup and the passphrase somewhere safe.
- **Uninstalling deletes the vault.** See [Install](#install); export a backup first.
- **The system clock is the only time source.** Network time sync would need the network. If
  codes are rejected, check that your computer's clock is correct.
- **There is no sync, by design.** Each browser profile has its own vault. To move accounts,
  export a backup and import it in the other profile.
- **Where the unlocked key lives:** after you unlock, the raw vault key is kept in
  `chrome.storage.session`. That storage is visible only to the extension's own pages and is held
  in memory. It is cleared when you press Lock or when the browser fully quits (on macOS: Cmd+Q;
  closing its windows is not enough). After 15 minutes without use the vault counts as locked:
  with no extension page open nothing runs in the background, so the key stays in session
  storage until you next open the popup, which then locks before showing any code.
- **Offline guessing:** someone who can read your browser profile on disk, or one of your
  exported backups, can try to guess the passphrase offline. PBKDF2-SHA-256 with 600,000
  iterations makes each guess expensive, roughly thousands to tens of thousands of guesses per
  second per GPU (an order-of-magnitude estimate, not a measurement). That only slows guessing
  down: use a long passphrase, such as several random words.
- **Passphrases are NFC-normalized** before key derivation, so the same passphrase typed with
  composed or decomposed characters (accented letters, Hangul) opens the same vault.
- **What it does not protect against:** malware running as your user, a compromised browser or
  browser profile, or someone using your unlocked browser session. Copied codes sit in the system
  clipboard, which other applications can read. A weak passphrase weakens the encryption of the
  stored vault and of exported backups.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Third-party code

The QR decoder `extension/vendor/jsQR.js` is jsQR 1.4.0 (Apache-2.0), the file
`dist/jsQR.js` of the npm package `jsqr@1.4.0`, unmodified. Its license is the package's
`LICENSE`, shipped as `extension/vendor/jsQR.LICENSE`.

- npm registry integrity of `jsqr@1.4.0`:
  `sha512-dxLob7q65Xg2DvstYkRpkYtmKm2sPJ9oFhrhmudT1dZvNFFTlroai3AWSpLey/w5vMcLBXRgOJsbXpdN9HzU/A==`
- sha256 of `jsQR.js`: `bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859`

To check it yourself, from the repository root:

```sh
npm view jsqr@1.4.0 dist.integrity             # the registry's integrity, as above
npm pack jsqr@1.4.0 --json | grep integrity     # the downloaded tarball's integrity, as above
tar -xzf jsqr-1.4.0.tgz package/dist/jsQR.js package/LICENSE
shasum -a 256 package/dist/jsQR.js extension/vendor/jsQR.js           # both bc40c8a1...
shasum -a 256 package/LICENSE extension/vendor/jsQR.LICENSE           # identical
rm -r jsqr-1.4.0.tgz package
```

## Development

Requires Node.js 20 or later. There are no runtime dependencies. The only dev dependency is
`playwright`, pinned to an exact version.

```sh
npm ci
npm test                                  # unit tests (node --test): RFC 6238 vectors, base32, otpauth, vault
npm run check                             # static trust gate
node scripts/check-policy.mjs --self-test # proves the gate catches each violation
npx playwright install chromium           # once, for the e2e browser
npm run e2e                               # real Chromium + the unpacked extension (E2E_HEADLESS=1 for headless)
npm run zip                               # dist/zauthenticator-<version>.zip and its sha256
```

`npm run e2e` drives the popup through its DOM contract. It compares the displayed and the
copied codes with an independent TOTP implementation and checks that storage and the exported
backup contain only ciphertext. It checks the lock and unlock flow and the blocked network, two
pages adding accounts at the same time (both must be kept), a lock from one page reaching the
other and clearing what was typed there, the 15-minute idle lock, a copy made after the code's
period changed, and that no page outside the extension was opened. Screenshots go to
`test-results/`, or to the directory in `E2E_ARTIFACTS`. The copy checks put TOTP codes of test
secrets on the clipboard.

Releases are cut by pushing a tag `v<version>` that matches `extension/manifest.json`. The
release workflow checks the tag, runs the full CI job (unit tests, gate and self-test, Chromium
end-to-end test) on the tagged commit, builds the zip, checks that it unpacks to exactly
`extension/`, and publishes it with its sha256. Only the publishing job can write to the
repository, and every action is pinned by commit SHA.

## Roadmap

- Change the passphrase (re-encrypt the vault under a new one).
- Auto-fill into OTP fields, bound to the exact origin (scheme, host and port), so a look-alike
  domain gets nothing. The plan is in [.prd/03-autofill.md](.prd/03-autofill.md).

## License

[MIT](LICENSE). The vendored QR decoder keeps its own license, shipped as
`extension/vendor/jsQR.LICENSE`.

## 한국어 요약

zauthenticator는 Chrome, Edge 같은 Chromium 브라우저용 오픈소스 TOTP(2단계 인증 코드)
확장 프로그램입니다(Manifest V3). 아래 신뢰 속성은 모두 이 저장소에서 직접 확인할 수 있습니다.

- **네트워크 연결 없음**: 확장 페이지는 CSP 때문에 네트워크에 연결하거나 원격 리소스를 불러올 수 없습니다. CSP는 위에 적은 승인 정책과 정확히 같아야 하고, 호스트 권한이 없으며, 소스에 네트워크 API가 없습니다. 확인 방법: `npm run check`, `npm run e2e`.
- **자기 페이지만 엶**: CSP는 최상위 탐색(navigation)을 막지 않으므로, 정적 검사가 URL 문자열과 탐색 지점(`window.open`, `location` 대입, 확장 밖을 가리키는 링크·폼·프레임)을 추가로 금지합니다. 탭 열기는 `extension/lib/nav.js` 한 곳에 모여 있고(이 확장의 팝업 화면만 엶), 정적 검사가 이 파일을 sha256으로 고정하며 다른 파일의 `chrome.windows` 사용과 `getCurrent`·`captureVisibleTab` 외의 `chrome.tabs` 사용을 거부합니다. 이 검사는 소스 문자열을 읽는 경보장치(tripwire)일 뿐 증명이 아닙니다. 확장 밖 페이지가 열리지 않았다는 것은 `npm run e2e`가 실제 브라우저에서 실행 중 열린 모든 페이지를 기록해 확인합니다.
- **원격·동적 코드 없음**: `script-src 'self'`를 쓰고 `eval`, `new Function`, 인라인 스크립트가 없습니다.
- **저장 시 암호화**: 비밀값은 패스프레이즈에서 PBKDF2-SHA-256(600,000회)으로 만든 키를 쓰는 AES-GCM-256 금고 안에만 저장됩니다. 패스프레이즈는 NFC로 정규화한 뒤 키를 만듭니다.
- **최소 권한**: `storage`와 `activeTab`만 씁니다.
- **외부 코드 고정**: QR 디코더는 npm 패키지 `jsqr@1.4.0`의 `dist/jsQR.js`를 수정 없이 함께 배포하며 sha256으로 고정합니다(`bc40c8a1...`). `extension/vendor`에서 `sha256sum -c SHA256SUMS`로 확인하고, 출처는 `npm pack jsqr@1.4.0`으로 받은 파일과 해시를 비교해 확인합니다(위 "Third-party code" 참고).

**설치**: 릴리스에서 zip을 받아 sha256을 확인한 뒤 압축을 풉니다. `chrome://extensions`(또는
`edge://extensions`)에서 개발자 모드를 켜고, "압축해제된 확장 프로그램을 로드합니다"로 그
폴더를 선택합니다. 저장소를 클론했다면 `extension/` 폴더를 선택합니다. 확장 프로그램을 제거하면
금고도 함께 삭제되니, 먼저 백업을 내보내세요.

**사용**: 처음 열 때 패스프레이즈를 만듭니다. 계정은 탭의 QR, QR 이미지, `otpauth://` URI,
수동 입력으로 추가합니다. 코드를 클릭하면 복사됩니다. 설정에서 암호화된 백업을 내보내고
가져옵니다. 잠금 해제 상태는 잠금 버튼을 누르거나, 15분 동안 쓰지 않거나, 브라우저를 완전히
종료할 때까지 유지됩니다(macOS에서는 Cmd+Q, 창만 닫으면 종료되지 않습니다).

**한계**: 패스프레이즈는 복구할 수 없습니다. 시간은 시스템 시계만 기준으로 합니다. 동기화는
의도적으로 없습니다. 브라우저 프로필을 디스크에서 읽을 수 있는 사람이나 백업 파일을 가진 사람은
패스프레이즈를 오프라인으로 추측해 볼 수 있습니다. PBKDF2-SHA-256 600,000회는 추측을 GPU 한
대당 초당 수천~수만 번 정도(대략적인 규모의 추정)로 늦출 뿐이니 긴 패스프레이즈를 쓰세요.

**개발**: `npm test`, `npm run check`, `node scripts/check-policy.mjs --self-test`, `npm run e2e`, `npm run zip`.
**로드맵**: 패스프레이즈 변경, 정확한 출처(origin)에 묶인 OTP 자동 입력([.prd/03-autofill.md](.prd/03-autofill.md)).
**라이선스**: MIT.
