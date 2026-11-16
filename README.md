# zauthenticator

An open-source TOTP (2FA code) authenticator for Chromium browsers such as Chrome and Edge
(Manifest V3). Extension pages and its service worker cannot open network connections or load
remote resources (CSP); the static gate additionally bans URL strings and navigation sinks; the
only pages the extension opens are its own. It runs no remote or dynamic code and keeps your
secrets encrypted at rest. It can fill codes into web pages: on a site only after you choose an
account from the right-click menu there, and automatically only on the exact sites you allowed,
where the page receives the code and nothing else. Each of those properties can be checked from
this repository.

You load it unpacked from a release zip or from a clone, so the code you run is the code you
read. It does not update itself.

## Trust properties and how to verify them

| Property | What it means | Verify it yourself |
|---|---|---|
| No network connections | Extension pages and the service worker cannot open network connections or load remote resources: their CSP is exactly `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. Host access to a site (granted only when you allow auto-fill there) is used to run the content script on that site, not to make requests: the CSP blocks requests from extension pages and the worker to any host. The content script runs inside web pages, where the extension's CSP does not apply; it is held to the static gate's source rules and, on top of them, to a default-deny list of what it may touch: it reads the page's fields, fills the code field, dispatches `input` and `change`, watches for changes, sets timers and asks the worker for a code; it creates no element, writes no `src`, `href`, style or markup, and uses no `postMessage`, `window.name`, worker, dynamic `import()` or `chrome` API other than `chrome.runtime.sendMessage` and `chrome.runtime.id`. The function the worker injects into the page when you pick an account from the right-click menu (`fillFocused`) is held to the same list. These are text tripwires; the end-to-end egress check is what observes it. Two known limits: a registration object built in another module and imported into the worker is not read (the worker still needs its own `js:` list naming only the content script), and in the worker a `/` that could be division or a regular expression is guessed rather than refused, so a contrived one could hide a `js:`, `func:` or `files` from the scan. The source contains no `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon` or WebRTC (`RTCPeerConnection`), and the stylesheet no `@import` or remote `url(`. | Read `content_security_policy` in `extension/manifest.json`. Run `npm run check`: it fails unless the CSP equals that policy exactly, on those APIs in any file, the content script included, on anything the content script uses outside its allowed list, on a script registration that names any file other than `lib/fieldfind.js` and `content/autofill.js`, and on an injection of anything but `fillFocused` (no other `func:`, no `files`). `npm run e2e` calls `fetch('https://example.com/')` from an extension page and `fetch()` from the service worker, expects both blocked by the CSP, and fails on any http(s) request made during the run other than the test's own loads of its locally answered test pages. |
| Opens only its own pages | CSP does not govern top-level navigation, so the static gate additionally bans URL strings and navigation sinks: `window.open`, assigning `location` or calling `location.assign`/`replace`, links with a `target` or an `href` outside the extension, forms with an `action` or `target`, frames and `<meta http-equiv="refresh">`. Tab and window opening is centralized in `extension/lib/nav.js`: `openOwnView` opens only this extension's own popup views in a tab (`popup/popup.html#add-file` and `#settings`), `openOwnWindow` only its `#bind` and `#unlock` views in a small window, and the gate pins that file by sha256. Everywhere else the gate rejects `chrome.windows` and every `chrome.tabs` method except `getCurrent` and `captureVisibleTab` (which open nothing), aliases of `chrome` included. These rules read source text: they are a tripwire, not a proof, and they cover the project's own files only — the vendored decoder in `extension/vendor/` is exempt from the source rules and is checked by hash against its upstream release instead (hash consistency, not a behavioural review of that code). | `npm run check`. `npm run e2e` is the browser-observed check: it records every page opened during the run in a real Chromium and fails if any of them shows a URL other than the extension's own pages (its popup and the `#bind`/`#unlock` windows) or `about:blank`, except the locally answered test pages the auto-fill part opens itself. |
| No remote or dynamic code | `script-src 'self'`, with no `unsafe-eval`, `unsafe-inline` or `wasm-unsafe-eval`. The source contains no `eval(`, `new Function`, `importScripts`, string timers, `javascript:` URLs, inline `<script>` or `on*=` handlers. The content script is shipped in `extension/` like every other file and held to the same rules. | `npm run check` |
| Encrypted at rest | Secrets are stored only inside an AES-GCM-256 vault. Its key is derived from your passphrase with PBKDF2-SHA-256 (600,000 iterations). `chrome.storage.local` holds only `{ v, kdf, iv, ct }`. Which site fills which account (the auto-fill bindings) is stored inside the vault too. The browser itself records, outside the vault, which sites the extension may access and the match list of its registered content script, so those site names are readable from the browser profile. | `npm run e2e` reads `chrome.storage` and the exported backup. It fails if a test secret appears as base32 (either case), hex, base64, base64url, a byte list or a raw byte string, or if storage holds any key besides `local.vault` and `session.vaultKey`/`session.lastActiveAt`/`session.pendingBind` (the last only between an auto-fill offer and your answer), or if any lock leaves anything in session storage. You can also inspect storage in DevTools on the popup page. |
| Minimal permissions | `storage`, `activeTab`, `contextMenus` and `scripting`, plus optional host access for `https://*/*` that is granted one exact site at a time, only when you allow auto-fill for that site and accept the browser's own prompt. Nothing is granted for any site at install. `activeTab` lets the extension capture the current tab for a QR scan after you click the toolbar icon, and fill the field you right-clicked after you choose an account in the menu. `contextMenus` adds the right-click menu; `scripting` fills that field and registers the content script. There is a background service worker (the menu, and codes for bound sites) and one content script (`content/autofill.js`, with its field finder `lib/fieldfind.js`), registered at run time for the bound sites only: there are no content scripts in the manifest and no web-accessible resources. | Read `extension/manifest.json`, or open the extension's Details page in the browser (site access lists the sites you allowed). `npm run check` fails on any other permission, on `optional_host_permissions` other than exactly `["https://*/*"]`, on a `background` other than exactly the `background.js` module worker, and on manifest keys such as `host_permissions`, `content_scripts` or `web_accessible_resources`. It also fails on `chrome.scripting` anywhere but `lib/autofill-worker.js`, and on asking for or giving up site access (`chrome.permissions`) anywhere but that worker and the popup's bind view (`popup/popup.js`). |
| Auto-fill only where you allowed it | A site is bound by its exact origin (`https:`, host and port): a look-alike domain or a subdomain gets nothing. The content script is registered for the bound origins only. It asks the service worker for a code, and the worker answers only a request from this extension's own content script whose frame origin is bound, while the vault is unlocked and not idle. Only the 6–8 digit code reaches the page: never the secret, the account name or the key. Auto-fill fills an empty code field once per page load, never submits a form, and does not count as activity for the 15-minute lock. Finding the field is a heuristic (see [Auto-fill](#auto-fill)). | `npm run e2e` (part 3, on a test copy, see [Development](#development)): a menu fill types the reference code into the field and offers the site; Allow stores the binding in the vault and registers the script for exactly that origin; a later visit is filled, the same page on another origin is not and gets no script, a bound site framed by another site is filled only inside the frame; nothing is filled while locked or idle, after the binding is removed, or after its account is deleted; no form is submitted. |
| Pinned third-party code | The only third-party code is the QR decoder (jsQR 1.4.0), vendored unmodified and pinned by sha256. Its license ships next to it. See [Third-party code](#third-party-code) for where it comes from. | `cd extension/vendor && sha256sum -c SHA256SUMS` (on macOS: `shasum -a 256 -c SHA256SUMS`). `npm run check` verifies the same hashes, one entry per file, and that every vendored `.js` has a `.LICENSE` beside it. |
| Readable source | Plain ES modules. No bundler, minifier or runtime npm dependencies. | Browse `extension/`. |

`npm run check` is the static trust gate (`scripts/check-policy.mjs`). It reads the source text
and prints one `PASS`/`FAIL` line per rule; it is a tripwire for this repository's own code, not a
sandbox. `node scripts/check-policy.mjs --self-test` checks the gate itself: it builds a clean
extension and a set of broken ones, confirms that each broken one fails the rule it breaks, and
compares the gate's policy (permissions, optional host permissions, the background worker,
forbidden manifest keys, homepage URL, CSP, the sha256 of `extension/lib/nav.js`, the
`chrome.tabs` methods allowed outside it, and the files allowed to use `chrome.scripting` and
`chrome.permissions`) with a second copy written out separately, so the policy cannot be widened
by editing one place. CI
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
6. **Fill a code into a site**: right-click the code field on the site, choose **zauthenticator**
   and then the account. The current code is typed into that field; nothing is submitted. While
   the vault is locked the menu offers **Unlock zauthenticator…** instead. See [Auto-fill](#auto-fill).

## Auto-fill

- **Once per site.** After a menu fill on an `https:` site that is not bound yet, a small window
  asks whether to fill that account automatically on that exact site (for example
  `https://login.example.com`). **Allow** opens the browser's own prompt for access to that one
  site; only if you accept it is the binding stored, inside the encrypted vault. **Not now**, or
  declining the prompt, stores nothing.
- **Later visits.** On a bound site (the top page or any frame of that exact origin) the code
  field is filled once per page load while the vault is unlocked. The extension looks for, in
  order, a field marked `autocomplete="one-time-code"`, a field whose name, id, label or
  placeholder looks like a code field (OTP, 2FA, verification code, …), a short numeric field of 6–8
  characters, or a row of 6–8 one-character boxes. That is a heuristic: on an unusual page it may
  find nothing or the wrong field. It fills only an empty field and never submits a form.
- **What the site gets.** The code, typed into its page, exactly as if you had typed it. The
  page's own scripts can read it, as they could if you typed it. The secret, the account name
  and the vault key never reach the page.
- **Remove a site.** Settings → **Auto-fill sites** → **Remove**. The binding leaves the vault, the
  content script is no longer registered for that site, and the extension gives up its access
  to it. Deleting an account removes its bindings too.
- **Locked or idle.** Nothing is filled while the vault is locked or after 15 minutes without use.
  If the service worker was asleep when those 15 minutes passed, account names can stay in the
  right-click menu until its next event or a browser restart; choosing one then opens the unlock
  window instead of filling.

## Security model and limits

- **The passphrase cannot be recovered.** If you forget it, the vault and every backup made with
  it are unreadable. Keep an exported backup and the passphrase somewhere safe.
- **Uninstalling deletes the vault.** See [Install](#install); export a backup first.
- **The system clock is the only time source.** Network time sync would need the network. If
  codes are rejected, check that your computer's clock is correct.
- **There is no sync, by design.** Each browser profile has its own vault. To move accounts,
  export a backup and import it in the other profile.
- **Where the unlocked key lives:** after you unlock, the raw vault key is kept in
  `chrome.storage.session`. That storage is visible only to the extension's own pages and its
  service worker (never to the content script) and is held in memory. It is cleared when you
  press Lock or when the browser fully quits (on macOS: Cmd+Q; closing its windows is not
  enough). After 15 minutes without use the vault counts as locked. No timer runs for that, so
  the key stays in session storage until the next thing that reads it: opening the popup, a menu
  choice or an auto-fill request. That read locks the vault and clears session storage before
  any code is shown or filled.
- **Offline guessing:** someone who can read your browser profile on disk, or one of your
  exported backups, can try to guess the passphrase offline. PBKDF2-SHA-256 with 600,000
  iterations makes each guess expensive, roughly thousands to tens of thousands of guesses per
  second per GPU (an order-of-magnitude estimate, not a measurement). That only slows guessing
  down: use a long passphrase, such as several random words.
- **Passphrases are NFC-normalized** before key derivation, so the same passphrase typed with
  composed or decomposed characters (accented letters, Hangul) opens the same vault.
- **What it does not protect against:** malware running as your user, a compromised browser or
  browser profile, or someone using your unlocked browser session. Copied codes sit in the system
  clipboard, which other applications can read. A code filled into a site can be read by that
  site's scripts, including injected ones on a compromised site. A weak passphrase weakens the
  encryption of the stored vault and of exported backups.

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
other and clearing what was typed there, the 15-minute idle lock, that every lock leaves session
storage empty, a copy made after the code's period changed, and that no page outside the
extension was opened. Screenshots go to `test-results/`, or to the directory in `E2E_ARTIFACTS`.
The copy checks put TOTP codes of test secrets on the clipboard.

Part 3 (`e2e/autofill.e2e.mjs`, also runnable on its own) covers auto-fill on a test copy of the
extension built in a temporary directory. The copy differs in two manifest fields, both refused
by the gate: its service worker entry is `e2e/fixtures/background.test.js`, which runs the
shipped `background.js` unchanged and exposes the menu handler, because a click in the
browser's own context menu cannot be automated; and it holds the test sites (`otp.test`,
`evil.test`, `host.test`, answered locally, nothing leaves the machine) as required host
permissions, so the browser grants the bind request without its prompt. In the shipped
extension that access is optional and granted per site, so giving it up on removal is observable
only there. `node e2e/fixture-smoke.mjs` proves the harness mechanics the test relies on with
throwaway fixture extensions.

**Manual checks** (not automatable): the browser's permission prompt after **Allow**, the
right-click menu itself (its items, and that choosing one fills through `activeTab` on a site
the extension has no access to), and a site's access entry on the extension's Details page
before and after **Remove**.

Releases are cut by pushing a tag `v<version>` that matches `extension/manifest.json`. The
release workflow checks the tag, runs the full CI job (unit tests, gate and self-test, Chromium
end-to-end test) on the tagged commit, builds the zip, checks that it unpacks to exactly
`extension/`, and publishes it with its sha256. Only the publishing job can write to the
repository, and every action is pinned by commit SHA.

## Roadmap

- Change the passphrase (re-encrypt the vault under a new one).

## License

[MIT](LICENSE). The vendored QR decoder keeps its own license, shipped as
`extension/vendor/jsQR.LICENSE`.

## 한국어 요약

zauthenticator는 Chrome, Edge 같은 Chromium 브라우저용 오픈소스 TOTP(2단계 인증 코드)
확장 프로그램입니다(Manifest V3). 아래 신뢰 속성은 모두 이 저장소에서 직접 확인할 수 있습니다.

- **네트워크 연결 없음**: 확장 페이지와 서비스 워커는 CSP 때문에 네트워크에 연결하거나 원격 리소스를 불러올 수 없습니다. CSP는 위에 적은 승인 정책과 정확히 같아야 하고, 소스에 네트워크 API가 없습니다. 사이트 접근 권한(자동 입력을 허용한 사이트에만 부여)은 그 사이트에서 콘텐츠 스크립트를 실행하는 데만 쓰입니다. 콘텐츠 스크립트는 웹 페이지 안에서 돌기 때문에 확장의 CSP가 적용되지 않으며, 정적 검사의 소스 규칙(경보장치)과 e2e의 외부 요청 감시로만 확인합니다. 확인 방법: `npm run check`, `npm run e2e`.
- **자기 페이지만 엶**: CSP는 최상위 탐색(navigation)을 막지 않으므로, 정적 검사가 URL 문자열과 탐색 지점(`window.open`, `location` 대입, 확장 밖을 가리키는 링크·폼·프레임)을 추가로 금지합니다. 탭과 창 열기는 `extension/lib/nav.js` 한 곳에 모여 있고(이 확장의 팝업 화면을 탭으로, `#bind`·`#unlock` 화면을 작은 창으로만 엶), 정적 검사가 이 파일을 sha256으로 고정하며 다른 파일의 `chrome.windows` 사용과 `getCurrent`·`captureVisibleTab` 외의 `chrome.tabs` 사용을 거부합니다. 이 검사는 소스 문자열을 읽는 경보장치(tripwire)일 뿐 증명이 아닙니다. 확장 밖 페이지가 열리지 않았다는 것은 `npm run e2e`가 실제 브라우저에서 실행 중 열린 모든 페이지를 기록해 확인합니다(자동 입력 테스트가 직접 연, 로컬에서 응답하는 테스트 사이트는 제외).
- **원격·동적 코드 없음**: `script-src 'self'`를 쓰고 `eval`, `new Function`, 인라인 스크립트가 없습니다. 콘텐츠 스크립트도 같은 규칙으로 검사합니다.
- **저장 시 암호화**: 비밀값은 패스프레이즈에서 PBKDF2-SHA-256(600,000회)으로 만든 키를 쓰는 AES-GCM-256 금고 안에만 저장됩니다. 패스프레이즈는 NFC로 정규화한 뒤 키를 만듭니다. 어느 사이트에 어느 계정을 자동 입력할지(바인딩)도 금고 안에 저장됩니다. 다만 브라우저 자체가 확장이 접근할 수 있는 사이트 목록과 등록된 콘텐츠 스크립트의 대상 목록을 금고 밖에 기록합니다.
- **최소 권한**: `storage`, `activeTab`, `contextMenus`, `scripting`과, 사이트 하나씩 부여되는 선택적 `https://*/*` 접근 권한만 씁니다. 설치 시에는 어떤 사이트 권한도 없고, 자동 입력을 허용한 그 사이트(정확한 출처)에 대해서만 브라우저의 권한 창에서 동의할 때 부여됩니다. 백그라운드 서비스 워커(오른쪽 클릭 메뉴, 바인딩된 사이트용 코드)와 콘텐츠 스크립트 하나(`content/autofill.js`와 입력란 찾기 `lib/fieldfind.js`)가 있으며, 콘텐츠 스크립트는 바인딩된 출처에만 실행 중에 등록됩니다. 매니페스트에는 콘텐츠 스크립트도, 웹 접근 리소스도 없습니다.
- **허용한 사이트에만 자동 입력**: 사이트는 정확한 출처(`https:`, 호스트, 포트)로 묶이므로 비슷한 도메인이나 하위 도메인에는 아무것도 가지 않습니다. 서비스 워커는 금고가 열려 있고 15분 미사용 상태가 아니며 요청한 프레임의 출처가 바인딩되어 있을 때만 답합니다. 페이지로 가는 것은 6–8자리 코드뿐이고 비밀값·계정 이름·키는 가지 않습니다. 비어 있는 입력란만 채우고, 폼을 제출하지 않으며, 입력란 찾기는 추정(휴리스틱)입니다.
- **외부 코드 고정**: QR 디코더는 npm 패키지 `jsqr@1.4.0`의 `dist/jsQR.js`를 수정 없이 함께 배포하며 sha256으로 고정합니다(`bc40c8a1...`). `extension/vendor`에서 `sha256sum -c SHA256SUMS`로 확인하고, 출처는 `npm pack jsqr@1.4.0`으로 받은 파일과 해시를 비교해 확인합니다(위 "Third-party code" 참고).

**설치**: 릴리스에서 zip을 받아 sha256을 확인한 뒤 압축을 풉니다. `chrome://extensions`(또는
`edge://extensions`)에서 개발자 모드를 켜고, "압축해제된 확장 프로그램을 로드합니다"로 그
폴더를 선택합니다. 저장소를 클론했다면 `extension/` 폴더를 선택합니다. 확장 프로그램을 제거하면
금고도 함께 삭제되니, 먼저 백업을 내보내세요.

**사용**: 처음 열 때 패스프레이즈를 만듭니다. 계정은 탭의 QR, QR 이미지, `otpauth://` URI,
수동 입력으로 추가합니다. 코드를 클릭하면 복사됩니다. 설정에서 암호화된 백업을 내보내고
가져옵니다. 잠금 해제 상태는 잠금 버튼을 누르거나, 15분 동안 쓰지 않거나, 브라우저를 완전히
종료할 때까지 유지됩니다(macOS에서는 Cmd+Q, 창만 닫으면 종료되지 않습니다).

**자동 입력**: 사이트의 코드 입력란을 오른쪽 클릭해 **zauthenticator**에서 계정을 고르면 현재
코드가 그 입력란에 입력됩니다(제출하지 않음). 아직 바인딩되지 않은 `https:` 사이트라면 작은 창이
그 사이트에서 앞으로 자동 입력할지 묻고, **Allow**를 누른 뒤 브라우저 권한 창에서 동의해야만
바인딩이 저장됩니다. 이후 그 사이트를 열면 금고가 열려 있는 동안 입력란이 한 번 채워집니다.
사이트를 빼려면 설정 → **Auto-fill sites** → **Remove**를 누릅니다(바인딩 삭제, 스크립트 등록 해제,
그 사이트 접근 권한 반납). 계정을 지우면 그 계정의 바인딩도 함께 지워집니다. 브라우저 권한 창과
오른쪽 클릭 메뉴 자체는 자동화할 수 없어 직접 확인해야 합니다.

**한계**: 패스프레이즈는 복구할 수 없습니다. 시간은 시스템 시계만 기준으로 합니다. 동기화는
의도적으로 없습니다. 브라우저 프로필을 디스크에서 읽을 수 있는 사람이나 백업 파일을 가진 사람은
패스프레이즈를 오프라인으로 추측해 볼 수 있습니다. PBKDF2-SHA-256 600,000회는 추측을 GPU 한
대당 초당 수천~수만 번 정도(대략적인 규모의 추정)로 늦출 뿐이니 긴 패스프레이즈를 쓰세요.
사이트에 입력된 코드는 그 사이트의 스크립트가 읽을 수 있습니다(직접 입력했을 때와 같음).

**개발**: `npm test`, `npm run check`, `node scripts/check-policy.mjs --self-test`, `npm run e2e`, `npm run zip`.
**로드맵**: 패스프레이즈 변경.
**라이선스**: MIT.
