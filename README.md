# zauthentificator

An open-source TOTP (2FA code) authenticator for Chromium browsers such as Chrome and Edge
(Manifest V3). It makes no network requests, runs no remote or dynamic code, and keeps your
secrets encrypted at rest. Each of those properties can be checked from this repository.

You load it unpacked from a release zip or from a clone, so the code you run is the code you
read. It does not update itself.

## Trust properties and how to verify them

| Property | What it means | Verify it yourself |
|---|---|---|
| Zero network | The extension pages' CSP sets `connect-src 'none'`. The manifest has no host permissions. The source contains no `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource` or `sendBeacon`. | Read `content_security_policy` in `extension/manifest.json`. Run `npm run check`. `npm run e2e` calls `fetch('https://example.com/')` from the extension page, expects a CSP block, and fails on any http(s) request made during the run. |
| No remote or dynamic code | `script-src 'self'`, with no `unsafe-eval`, `unsafe-inline` or `wasm-unsafe-eval`. The source contains no `eval(`, `new Function`, inline `<script>` or `on*=` handlers. | `npm run check` |
| Encrypted at rest | Secrets are stored only inside an AES-GCM-256 vault. Its key is derived from your passphrase with PBKDF2-SHA-256 (600,000 iterations). `chrome.storage.local` holds only `{ v, kdf, iv, ct }`. | `npm run e2e` reads `chrome.storage` and the exported backup. It fails if a test secret appears as base32 (either case), hex, base64, base64url, a byte list or a raw byte string. You can also inspect storage in DevTools on the popup page. |
| Minimal permissions | `storage` and `activeTab` only. `activeTab` lets the extension capture the current tab for a QR scan, and only after you click the toolbar icon. | Read `permissions` in `extension/manifest.json`, or open the extension's Details page in the browser. `npm run check` fails on anything else. |
| Pinned third-party code | The only third-party code is the QR decoder (jsQR), vendored and pinned by sha256. Its license ships next to it. | `cd extension/vendor && sha256sum -c SHA256SUMS` (on macOS: `shasum -a 256 -c SHA256SUMS`). `npm run check` verifies the same hashes. |
| Readable source | Plain ES modules. No bundler, minifier or runtime npm dependencies. | Browse `extension/`. |

`npm run check` is the static trust gate (`scripts/check-policy.mjs`). It prints one
`PASS`/`FAIL` line per rule. `node scripts/check-policy.mjs --self-test` checks the gate itself:
it builds a clean extension and a set of broken ones, and confirms that each broken one fails
the rule it breaks. CI runs the unit tests, the gate, its self-test and the end-to-end test on
every push.

## Install

**From a release (recommended)**

1. Download `zauthentificator-<version>.zip` from the
   [Releases](https://github.com/2lab-ai/zauthentificator/releases) page. Check its sha256
   against the one in the release notes: `sha256sum zauthentificator-<version>.zip`.
2. Unzip it into a folder you will keep. The browser loads the extension from that folder.
3. Open `chrome://extensions` (or `edge://extensions`) and turn on **Developer mode**.
4. Click **Load unpacked** and select the unzipped folder, the one that contains `manifest.json`.

**From source**

```sh
git clone https://github.com/2lab-ai/zauthentificator.git
```

Then click **Load unpacked** and select the `extension/` folder.

To update, replace the folder's contents with a newer release and click the reload icon on the
extensions page. Your vault stays in the browser profile. Keep the same folder path: an unpacked
extension's id is derived from its path, so a different folder loads as a different extension
with an empty vault. Export a backup before you move the folder.

## Usage

1. **Create a passphrase** the first time you open the popup. It encrypts the vault.
2. **Add accounts** with one of these methods:
   - **Scan QR from tab**: scans an `otpauth://` QR code shown on the current page.
   - **Scan QR image**: decodes a QR code from an image file.
   - **otpauth URI**: paste one or more `otpauth://totp/...` URIs, one per line.
   - **Manual entry**: enter the issuer, label and base32 secret (SHA-1, 6 digits, 30 s by default).
3. **Copy a code**: click it to copy it to the clipboard. A countdown shows when the code changes.
4. **Lock** with the lock button. The popup then asks for the passphrase again.
5. **Back up** from Settings. Export downloads the encrypted vault record. Import restores it with
   that backup's passphrase.

## Security model and limits

- **The passphrase cannot be recovered.** If you forget it, the vault and every backup made with
  it are unreadable. Keep an exported backup and the passphrase somewhere safe.
- **The system clock is the only time source.** Network time sync would break the zero-network
  property. If codes are rejected, check that your computer's clock is correct.
- **There is no sync, by design.** Each browser profile has its own vault. To move accounts,
  export a backup and import it in the other profile.
- **Where the unlocked key lives:** after you unlock, the raw vault key is kept in
  `chrome.storage.session`. That storage is visible only to the extension's own pages and is held
  in memory. The key stays there until you press Lock or the browser session ends.
- **What it does not protect against:** malware running as your user, a compromised browser or
  browser profile, or someone using your unlocked browser session. Copied codes sit in the system
  clipboard, which other applications can read. A weak passphrase weakens the encryption of the
  stored vault and of exported backups.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

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
npm run zip                               # dist/zauthentificator-<version>.zip and its sha256
```

`npm run e2e` drives the popup through its DOM contract. It compares the displayed codes with
an independent TOTP implementation and checks that storage and the exported backup contain
only ciphertext. It also checks the lock and unlock flow and the blocked network. Screenshots
go to `test-results/`, or to the directory in `E2E_ARTIFACTS`.

Releases are cut by pushing a tag `v<version>` that matches `extension/manifest.json`. The
release workflow tests, runs the gate, builds the zip and publishes it with its sha256.

## Roadmap

- Auto-fill into OTP fields, bound to the exact origin (scheme, host and port), so a look-alike
  domain gets nothing. The plan is in [.prd/03-autofill.md](.prd/03-autofill.md).

## License

[MIT](LICENSE). The vendored QR decoder keeps its own license, shipped as
`extension/vendor/jsQR.LICENSE`.

## 한국어 요약

zauthentificator는 Chrome, Edge 같은 Chromium 브라우저용 오픈소스 TOTP(2단계 인증 코드)
확장 프로그램입니다(Manifest V3). 아래 신뢰 속성은 모두 이 저장소에서 직접 확인할 수 있습니다.

- **네트워크 없음**: CSP가 `connect-src 'none'`이고, 호스트 권한이 없으며, 소스에 네트워크 API가 없습니다. 확인 방법: `npm run check`, `npm run e2e`.
- **원격·동적 코드 없음**: `script-src 'self'`를 쓰고 `eval`, `new Function`, 인라인 스크립트가 없습니다.
- **저장 시 암호화**: 비밀값은 패스프레이즈에서 PBKDF2-SHA-256(600,000회)으로 만든 키를 쓰는 AES-GCM-256 금고 안에만 저장됩니다.
- **최소 권한**: `storage`와 `activeTab`만 씁니다.
- **외부 코드 고정**: QR 디코더(jsQR)는 sha256으로 고정해 함께 배포합니다. `extension/vendor`에서 `sha256sum -c SHA256SUMS`로 확인합니다.

**설치**: 릴리스에서 zip을 받아 sha256을 확인한 뒤 압축을 풉니다. `chrome://extensions`(또는
`edge://extensions`)에서 개발자 모드를 켜고, "압축해제된 확장 프로그램을 로드합니다"로 그
폴더를 선택합니다. 저장소를 클론했다면 `extension/` 폴더를 선택합니다.

**사용**: 처음 열 때 패스프레이즈를 만듭니다. 계정은 탭의 QR, QR 이미지, `otpauth://` URI,
수동 입력으로 추가합니다. 코드를 클릭하면 복사됩니다. 잠금 버튼으로 잠그고, 설정에서 암호화된
백업을 내보내고 가져옵니다.

**한계**: 패스프레이즈는 복구할 수 없습니다. 시간은 시스템 시계만 기준으로 합니다. 동기화는
의도적으로 없습니다. 잠금을 해제하면 키가 `chrome.storage.session`에 있다가, 잠그거나 브라우저
세션이 끝나면 사라집니다.

**개발**: `npm test`, `npm run check`, `npm run e2e`, `npm run zip`.
**로드맵**: 정확한 출처(origin)에 묶인 OTP 자동 입력([.prd/03-autofill.md](.prd/03-autofill.md)).
**라이선스**: MIT.
