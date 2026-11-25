# zauthenticator

An open-source authenticator for Chrome and Edge: it shows your two-factor (TOTP) login codes in
the browser and keeps the secrets behind them on your device.

- **Open source, readable.** MIT license. Plain JavaScript with no bundler, no minifier and no
  npm dependencies at run time (one vendored QR decoder, pinned by hash), so you can read what
  runs.
- **Codes are made on your device**, from the secret key and your computer's clock.
- **No account, no vault sync, no telemetry.** The extension's own pages and its background worker
  cannot connect to any server.
- **Encrypted with your passphrase.** Secrets are stored only inside an encrypted vault, and the
  passphrase itself is never stored. From version 0.3 you can also unlock with a passkey; the
  passphrase keeps working.
- **Optional auto-fill, one site at a time.** You choose the sites. A site gets the 6–8 digit
  code and nothing else.

<img src="docs/images/popup-list.png" width="360" alt="The zauthenticator popup listing accounts and their current codes">

[한국어 안내](#한국어) · [Privacy policy](PRIVACY.md) · [Security policy](SECURITY.md)

## Install

**From a store** (the easiest way; the browser keeps it updated):

- Chrome Web Store: coming soon (the link will be added here once the listing is live)
- Microsoft Edge Add-ons: coming soon (the link will be added here once the listing is live)

**Manually, from a release** (you run exactly the files you downloaded; nothing updates them):

1. Download `zauthenticator-<version>.zip` from
   [Releases](https://github.com/2lab-ai/zauthenticator/releases). The release notes give its
   sha256 if you want to check the download.
2. Unzip it into a folder you will keep. The browser loads the extension from that folder.
3. Open `chrome://extensions` or `edge://extensions` and turn on **Developer mode**.
4. Click **Load unpacked** and pick the unzipped folder (the one that contains `manifest.json`).

To update a manual install, replace the folder's contents with the new release and click the
reload icon on the extensions page. Keep the same folder: the browser derives the extension's id
from the folder's path, so a different folder loads as a different extension with an empty vault.

Things to know before you move or remove it:

- **A store install and a manual install are separate extensions** with separate vaults. To move
  your accounts, export a backup from one and import it into the other (see
  [Back up and restore](#back-up-and-restore)).
- **Uninstalling deletes the vault.** Export a backup first if you may want your accounts back.

## Use

### Set a passphrase

The first time you open the popup, you choose a passphrase of 8 characters or more. It encrypts
your accounts. **It cannot be recovered**: if you forget it, the saved accounts cannot be opened
(from version 0.3, unless a passkey you enrolled still works), and the extension cannot import
your backups, because import asks for the passphrase the backup was made with.

### Unlock with a passkey (from version 0.3)

From version 0.3 you can unlock with a passkey instead of typing the passphrase. The passphrase
keeps working and stays the way back in if the passkey is lost.

- **What you need.** An authenticator that supports the WebAuthn PRF extension with user
  verification, such as a phone reached through the browser's QR code flow, a security key with a
  PIN, or a computer's built-in passkey store. An iPhone saving to Apple Passwords works through
  that phone flow with Edge on Linux. One tested Android phone saving to Samsung Pass returned no
  PRF value, so enrollment with that combination is refused; other Android passkey providers have
  not been tested. Mac and security-key setups follow the browser documentation and have not been
  tested by the maintainer.
- **Enroll.** Open **Settings** in a full tab (in the toolbar popup, the passkey section only
  offers to open it in a tab) and add a passkey. Enter your passphrase again; it is checked before
  anything else. The browser then asks twice: once to create the passkey and once to use it, so
  the extension can check that it returns the PRF value. If anything fails, nothing is saved, but
  the passkey may already exist on your phone or key; delete it there if you do not want it.
- **Unlock.** When the vault is locked, the popup offers to unlock with the passkey. That opens a
  separate unlock window (the toolbar popup closes when the browser's passkey dialog takes focus),
  where you confirm. If it fails, the vault stays locked and the passphrase still works.
- **One enrollment per installation.** A passkey is bound to the extension's ID, which differs
  between the store versions and a manual install. Enroll in each one separately.
- **Remove.** Removing the passkey in **Settings** removes it from this vault only. Delete the
  passkey on your phone, key or password manager too. Older copies of the vault, such as a copied
  browser profile, keep their passkey slot.
- **Version compatibility.** Enrolling a passkey converts the vault to the 0.3 format. Version
  0.2.0 cannot open a converted vault, and cannot import a backup exported from it: those exports
  are in the 0.3 format too, even though they leave the passkey out. Removing the passkey later
  does not convert the vault back. A vault that never had a passkey stays in the 0.2.0 format, and
  0.2.0 can open it and import its backups. **Export a backup before you enroll**, so you keep a
  copy that 0.2.0 can read.

### Add an account

Click **Add account** and use whichever your service gives you:

- **A QR code on the current page.** Open the page that shows the QR code, click the
  zauthenticator icon in the toolbar, and choose to scan this page. Only the visible part of the
  tab is read.
- **A QR code image.** Choose, drop or paste a screenshot or saved picture of the QR code.
- **An `otpauth://` link.** Paste one or more links, one per line.
- **A setup key.** Type the service, the account name and the secret key. The defaults (SHA-1,
  6 digits, 30 seconds) suit most services; **Advanced** changes them.

### Copy a code

Click a code to copy it. A countdown shows when the next code starts.

### Fill a code into a site

1. On the site, right-click the code field, choose **zauthenticator**, then the account. The
   current code is typed into that field. Nothing is submitted.
2. The first time you do this on an `https` site, a small window asks whether to fill this
   account's code automatically on that exact site. Click **Allow**, then accept the browser's
   own prompt for access to that one site. **Not now**, or declining the prompt, stores nothing.
3. On later visits, while zauthenticator is unlocked, the code field is filled for you.

After a fill, until you submit:

- **The code is kept current, once.** When the filled code expires, it is replaced with the new
  one, one time.
- **A rejected code is replaced once.** If the site rejects the code, a fresh one is filled once;
  the same code is never filled twice.
- **It is capped.** In one tab, a site gets at most 3 codes in 5 minutes.
- **It stops** as soon as you type or delete in the field yourself, when you leave the page, or
  when zauthenticator locks. It never submits a form.

<img src="docs/images/popup-autofill-bind.png" width="400" alt="The window that asks whether to fill codes automatically on a site">

Auto-fill works only on the exact site you allowed: the same scheme, host and port, on the page
itself or in a frame of that site inside another page. A subdomain or a look-alike domain gets
nothing. It fills only fields marked as a code field: a field the site
marks as a one-time code, a field whose name or label says OTP, 2FA, verification code and the
like, or a row of 6–8 one-character boxes labelled as a code. Fields that merely look like a code,
such as a PIN or a postal code, are left alone; use the right-click menu for those. Finding the
field is a best guess, so on an unusual page it may find nothing, or the wrong field.

To stop auto-fill on a site, open **Settings**, find the site under auto-fill sites and click
**Remove**. The extension also gives up its access to that site. Deleting an account removes its
sites too.

### Back up and restore

In **Settings**, **Export encrypted backup** saves a `.json` file. It is your vault as stored,
still encrypted with your passphrase (from version 0.3, without the passkey; see below). To
restore, choose the file under **Import a backup** and enter the passphrase that backup was made
with. Import adds the backup's accounts (duplicates are skipped); auto-fill sites are not
imported, so set them again from the right-click menu.

From version 0.3:

- A backup of a vault with a passkey leaves the passkey out, and importing a backup never adds
  a passkey. Such a backup is in the 0.3 format, so version 0.2.0 cannot import it (see
  [version compatibility](#unlock-with-a-passkey-from-version-03)).
- The passphrase is how the extension imports a backup, not the only key that can decrypt it.
  The backup's accounts are encrypted under the same data key (DEK) as the vault it came from,
  and leaving the passkey out of the backup, or removing the passkey from the vault, does not
  change that key. Someone who holds the DEK can decrypt the backup, and data the vault encrypts
  later under the same DEK, without the passphrase: for example someone with an older copy of the
  vault that still has the passkey slot together with the matching authenticator and its user
  verification, or someone who took the DEK from an unlocked session.
- Backups exported before you enrolled use your earlier passphrase key, because enrolling draws a
  new DEK.

### Lock

Click **Lock** to lock right away. zauthenticator also locks after 15 minutes without use, and
when the browser fully quits (on macOS, Cmd+Q; closing the windows is not enough). While it is
locked nothing is filled, and the right-click menu offers **Unlock zauthenticator…** instead of
your accounts.

<img src="docs/images/popup-locked.png" width="360" alt="The locked popup asking for the passphrase">

## Privacy and security

**What stays on your device.** Your secret keys, account names and auto-fill sites are stored in
the browser's storage for this extension, inside a vault encrypted with a key made from your
passphrase. The passphrase is never stored. After you unlock, the key is held in the browser's
session memory until you lock or the browser quits; after 15 minutes without use it is removed
the next time anything asks for it (see the limits below). While it is unlocked, session memory
also holds a small auto-fill record: for each tab and allowed site that got a code, the tab
number, the site's address, the account's internal id, which code period it was (the TOTP
counter) and when; never a code. It exists only so that a site gets at most 3 codes per tab
in 5 minutes and never the same code twice. Entries older than 5 minutes no longer count and are
dropped the next time the record changes; choosing an account from the right-click menu clears
that tab and site; locking removes the whole record. Nothing is sent to the developer or anyone
else; there is no server.

**From version 0.3, with a passkey.** Enrolling a passkey re-encrypts the vault under a random
data key (DEK). The DEK is stored twice, each copy encrypted: once with a key made from your
passphrase (PBKDF2, as before) and once with a key derived (HKDF) from a value your authenticator
computes only after verifying you (the WebAuthn PRF output). Next to the encrypted data, the vault
then also holds, readable to anyone who can read your browser profile: the passkey's credential
ID, the random input sent to the authenticator (PRF salt), the label you gave it, when it was
added, and the encrypted DEK with its IV. It never holds the PRF output or the DEK in plain form,
and your secrets stay encrypted. Session memory holds the unlocked key together with the vault's
version and identity, plus a random, nonsecret lock counter (`lockGen`) that each lock replaces
instead of removing, so a passkey request started before a lock cannot unlock afterwards.

**What passkey unlock involves outside the extension (from version 0.3).** The extension's pages
still cannot connect to any server; the passkey requests are made by the browser. It sends the
extension's ID (as the relying party), the credential ID, a challenge and the PRF salt to your
authenticator, which may be a phone reached through the browser's QR code flow. Your passkey
provider may sync the passkey to your other devices, independently of the extension. Your TOTP
secrets and the vault's contents are never sent.

**What it reads from web pages.** Only when you click the button to scan
the current page, the extension takes one picture of the visible part of that tab (the browser
allows this for the tab where you just clicked the toolbar icon). The picture is decoded in the
popup by the bundled QR decoder and held in memory only for that; it is never stored or sent.
Only the account found in it, if it is a valid two-factor QR code, is added to your vault. On a
site where you allowed auto-fill, the auto-fill script reads the attributes of the page's input
fields (such as name, label and placeholder) to find the code field, and keeps none of it.

**What the browser itself records.** Outside the encrypted vault, the browser keeps the list of
sites you gave the extension access to (shown on the extension's details page) and the list of
sites its auto-fill script is registered for. Someone who can read your browser profile can see
those site names. If you installed from a store, the browser checks that store for updates, as it
does for every extension installed from there.

**What a site receives.** Only the 6–8 digit code, typed into its page: on a site you allowed, or
in the field you right-clicked. The site's scripts can read it, just as if you had typed it. The
secret key, the account name and your passphrase never reach the page.

**Permissions and why they are needed:**

| Permission | What it lets the extension do | Why |
|---|---|---|
| `storage` | Keep data in the browser's storage for this extension | To save the encrypted vault, and the unlocked key for the browser session |
| `activeTab` | Use the current tab, only right after you click the toolbar icon or choose an account in the right-click menu | To scan a QR code on the page you are looking at, and to type a code into the field you right-clicked |
| `contextMenus` | Add an item to the right-click menu of text fields | To let you choose which account's code to fill |
| `scripting` | Run the extension's own fill code in a page | To type the code into the field, and to register auto-fill for the sites you allowed |
| Access to `https` sites (optional) | Run the auto-fill script on a site | Nothing is granted at install. The browser asks you for one exact site when you click **Allow**, and the access is removed when you remove that site |

**Limits worth knowing:**

- The passphrase cannot be recovered, and it cannot be changed. Restoring a backup
  in the extension asks for the passphrase it was made with: a backup protects you against losing
  the device or the browser profile, not against forgetting the passphrase. From version 0.3, a
  backup shares the vault's DEK, so it is not isolated from anyone who holds that key (see
  [Back up and restore](#back-up-and-restore)).
- The computer's clock is the only time source. If codes are rejected, make sure the date and
  time are set automatically.
- There is no vault sync, by design. Each browser profile has its own vault; use export and import
  to move accounts. Passkey providers may independently sync passkeys.
- Someone who gets a copy of your browser profile or of a backup file can try to guess the
  passphrase offline. The key derivation makes each guess slow, but a long passphrase (several
  random words) is what keeps it out of reach. From version 0.3, a profile copy that holds a
  passkey slot also opens with the matching authenticator and its user verification.
- It does not protect against malware running as your user, a compromised browser or profile, or
  someone using your browser while it is unlocked. Copied codes sit in the system clipboard,
  where other applications can read them.
- No timer runs for the 15-minute lock. The unlocked key stays in the browser's session memory
  until the next thing that reads it (opening the popup, a menu choice or an auto-fill request);
  that read locks the vault and clears the key before any code is shown or filled. In the same
  way, if the browser's background worker was asleep when the 15 minutes passed, account names
  can stay in the right-click menu until it next wakes; choosing one then opens the unlock window
  instead of filling.

Full details: [Privacy policy](PRIVACY.md) · [Security policy and how to report a vulnerability](SECURITY.md) ·
[Verifying the trust claims](#verifying-the-trust-claims).

## Verifying the trust claims

The claims above can be checked from this repository. `npm run check` is a static gate
(`scripts/check-policy.mjs`) that reads the source and prints one `PASS`/`FAIL` line per rule;
`npm run e2e` loads the extension into a real Chromium and observes what it does. CI runs the unit
tests, the gate, the gate's self-test and the end-to-end test on every push and pull request, and
the release workflow runs the same job on the tagged commit before it publishes the zip.

| Claim | How it is enforced | How to check |
|---|---|---|
| No network from the extension (from version 0.3, passkey requests are made by the browser, as described above) | The CSP of extension pages and the worker is exactly `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. The source has no `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon` or `RTCPeerConnection`, and the stylesheet no `@import` or remote `url(`. The content script runs inside web pages, where that CSP does not apply; it is held to a default-deny list instead: it reads fields, fills the code field, dispatches `input`/`change`, watches for changes, sets timers and asks the worker for a code, and creates no element, writes no `src`/`href`/style/markup, and uses no `postMessage`, worker, dynamic `import()` or `chrome` API beyond `runtime.sendMessage` and `runtime.id`. The function injected for a menu fill (`fillFocused`) is held to the same list and writes only if the frame is still on the origin the menu was opened on. | Read `content_security_policy` in `extension/manifest.json`. `npm run check` fails unless the CSP equals that policy, and on any of those APIs in any file, the content script included. `npm run e2e` calls `fetch()` from an extension page and from the worker, expects both blocked, and fails on any http(s) request during the run other than its own locally answered test pages. |
| Opens only its own pages | CSP does not govern navigation, so the gate also bans URL strings and navigation sinks (`window.open`, assigning `location`, links or forms pointing outside, frames, meta refresh). Opening a tab or window is done only in `extension/lib/nav.js` (the extension's own views), which the gate pins by sha256; elsewhere `chrome.windows` and every `chrome.tabs` method but `getCurrent` and `captureVisibleTab` are refused. | `npm run check`. `npm run e2e` records every page opened during the run and fails on any URL other than the extension's own pages, `about:blank` and its own test pages. |
| No remote or dynamic code | `script-src 'self'` without `unsafe-eval`, `unsafe-inline` or `wasm-unsafe-eval`; no `eval(`, `new Function`, `importScripts`, string timers, `javascript:` URLs, inline scripts or `on*=` handlers. | `npm run check` |
| Encrypted at rest | AES-GCM-256 with a key from PBKDF2-SHA-256 (600,000 iterations) over the NFC-normalized passphrase. For a vault that has never enrolled a passkey, `chrome.storage.local` holds only `{ v, kdf, iv, ct }`. From version 0.3, enrolling a passkey stores `{ v: 2, id, data: { iv, ct }, slots }`, and the vault keeps that format after the passkey is removed: the data is encrypted under a random DEK, and `slots` holds that DEK wrapped once under the passphrase key and once under an HKDF-SHA-256 key from the passkey's PRF output, next to the passkey's credential ID, PRF salt, label and creation time. Auto-fill sites are inside the vault. Outside the vault, the browser itself records the sites the extension was granted access to and the match list of its registered content script; while unlocked, `chrome.storage.session.autofillServed` holds bound origins and account ids (with tab ids, TOTP period numbers and times; no codes, no secrets) unencrypted in the browser's session memory, removed on lock; and from version 0.3, `chrome.storage.session.lockGen` holds 16 random, nonsecret bytes that every lock replaces. | `npm run e2e` reads storage and the exported backup, and fails if a test secret appears in base32, hex, base64(url), as a byte list or raw bytes, if storage holds any key besides `local.vault` and `session.vaultKey`/`lastActiveAt`/`pendingBind`/`autofillServed`/`lockGen`, or if a lock leaves anything in session storage but a 16-byte `lockGen`. |
| Minimal permissions | `storage`, `activeTab`, `contextMenus`, `scripting`, and optional `https://*/*` granted one site at a time. No `host_permissions`, no content scripts in the manifest, no web-accessible resources; the one content script (`content/autofill.js` with `lib/fieldfind.js`) is registered at run time for the allowed sites only. | `npm run check` fails on any other permission or host pattern, on those manifest keys, on a background other than the `background.js` module worker, on `chrome.scripting` outside `lib/autofill-worker.js`, and on `chrome.permissions` outside that file and `popup/popup.js`. |
| Auto-fill only where you allowed it | Sites are bound by exact origin. The worker answers only this extension's own content script, from a frame whose origin is bound, while the vault is unlocked and not idle, and answers with the code and how long it stays valid, never account names or secrets. Auto-fill never submits a form and does not count as activity for the 15-minute lock. | `npm run e2e` part 3: a menu fill types the reference code; **Allow** stores the binding and registers the script for that origin only; a later visit is filled; another origin with the same page, a locked or idle vault, a removed site and a deleted account get nothing; no form is submitted. |
| Pinned third-party code | The only third-party code is the QR decoder jsQR 1.4.0, vendored unmodified, pinned by sha256, with its license beside it. | `cd extension/vendor && shasum -a 256 -c SHA256SUMS`; `npm run check` verifies the same. See [Third-party code](#third-party-code). |

**Limits of these checks.** The gate reads source text: it is a tripwire for this repository's
own files, not a proof, and the vendored decoder is checked by hash only (consistency with its
upstream release, not a review of its behaviour). Two known gaps: outside the content script, a
`/` that could be division or a regular expression is guessed rather than refused, so a contrived
one could hide a `js:`, `func:`, `files` or `css`, an alias of `chrome.scripting`, a call's
options, a rebinding of `fillFocused` or a global-object access from the scan; and an expression
that yields the global object without naming it (such as `document.defaultView`,
`globalThis.valueOf()`, `event.view`, or `this` in an event listener) can still be indexed by a
computed name, which checks that read `chrome.` by its spelling do not see. The end-to-end test,
which observes the requests made and the pages opened during its run, is the backstop.
`node scripts/check-policy.mjs --self-test` checks the gate itself: each deliberately broken copy
of the extension must fail the rule it breaks, and the gate's policy is compared with a second
copy written out separately, so it cannot be widened by editing one place.

Three things cannot be automated and are checked by hand: the browser's permission prompt after
**Allow**, the right-click menu itself (including a fill on a site the extension has no access
to), and a site's entry on the extension's details page before and after **Remove**.

### Third-party code

`extension/vendor/jsQR.js` is jsQR 1.4.0 (Apache-2.0): the file `dist/jsQR.js` of the npm package
`jsqr@1.4.0`, unmodified. Its license ships as `extension/vendor/jsQR.LICENSE`.

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

Requires Node.js 20 or later. The only dev dependency is `playwright`, pinned to an exact version.

```sh
npm ci
npm test                                  # unit tests: RFC 6238 vectors, base32, otpauth, vault, auto-fill
npm run check                             # static trust gate
node scripts/check-policy.mjs --self-test # proves the gate catches each violation
npx playwright install chromium           # once, for the e2e browser
npm run e2e                               # real Chromium + the unpacked extension (E2E_HEADLESS=1 for headless)
npm run zip                               # dist/zauthenticator-<version>.zip and its sha256
```

To try a change, load the `extension/` folder with **Load unpacked**. `npm run e2e` drives the
popup through its DOM contract, compares the displayed and copied codes with an independent TOTP
implementation, and covers locking, the 15-minute idle lock, concurrent pages and the blocked
network; its copy checks put codes of test secrets on the clipboard. Screenshots go to
`test-results/` (or `E2E_ARTIFACTS`). The auto-fill part (`e2e/autofill.e2e.mjs`) runs on a test
copy of the extension whose manifest differs in two fields the gate refuses: a test service-worker
entry that runs the shipped `background.js` and exposes the menu handler (a click in the browser's
own menu cannot be automated), and the locally answered test sites as required host permissions,
so no permission prompt appears.

Releases are cut by pushing a tag `v<version>` that matches `extension/manifest.json`. The release
workflow runs the full CI job on the tagged commit, builds the zip, checks that it unpacks to
exactly `extension/`, and publishes it with its sha256. Only the publishing job can write to the
repository, and every action is pinned by commit SHA. That zip is what is uploaded to the stores;
the listing texts live in [`store/listing/`](store/listing/).

The same tag then submits that zip to the existing Microsoft Edge Add-ons product
([Update REST API v1.1](https://learn.microsoft.com/en-us/microsoft-edge/extensions/update/api/using-addons-api)).
Succeeded means Microsoft has the submission (In review, up to seven business days), not that the
store is serving the new version. The API cannot change the description, screenshots or privacy
text. Reviewer notes are `store/listing/edge-certification-notes.txt` with the first line rewritten
to the tag. The job needs three repository secrets, created once at Partner Center under
Microsoft Edge → Publish API (Client ID, API key, and the product GUID from the extension overview,
not the public store listing id): `EDGE_ADDONS_CLIENT_ID`, `EDGE_ADDONS_API_KEY`,
`EDGE_ADDONS_PRODUCT_ID`. Until those exist the job logs `EDGE_SUBMIT=skipped` and the GitHub
release still stands. A second submission while one is already in review fails with
`InProgressSubmission`.

## License

[MIT](LICENSE). The vendored QR decoder keeps its own license (Apache-2.0), shipped as
`extension/vendor/jsQR.LICENSE`.

## 한국어

zauthenticator는 Chrome과 Edge에서 쓰는 오픈소스 2단계 인증(TOTP) 확장 프로그램이에요. 로그인할 때
필요한 인증 코드를 브라우저에서 바로 보여 주고, 코드를 만드는 비밀 키는 이 기기 밖으로 내보내지 않아요.

- **오픈소스**: MIT 라이선스예요. 번들러나 코드 압축 없이 평범한 JavaScript라서 실행되는 코드를 그대로 읽을 수 있어요.
- **코드는 이 기기에서 만들어요**: 비밀 키와 컴퓨터 시계만으로 계산해요.
- **회원 가입·보관함 동기화·사용 통계 수집이 없어요**: 확장 프로그램 화면과 백그라운드 워커는 어떤 서버에도 연결할 수 없어요.
- **마스터 비밀번호로 암호화해요**: 비밀 키는 암호화된 보관함 안에만 저장되고, 비밀번호 자체는 어디에도 저장하지 않아요.
  0.3부터는 패스키로도 잠금을 풀 수 있고, 비밀번호도 계속 쓸 수 있어요.
- **자동 입력은 사이트마다 직접 허용해요**: 사이트가 받는 건 6–8자리 코드뿐이에요.

### 설치

- **스토어에서 설치**: Chrome 웹 스토어와 Microsoft Edge 추가 기능에 곧 올라가요(공개되면 여기에 링크를
  넣을게요). 스토어로 설치하면 브라우저가 알아서 업데이트해요.
- **직접 설치**: [Releases](https://github.com/2lab-ai/zauthenticator/releases)에서
  `zauthenticator-<버전>.zip`을 받아 계속 둘 폴더에 압축을 풀어요. `chrome://extensions`나
  `edge://extensions`에서 **개발자 모드**를 켜고 **압축해제된 확장 프로그램을 로드합니다**를 눌러 그 폴더(`manifest.json`이 있는 폴더)를
  고르면 돼요. 업데이트할 때는 같은 폴더의 내용을 새 버전으로 바꾸고 새로고침 아이콘을 눌러요. 확장
  프로그램 ID가 폴더 경로로 정해지기 때문에, 폴더가 바뀌면 빈 보관함을 가진 다른 확장 프로그램이 돼요.
- 스토어 설치와 직접 설치는 서로 다른 확장 프로그램이라 보관함도 따로예요. 계정을 옮기려면 한쪽에서
  백업을 내보내고 다른 쪽에서 가져오세요.
- 확장 프로그램을 삭제하면 보관함도 함께 지워져요. 삭제하기 전에 백업을 내보내세요.

### 사용법

- **처음 열 때** 마스터 비밀번호(8자 이상)를 만들어요. 비밀번호는 복구할 수 없고 바꿀 수도 없으니 잊지 않도록 해 주세요.
  잊으면 저장한 계정을 열 수 없고(0.3부터는 등록한 패스키가 아직 동작하면 열 수 있어요), 백업을 가져올 때도
  그 백업을 만들 때 쓴 비밀번호를 묻기 때문에 백업으로도 되살릴 수 없어요. 백업은 기기나 브라우저 프로필을
  잃었을 때를 위한 거예요.
- **계정 추가**: 지금 보고 있는 페이지의 QR 코드(툴바 아이콘을 눌러 스캔), QR 이미지, `otpauth://` 링크,
  설정 키 직접 입력 중 편한 방법을 쓰면 돼요.
- **코드 복사**: 코드를 클릭하면 복사돼요. 다음 코드까지 남은 시간도 보여요.
- **사이트에 입력**: 사이트의 코드 입력란에서 마우스 오른쪽 버튼을 누르고 **zauthenticator**에서 계정을
  고르면 현재 코드가 입력돼요(제출은 하지 않아요). `https` 사이트에서 처음 이렇게 하면 앞으로 이 사이트에서
  자동으로 입력할지 묻는 작은 창이 떠요. **허용**을 누르고 브라우저가 그 사이트 하나에 접근해도 되는지 물을 때
  동의하면, 다음부터는 잠금이 풀려 있는 동안 코드가 자동으로 입력돼요. **나중에**를 누르거나 브라우저 권한을
  거절하면 아무것도 저장하지 않아요.
- 자동으로 입력한 뒤 제출하기 전까지는 이렇게 해요. 입력한 코드가 만료되면 새 코드로 한 번 바꿔요.
  사이트가 코드를 거부하면 새 코드로 한 번 다시 입력하고, 같은 코드를 두 번 넣지는 않아요. 한 탭에서 한
  사이트에 넣는 코드는 5분에 3개까지예요. 입력란에 직접 입력하거나 지우면, 그 페이지를 떠나면, 잠기면 바로
  멈춰요. 폼을 제출하지는 않아요.
- 자동 입력은 허용한 바로 그 사이트(같은 주소·포트)에서만 해요. 하위 도메인이나 비슷한 도메인에는
  입력하지 않아요. 코드 입력란이라는 표시가 있는 칸만 채우고, PIN이나 우편번호처럼 모양만 비슷한 칸은
  건드리지 않으니 그런 칸에는 오른쪽 클릭 메뉴로 넣어 주세요.
- 자동 입력을 그만하려면 **설정**의 **자동 입력 사이트**에서 **삭제**를 눌러요. 그 사이트에 대한 접근 권한도
  함께 반납해요.
- **패스키로 잠금 해제 (0.3부터)**: 비밀번호를 입력하는 대신 패스키로 잠금을 풀 수 있어요. 비밀번호는 계속
  쓸 수 있고, 패스키를 잃었을 때 다시 들어오는 방법이에요.
  - 필요한 것: 사용자 확인과 WebAuthn PRF 확장을 지원하는 인증기예요. 예를 들어 브라우저의 QR 코드로 연결한
    휴대폰, PIN을 설정한 보안 키, 컴퓨터에 내장된 패스키 저장소가 있어요. Linux의 Edge에서 Apple Passwords에
    저장하는 iPhone은 이 휴대폰 연결 방식으로 동작해요. 시험한 Android 휴대폰 하나(Samsung Pass에 저장)는
    PRF 값을 돌려주지 않아 그 조합은 등록이 거절돼요. 다른 Android 패스키 제공자는 시험하지 않았어요. Mac과
    보안 키는 브라우저 문서를 따른 것이고 관리자가 직접 시험하지는 않았어요.
  - 등록: **설정**을 전체 탭으로 열고(툴바 팝업에서는 탭으로 여는 버튼만 보여요) 패스키를 추가해요. 비밀번호를
    다시 입력하면 먼저 확인하고, 그다음 브라우저가 두 번 물어요. 한 번은 패스키를 만들고, 한 번은 PRF 값을
    돌려주는지 확인하려고 패스키를 써요. 어느 단계에서든 실패하면 아무것도 저장하지 않지만, 휴대폰이나 키에는
    패스키가 이미 만들어졌을 수 있으니 필요 없으면 거기서 삭제하세요.
  - 잠금 해제: 잠긴 팝업에서 패스키 잠금 해제를 고르면 별도 창이 열리고(툴바 팝업은 브라우저의 패스키 창이
    뜨면 닫혀요), 그 창에서 확인해요. 실패하면 잠긴 채로 있고 비밀번호는 그대로 쓸 수 있어요.
  - 설치마다 따로 등록해요. 패스키는 확장 프로그램 ID에 묶이는데, 스토어 설치와 직접 설치의 ID가 달라요.
  - 삭제: **설정**에서 패스키를 삭제하면 이 보관함에서만 지워져요. 휴대폰·보안 키·비밀번호 관리자에서도
    삭제하세요. 복사해 둔 브라우저 프로필 같은 이전 보관함 복사본에는 패스키 슬롯이 남아 있어요.
  - 버전 호환: 패스키를 등록하면 보관함이 0.3 형식으로 바뀌어요. 0.2.0은 바뀐 보관함을 열 수 없고, 그
    보관함에서 내보낸 백업도 가져올 수 없어요(패스키는 빠지지만 백업도 0.3 형식이에요). 나중에 패스키를
    삭제해도 이전 형식으로 돌아가지 않아요. 패스키를 등록한 적이 없는 보관함은 0.2.0 형식 그대로라서 0.2.0이
    열 수 있고 그 백업도 가져올 수 있어요. **등록하기 전에 백업을 내보내 두세요.** 그래야 0.2.0이 읽을 수
    있는 복사본이 남아요.
- **백업**: 설정에서 암호화된 백업을 `.json` 파일로 내보내고, 가져올 때는 그 백업을 만들 때 쓴 비밀번호를
  입력해요. 계정만 가져오고 자동 입력 사이트는 다시 설정해야 해요. 0.3부터는 이렇게 돼요.
  - 패스키를 등록한 보관함의 백업에는 패스키가 빠지고, 백업을 가져와도 패스키는 등록되지 않아요. 이 백업은
    0.3 형식이라 0.2.0에서는 가져올 수 없어요.
  - 비밀번호는 확장 프로그램이 백업을 가져오는 방법일 뿐, 백업을 풀 수 있는 유일한 키는 아니에요. 백업의
    계정은 원래 보관함과 같은 데이터 키(DEK)로 암호화되고, 백업에서 패스키를 빼거나 보관함에서 패스키를
    삭제해도 그 키는 바뀌지 않아요. 그 DEK를 가진 사람은 비밀번호 없이 백업과, 보관함이 나중에 같은 DEK로
    암호화한 데이터를 풀 수 있어요. 예를 들어 패스키 슬롯이 남은 이전 보관함 복사본과 그에 맞는 인증기·사용자
    확인을 가진 사람, 또는 잠금이 풀린 세션에서 DEK를 가져간 사람이에요.
  - 패스키를 등록하기 전에 내보낸 백업은 이전 비밀번호 키를 써요. 등록할 때 새 DEK를 만들기 때문이에요.
- **잠금**: 잠그기 버튼을 누르거나, 15분 동안 쓰지 않거나, 브라우저를 완전히 종료하면(macOS는 Cmd+Q) 잠겨요.
  잠겨 있는 동안에는 아무것도 입력하지 않아요.

### 개인정보와 보안

- 잠금이 풀려 있는 동안에는 브라우저 세션 메모리에 자동 입력 기록도 잠깐 둬요. 코드를 받은 탭과 허용한
  사이트마다 탭 번호, 사이트 주소, 계정의 내부 ID, 몇 번째 코드 주기였는지와 그 시각을 적고, 코드 자체는 적지
  않아요. 한 탭에서 한 사이트가 5분에 코드를 3개까지만 받고 같은 코드를 두 번 받지 않게 하려고만 써요. 5분이
  지난 항목은 더 세지 않고 기록이 바뀔 때 지워지며, 오른쪽 클릭 메뉴로 계정을 고르면 그 탭과 사이트의 기록이
  지워지고, 잠기면 기록 전체가 지워져요.
- 비밀 키, 계정 이름, 자동 입력 사이트는 이 기기의 브라우저 저장소에 암호화된 채로만 있어요. 개발자에게도,
  다른 누구에게도 보내지 않아요.
- 0.3부터 패스키를 등록하면 보관함은 임의의 데이터 키(DEK)로 다시 암호화되고, 그 DEK는 비밀번호에서 만든
  키(PBKDF2)와 인증기의 PRF 출력에서 만든 키(HKDF)로 각각 암호화해 두 번 저장돼요. 암호화된 데이터 옆에는
  패스키의 인증 정보 ID, 인증기에 보내는 임의의 입력값(PRF 솔트), 붙인 이름, 등록 시각, 암호화된 DEK와 IV가
  저장되고, 브라우저 프로필을 읽을 수 있는 사람은 이름을 포함해 이 정보를 볼 수 있어요. PRF 출력이나 평문
  DEK는 저장하지 않고 비밀 키는 암호화된 채로 남아요. 세션 메모리에는 풀린 키와 보관함의 버전·식별 정보,
  그리고 비밀이 아닌 잠금 카운터(`lockGen`)가 있어요. 잠글 때마다 이 값을 지우지 않고 새 값으로 바꿔서,
  잠그기 전에 시작한 패스키 요청은 잠근 뒤에 잠금을 풀 수 없어요.
- 0.3부터 패스키 요청은 확장 프로그램이 아니라 브라우저가 처리해요(확장 프로그램 화면은 여전히 어떤 서버에도
  연결할 수 없어요). 브라우저는 확장 프로그램 ID(RP), 인증 정보 ID, 챌린지, PRF 솔트를 인증기에 보내요.
  인증기는 브라우저의 QR 코드로 연결한 휴대폰일 수도 있어요. 패스키 제공자는 확장 프로그램과 별개로 패스키를
  다른 기기에 동기화할 수 있어요. TOTP 비밀 키와 보관함 내용은 보내지 않아요.
- 브라우저는 확장 프로그램이 접근할 수 있는 사이트 목록과 자동 입력 스크립트가 등록된 사이트
  목록을 보관함 밖에 따로 기록해요. 브라우저 프로필을 읽을 수 있는 사람은 이 사이트 이름을 볼 수 있어요.
- 사이트가 받는 건 입력된 6–8자리 코드뿐이에요. 그 사이트의 스크립트는 직접 입력했을 때처럼 이 코드를 읽을 수 있어요.
- 팝업에서 **이 페이지 스캔** 버튼을 누를 때만 지금 탭에서 보이는 부분을 한 장 캡처해요. 이 이미지는 팝업 안에서 QR
  디코더로 읽는 동안만 메모리에 있고, 저장하거나 보내지 않아요. 올바른 2단계 인증 QR 코드라면 거기서 찾은
  계정만 보관함에 추가해요. 자동 입력을 허용한 사이트에서는 코드 입력란을 찾으려고 입력란의 속성(이름,
  레이블, placeholder 등)을 읽어요.
- 권한: `storage`(암호화된 보관함 저장), `activeTab`(툴바 아이콘이나 오른쪽 클릭 메뉴를 쓴 그 탭에서만 QR
  스캔·코드 입력), `contextMenus`(오른쪽 클릭 메뉴), `scripting`(코드 입력과 자동 입력 등록), 그리고 허용한
  사이트 하나씩만 받는 선택적 `https` 사이트 접근이에요. 설치할 때는 어떤 사이트 권한도 받지 않아요.
- 컴퓨터 시계가 틀리면 코드도 틀려요. 보관함 동기화는 일부러 넣지 않았어요(패스키 제공자는 패스키를 따로
  동기화할 수 있어요). 백업 파일이나 브라우저 프로필을 가진 사람은 비밀번호를 오프라인에서 추측해 볼 수
  있으니 긴 비밀번호를 쓰세요. 0.3부터 패스키 슬롯이 있는 프로필 복사본은 그에 맞는 인증기와 사용자
  확인으로도 열려요.
- 자세한 내용은 [개인정보처리방침](PRIVACY.md)(영문), [보안 정책](SECURITY.md)(영문),
  [Verifying the trust claims](#verifying-the-trust-claims)에 있어요.

### 개발

`npm ci` 후 `npm test`, `npm run check`, `node scripts/check-policy.mjs --self-test`, `npm run e2e`,
`npm run zip`을 실행해요. 라이선스는 MIT예요.
