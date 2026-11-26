# zauthenticator

[![Microsoft Edge Add-ons](https://img.shields.io/badge/dynamic/json?label=Edge%20Add-ons&query=%24.version&prefix=v&url=https%3A%2F%2Fmicrosoftedge.microsoft.com%2Faddons%2Fgetproductdetailsbycrxid%2Fdliacchcdohpbldddfmhmcpcdhdnakdp&logo=microsoftedge&logoColor=white&color=0078D7)](https://microsoftedge.microsoft.com/addons/detail/dliacchcdohpbldddfmhmcpcdhdnakdp)
[![Chrome Web Store: planned](https://img.shields.io/badge/Chrome%20Web%20Store-planned-lightgrey?logo=googlechrome&logoColor=white)](#install)
[![Latest release](https://img.shields.io/github/v/release/2lab-ai/zauthenticator?label=release)](https://github.com/2lab-ai/zauthenticator/releases/latest)
[![CI](https://github.com/2lab-ai/zauthenticator/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/2lab-ai/zauthenticator/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/2lab-ai/zauthenticator)](LICENSE)

An open-source two-factor (TOTP) authenticator for Chrome and Edge. It shows your login codes in
the browser, and the secret keys behind them stay on your device.

<img src="docs/images/popup-list.png" width="360" alt="The zauthenticator popup listing accounts and their current codes">

- **Codes are made on your device**, from the secret key and your computer's clock. There is no
  account, no vault sync and no telemetry, and the extension's own pages and background worker
  cannot connect to any server.
- **The vault is encrypted at rest.** Unlock it with a passphrase or a passkey. If you remove the
  passphrase, the vault stays encrypted with a key that this browser keeps.
- **You choose where codes go.** Right-click a code field to fill it, or allow auto-fill on one
  exact site at a time. A site receives the 6–8 digit code and nothing else.
- **Your accounts can leave with you**: as an encrypted backup, as `otpauth://` links, or as QR
  codes that Google Authenticator imports.
- **You can read what runs.** MIT license, plain JavaScript with no bundler, no minifier and no
  npm dependencies at run time. The two vendored QR libraries are pinned by hash, and CI checks
  the trust claims on every push ([how](docs/trust.md)).

[한국어 안내](#한국어) · [Privacy policy](PRIVACY.md) · [Security policy](SECURITY.md) ·
[Verifying the trust claims](docs/trust.md)

## Install

| Where | Status | Updates |
|---|---|---|
| [Microsoft Edge Add-ons](https://microsoftedge.microsoft.com/addons/detail/dliacchcdohpbldddfmhmcpcdhdnakdp) | Available | Automatic, by the browser |
| Chrome Web Store | Planned, not listed yet | Automatic, once listed |
| [GitHub Releases](https://github.com/2lab-ai/zauthenticator/releases) | Every version, as a zip for Chrome or Edge | By hand |

Until the Chrome Web Store listing is live, Chrome users install a release by hand. A manual
install runs exactly the files you downloaded, and nothing updates them:

1. Download `zauthenticator-<version>.zip` from
   [Releases](https://github.com/2lab-ai/zauthenticator/releases). The release notes give its
   sha256 if you want to check the download.
2. Unzip it into a folder you will keep. The browser loads the extension from that folder.
3. Open `chrome://extensions` or `edge://extensions` and turn on **Developer mode**.
4. Click **Load unpacked** and pick the unzipped folder (the one that contains `manifest.json`).

To update a manual install, replace the folder's contents with the new release and click the
reload icon on the extensions page. Keep the same folder: the browser derives the extension's id
from the folder's path, so a different folder loads as a different extension with an empty vault.

Before you move or remove it:

- **A store install and a manual install are separate extensions** with separate vaults. To move
  your accounts, export a backup from one and import it into the other (see
  [Back up and restore](#back-up-and-restore)).
- **Uninstalling deletes the vault.** Export a backup first if you may want your accounts back.

## Use

### Set a passphrase

The first time you open the popup, you choose a passphrase of 8 characters or more. It encrypts
your accounts. **It cannot be recovered**: if you forget it, the saved accounts cannot be opened
unless a passkey you enrolled still works, and your backups cannot be imported either, because
import asks for the passphrase the backup was made with. You can change or remove it later in
**Settings** (see [Change or remove the passphrase](#change-or-remove-the-passphrase)).

While you type in any passphrase field, a line under it shows the input source your keys produce
(for example Latin letters or Korean Hangul, or an input method composing) and whether Caps Lock
is on. Only the kind of character is shown, never what you typed.

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

<img src="docs/images/popup-autofill-bind.png" width="400" alt="The window that asks whether to fill codes automatically on a site">

After a fill, until you submit:

- **The code is kept current, once.** When the filled code expires, it is replaced with the new
  one, one time.
- **A rejected code is replaced once.** If the site rejects the code, a fresh one is filled once;
  the same code is never filled twice.
- **It is capped.** In one tab, a site gets at most 3 codes in 5 minutes.
- **It stops** as soon as you type or delete in the field yourself, when you leave the page, or
  when zauthenticator locks. It never submits a form.

Auto-fill works only on the exact site you allowed: the same scheme, host and port, on the page
itself or in a frame of that site inside another page. A subdomain or a look-alike domain gets
nothing. It fills only fields marked as a code field: a field the site marks as a one-time code,
a field whose name or label says OTP, 2FA, verification code and the like, or a row of 6–8
one-character boxes labelled as a code. Fields that merely look like a code, such as a PIN or a
postal code, are left alone; use the right-click menu for those. Finding the field is a best
guess, so on an unusual page it may find nothing, or the wrong field.

To stop auto-fill on a site, open **Settings**, find the site under auto-fill sites and click
**Remove**. The extension also gives up its access to that site. Deleting an account removes its
sites too.

### Lock

Click **Lock** to lock right away. zauthenticator also locks 15 minutes after you last used it,
and when the browser fully quits (on macOS, Cmd+Q; closing the windows is not enough). The account
list shows when it will lock, and opening or using the extension moves that time to at least
15 minutes from now. While it is locked nothing is filled, and the right-click menu offers
**Unlock zauthenticator…** instead of your accounts.

**Extend** keeps it unlocked for 1 hour, 24 hours or 7 days, for example while an AI agent works
in this browser and needs codes. It asks twice, in red, because until then anyone using this
browser can see and fill your codes. **Back to 15 minutes** ends an extension; Lock and quitting
the browser end it at once.

<img src="docs/images/popup-locked.png" width="360" alt="The locked popup asking for the passphrase">

### Unlock with a passkey

You can unlock with a passkey instead of typing the passphrase. The passphrase keeps working and
stays the way back in if the passkey is lost.

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

### Change or remove the passphrase

In **Settings**, **Passphrase**:

- **Change passphrase**: enter the current one and the new one twice. The vault is encrypted again
  under a new data key, so a passkey you enrolled is removed (enroll it again if you want it) and
  other open windows of the extension lock. Backups you exported before keep the old passphrase.
- **Remove passphrase**: enter the current one, then confirm twice on red warnings. After that the
  extension opens without asking. Your accounts stay encrypted, with a random key that this browser
  generated on this computer and keeps as *non-extractable*: the extension can use it but cannot
  read it, and it is never exported or synced. The browser still stores it in the profile's files,
  so anyone who can copy your browser profile can decrypt the vault. A disk serial number or a
  "computer fingerprint" is not used: an extension cannot read a disk serial, and a fingerprint
  changes after a driver update or a new monitor, which would lock you out for good. Without a
  passphrase there is no Lock button and no automatic lock, and a backup asks for a passphrase
  just for that file. **Anyone who can use this browser profile can see your codes**, and if the
  profile or the extension's data is lost, only a backup brings the accounts back.
- **Set passphrase**: a vault without one can get one again at any time; the browser's key is then
  deleted.

### Back up and restore

In **Settings**, **Export encrypted backup** saves a `.json` file: your vault as stored, still
encrypted, without any passkey. To restore, choose the file under **Import a backup** and enter
the passphrase that backup was made with. Import adds the backup's accounts (duplicates are
skipped) and never adds a passkey. Auto-fill sites are not imported, so set them again from the
right-click menu. A vault without a passphrase asks for a passphrase for the backup file, which is
then encrypted under its own key that the vault does not share.

The passphrase is how the extension imports a backup, not the only key that can decrypt it. A
backup's accounts are encrypted under the same data key (DEK) as the vault it came from, and
leaving the passkey out of the backup, or removing the passkey from the vault, does not change
that key. Someone who holds the DEK can decrypt the backup, and data the vault encrypts later
under the same DEK, without the passphrase: for example someone with an older copy of the vault
that still has the passkey slot together with the matching authenticator and its user
verification, or someone who took the DEK from an unlocked session. Backups exported before you
enrolled a passkey use your earlier passphrase key, because enrolling draws a new DEK.

### Export accounts to another app

**Settings → Backup → Export accounts** moves accounts to another authenticator. Enter your
passphrase again (a vault without one skips this), tick one or more accounts, then:

- **Copy links** puts one `otpauth://` link per line on the clipboard. Any authenticator that
  imports otpauth links reads them, and so does zauthenticator's own **Add account**.
- **Show QR** draws QR codes in the popup. One account gives its `otpauth://` QR, which any
  authenticator scans (Google Authenticator: **+ → Scan a QR code**). Several accounts give Google
  Authenticator transfer QR codes: on the phone open **Transfer accounts → Import accounts** and
  scan each code in order. Google's format has no room for a code period other than 30 seconds
  or for 7-digit codes, so such an account follows as its own otpauth QR. **One QR per account**
  shows every account as an otpauth QR instead.

Links and QR codes hold the secret keys in plain form: anyone who sees a QR code or the copied
text can make your codes. They are made in the popup and never sent anywhere; leaving the view or
locking removes them from the screen, but copied text stays on the clipboard until something
else replaces it.

### Going back to version 0.2.0

Version 0.2.0 reads only the original vault format. Enrolling a passkey, changing the passphrase or
removing it converts the vault to the newer format, and removing the passkey later does not
convert it back. Version 0.2.0 cannot open a converted vault, and cannot import a backup exported
from it. **Export a backup before** you do any of these, so you keep a copy that 0.2.0 can read.

## Privacy and security

**What stays on your device.** Your secret keys, account names and auto-fill sites are stored in
the browser's storage for this extension, inside a vault encrypted with AES-256-GCM. With a
passphrase, the key is derived from it (PBKDF2-SHA-256, 600,000 iterations) and the passphrase
itself is never stored. A passkey adds a second way to open the same data key. Without a
passphrase, a non-extractable key that the browser keeps for this extension protects it. While
the vault is unlocked, the browser's session memory holds the key, the end of an extended unlock
time and a short auto-fill record: for each tab and allowed site that got a code, the tab number,
the site's address, the account's internal id, which code period it was and when, never a code.
That record exists only so that a site gets at most 3 codes per tab in 5 minutes and never the
same code twice; locking removes all of it. Nothing is sent to the developer or anyone else; there
is no server. The [privacy policy](PRIVACY.md) lists every stored value.

**What leaves the extension.** A site receives only the 6–8 digit code, typed into its page: on a
site you allowed, or in the field you right-clicked. The site's scripts can read it, just as if
you had typed it. The secret key, the account name and your passphrase never reach the page. For
passkey unlock, the browser, not the extension, sends the extension's ID (as the relying party),
the credential ID, a challenge and the PRF salt to your authenticator, which may be a phone
reached through the browser's QR code flow. Your passkey provider may sync the passkey to your
other devices, independently of the extension. Your TOTP secrets and the vault's contents are
never sent.

**What it reads from web pages.** Only when you click the button to scan the current page, the
extension takes one picture of the visible part of that tab (the browser allows this for the tab
where you just clicked the toolbar icon). The picture is decoded in the popup by the bundled QR
decoder and held in memory only for that; it is never stored or sent. Only the account found in
it, if it is a valid two-factor QR code, is added to your vault. On a site where you allowed
auto-fill, the auto-fill script reads the attributes of the page's input fields (such as name,
label and placeholder) to find the code field, and keeps none of it.

**What the browser itself records.** Outside the encrypted vault, the browser keeps the list of
sites you gave the extension access to (shown on the extension's details page) and the list of
sites its auto-fill script is registered for. Someone who can read your browser profile can see
those site names. If you installed from a store, the browser checks that store for updates, as it
does for every extension installed from there.

**Permissions and why they are needed:**

| Permission | What it lets the extension do | Why |
|---|---|---|
| `storage` | Keep data in the browser's storage for this extension | To save the encrypted vault, and the unlocked key for the browser session |
| `activeTab` | Use the current tab, only right after you click the toolbar icon or choose an account in the right-click menu | To scan a QR code on the page you are looking at, and to type a code into the field you right-clicked |
| `contextMenus` | Add an item to the right-click menu of text fields | To let you choose which account's code to fill |
| `scripting` | Run the extension's own fill code in a page | To type the code into the field, and to register auto-fill for the sites you allowed |
| Access to `https` sites (optional) | Run the auto-fill script on a site | Nothing is granted at install. The browser asks you for one exact site when you click **Allow**, and the access is removed when you remove that site |

**Limits worth knowing:**

- The passphrase cannot be recovered. Restoring a backup in the extension asks for the passphrase
  it was made with: a backup protects you against losing the device or the browser profile, not
  against forgetting the passphrase. A backup shares the vault's DEK, so it is not isolated from
  anyone who holds that key (see [Back up and restore](#back-up-and-restore)).
- The computer's clock is the only time source. If codes are rejected, make sure the date and
  time are set automatically.
- There is no vault sync, by design. Each browser profile has its own vault; use export and import
  to move accounts. Passkey providers may independently sync passkeys.
- Someone who gets a copy of your browser profile or of a backup file can try to guess the
  passphrase offline. The key derivation makes each guess slow, but a long passphrase (several
  random words) is what keeps it out of reach. A profile copy that holds a passkey slot also opens
  with the matching authenticator and its user verification.
- It does not protect against malware running as your user, a compromised browser or profile, or
  someone using your browser while it is unlocked. Copied codes sit in the system clipboard,
  where other applications can read them.
- Without a passphrase, the vault is only as safe as the browser profile: anyone who can use it,
  or copy it whole, can open your codes.
- An extended unlock time keeps codes available to anyone using this browser, people and AI
  agents alike, until it ends or you lock.
- No timer runs for the lock time. The unlocked key stays in the browser's session memory until
  the next thing that reads it (opening the popup, a menu choice or an auto-fill request); that
  read locks the vault and clears the key before any code is shown or filled. In the same way, if
  the browser's background worker was asleep when the lock time passed, account names can stay in
  the right-click menu until it next wakes; choosing one then opens the unlock window instead of
  filling.

To report a vulnerability, see the [security policy](SECURITY.md).

## Verifying the trust claims

Each claim above can be checked from this repository. `npm run check` is a static gate that reads
the source and prints one `PASS`/`FAIL` line per rule, and `npm run e2e` loads the extension into
a real Chromium and observes the requests it makes and the pages it opens. CI runs both, with the
unit tests and the gate's self-test, on every push and pull request and on each release tag.
[docs/trust.md](docs/trust.md) maps every claim to the rule or test that enforces it, says what
those checks cannot see, and shows how to compare the two vendored QR libraries with their npm
releases.

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

### Releases

Push a tag `v<version>` that matches `extension/manifest.json`. The release workflow runs the full
CI job on the tagged commit, builds the zip, checks that it unpacks to exactly `extension/`, and
publishes it with its sha256 as a GitHub release. Only the publishing job can write to the
repository, and every action is pinned by commit SHA.

The same tag then uploads that zip to the existing Microsoft Edge Add-ons listing through the
[Update REST API v1.1](https://learn.microsoft.com/en-us/microsoft-edge/extensions/update/api/using-addons-api)
and submits it for certification, with `store/listing/edge-certification-notes.txt` as the
reviewer notes. Their first line says what changed in this version; if it names another version,
the job replaces it with a line that names the tag. A successful run means Microsoft has the
submission (In review, up to seven business days), not that the store serves the new version yet.
A second submission while one is in review fails with `InProgressSubmission`. The API cannot
change the description, screenshots or privacy answers; those stay a Partner Center edit, from the
texts in [`store/listing/`](store/listing/). The job reads three repository secrets created at
Partner Center under Microsoft Edge → Publish API: `EDGE_ADDONS_CLIENT_ID`, `EDGE_ADDONS_API_KEY`
and `EDGE_ADDONS_PRODUCT_ID` (the product GUID from the extension overview, not the public listing
id). Without them it logs `EDGE_SUBMIT=skipped` and the GitHub release still stands. The secrets
were set on 2026-11-25; the API key expires on 2027-02-05, so renew it on the Publish API page and
update `EDGE_ADDONS_API_KEY` before then.

The Chrome Web Store listing does not exist yet. Once it does, the same zip is uploaded there by
hand, following [`store/listing/submission-checklist.md`](store/listing/submission-checklist.md).

## License

[MIT](LICENSE). The vendored QR libraries keep their own licenses, shipped beside them: jsQR
(Apache-2.0, `extension/vendor/jsQR.LICENSE`) and qrcode-generator (MIT,
`extension/vendor/qrcode.LICENSE`).

## 한국어

zauthenticator는 Chrome과 Edge에서 쓰는 오픈소스 2단계 인증(TOTP) 확장 프로그램이에요. 로그인할 때
필요한 인증 코드를 브라우저에서 바로 보여 주고, 코드를 만드는 비밀 키는 이 기기 밖으로 내보내지 않아요.

- **코드는 이 기기에서 만들어요.** 비밀 키와 컴퓨터 시계만으로 계산해요. 회원 가입·보관함 동기화·사용
  통계 수집이 없고, 확장 프로그램 화면과 백그라운드 워커는 어떤 서버에도 연결할 수 없어요.
- **보관함은 암호화돼 있어요.** 마스터 비밀번호나 패스키로 잠금을 풀어요. 비밀번호를 없애도 보관함은 이
  브라우저가 보관하는 키로 계속 암호화돼요.
- **코드를 어디에 넣을지는 직접 정해요.** 코드 입력란에서 오른쪽 클릭으로 넣거나, 사이트 하나씩 자동 입력을
  허용해요. 사이트가 받는 건 6–8자리 코드뿐이에요.
- **계정을 다른 앱으로 옮길 수 있어요.** 암호화된 백업, `otpauth://` 링크, Google Authenticator가 바로
  가져오는 QR 코드로 내보내요.
- **실행되는 코드를 그대로 읽을 수 있어요.** MIT 라이선스이고, 번들러·코드 압축·실행 시점 npm 의존성이 없는
  평범한 JavaScript예요. 함께 넣은 QR 라이브러리 두 개는 해시로 고정돼 있고, 신뢰 주장은 푸시마다 CI가
  검사해요([검사 방법](docs/trust.md), 영문).

### 설치

| 어디서 | 상태 | 업데이트 |
|---|---|---|
| [Microsoft Edge 추가 기능](https://microsoftedge.microsoft.com/addons/detail/dliacchcdohpbldddfmhmcpcdhdnakdp) | 설치할 수 있어요 | 브라우저가 알아서 해요 |
| Chrome 웹 스토어 | 올릴 예정이에요(아직 없어요) | 올라가면 브라우저가 알아서 해요 |
| [GitHub Releases](https://github.com/2lab-ai/zauthenticator/releases) | 모든 버전을 zip으로 받아요(Chrome·Edge 공용) | 직접 바꿔요 |

Chrome 웹 스토어에 올라가기 전까지 Chrome에서는 직접 설치해요.

1. [Releases](https://github.com/2lab-ai/zauthenticator/releases)에서 `zauthenticator-<버전>.zip`을 받아요.
   릴리스 노트에 sha256이 있어서 받은 파일을 확인할 수 있어요.
2. 계속 둘 폴더에 압축을 풀어요. 브라우저는 그 폴더에서 확장 프로그램을 읽어요.
3. `chrome://extensions`나 `edge://extensions`에서 **개발자 모드**를 켜요.
4. **압축해제된 확장 프로그램을 로드합니다**를 눌러 그 폴더(`manifest.json`이 있는 폴더)를 골라요.

업데이트할 때는 같은 폴더의 내용을 새 버전으로 바꾸고 새로고침 아이콘을 눌러요. 확장 프로그램 ID가 폴더
경로로 정해지기 때문에, 폴더가 바뀌면 빈 보관함을 가진 다른 확장 프로그램이 돼요.

- **스토어 설치와 직접 설치는 서로 다른 확장 프로그램이라 보관함도 따로예요.** 계정을 옮기려면 한쪽에서
  백업을 내보내고 다른 쪽에서 가져오세요.
- **확장 프로그램을 삭제하면 보관함도 함께 지워져요.** 삭제하기 전에 백업을 내보내세요.

### 사용법

- **처음 열 때** 마스터 비밀번호(8자 이상)를 만들어요. **비밀번호는 복구할 수 없어요.** 잊으면 등록한
  패스키가 아직 동작하지 않는 한 저장한 계정을 열 수 없고, 백업을 가져올 때도 그 백업을 만들 때 쓴 비밀번호를
  묻기 때문에 백업으로도 되살릴 수 없어요. 비밀번호를 입력하는 동안 아래 줄에 지금 키가 어떤 입력 소스로
  들어가는지(영문, 한글, 입력기 조합 중 등)와 Caps Lock이 켜져 있는지 보여 줘요. 입력한 글자 자체는 보여 주지
  않아요.
- **계정 추가**: 지금 보고 있는 페이지의 QR 코드(툴바 아이콘을 눌러 스캔), QR 이미지, `otpauth://` 링크,
  설정 키 직접 입력 중 편한 방법을 써요.
- **코드 복사**: 코드를 클릭하면 복사돼요. 다음 코드까지 남은 시간도 보여요.
- **사이트에 입력**: 사이트의 코드 입력란에서 마우스 오른쪽 버튼을 누르고 **zauthenticator**에서 계정을
  고르면 현재 코드가 입력돼요(제출은 하지 않아요). `https` 사이트에서 처음 이렇게 하면 앞으로 이 사이트에서
  자동으로 입력할지 묻는 작은 창이 떠요. **허용**을 누르고 브라우저가 그 사이트 하나에 접근해도 되는지 물을 때
  동의하면, 다음부터는 잠금이 풀려 있는 동안 코드가 자동으로 입력돼요. **나중에**를 누르거나 브라우저 권한을
  거절하면 아무것도 저장하지 않아요.
  - 자동으로 입력한 뒤 제출하기 전까지: 입력한 코드가 만료되면 새 코드로 한 번 바꿔요. 사이트가 코드를
    거부하면 새 코드로 한 번 다시 입력하고, 같은 코드를 두 번 넣지는 않아요. 한 탭에서 한 사이트에 넣는 코드는
    5분에 3개까지예요. 입력란에 직접 입력하거나 지우면, 그 페이지를 떠나면, 잠기면 바로 멈춰요. 폼을
    제출하지는 않아요.
  - 허용한 바로 그 사이트(같은 주소·포트)에서만 입력해요. 하위 도메인이나 비슷한 도메인에는 입력하지 않아요.
    코드 입력란이라는 표시가 있는 칸만 채우고, PIN이나 우편번호처럼 모양만 비슷한 칸은 건드리지 않으니 그런
    칸에는 오른쪽 클릭 메뉴로 넣어 주세요.
  - 그만하려면 **설정**의 **자동 입력 사이트**에서 **삭제**를 눌러요. 그 사이트에 대한 접근 권한도 함께
    반납해요.
- **잠금**: 잠그기 버튼을 누르거나, 마지막으로 쓰고 15분이 지나거나, 브라우저를 완전히 종료하면(macOS는
  Cmd+Q) 잠겨요. 잠겨 있는 동안에는 아무것도 입력하지 않아요. 계정 목록에 언제 잠기는지 보이고, 확장
  프로그램을 열거나 쓰면 그 시각이 적어도 지금부터 15분 뒤로 늘어나요. **연장**을 누르면 1시간, 24시간,
  7일 동안 잠금 해제해 둘 수 있어요(예: AI 에이전트가 이 브라우저에서 코드를 써야 할 때). 그동안 이 브라우저를
  쓰는 누구나 코드를 보고 입력할 수 있어서 빨간 확인을 두 번 거쳐요. **15분으로 되돌리기**로 끝낼 수 있고,
  잠그거나 브라우저를 종료하면 바로 끝나요.
- **패스키로 잠금 해제**: 비밀번호를 입력하는 대신 패스키로 잠금을 풀 수 있어요. 비밀번호는 계속 쓸 수 있고,
  패스키를 잃었을 때 다시 들어오는 방법이에요.
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
- **비밀번호 변경·제거**: **설정 → 암호**에서 현재 비밀번호와 새 비밀번호(두 번)를 넣으면 바뀌어요. 보관함이
  새 데이터 키로 다시 암호화되므로 등록한 패스키는 지워지고(필요하면 다시 등록하세요), 열려 있는 다른 창은
  잠겨요. 전에 내보낸 백업은 이전 비밀번호 그대로예요. **암호 제거**는 현재 비밀번호를 넣은 뒤 빨간 경고를 두
  번 확인해야 해요. 그 뒤로는 묻지 않고 열려요. 계정은 이 컴퓨터에서 이 브라우저가 만든 임의의 키로 계속
  암호화되고, 이 키는 *추출 불가*로 보관돼서 확장 프로그램도 쓰기만 할 뿐 읽을 수 없고, 내보내거나 동기화되지
  않아요. 다만 브라우저는 이 키를 프로필 파일에 저장하므로, 브라우저 프로필을 복사할 수 있는 사람은 보관함을
  풀 수 있어요. 디스크 시리얼이나 "컴퓨터 지문"은 쓰지 않아요. 확장 프로그램은 디스크 시리얼을 읽을 수 없고,
  지문은 드라이버 업데이트나 모니터 교체로 바뀌어 영영 못 열게 될 수 있어서예요. 비밀번호가 없으면 잠그기
  버튼과 자동 잠금이 없고, 백업은 그 파일에만 쓸 비밀번호를 따로 물어요. **이 브라우저 프로필을 쓸 수 있는
  누구나 코드를 볼 수 있고**, 프로필이나 확장 프로그램 데이터를 잃으면 백업으로만 되찾을 수 있어요. 언제든
  **암호 설정**으로 다시 비밀번호를 정할 수 있고, 그러면 브라우저의 키는 지워져요.
- **백업**: 설정에서 암호화된 백업을 `.json` 파일로 내보내고, 가져올 때는 그 백업을 만들 때 쓴 비밀번호를
  입력해요. 백업에는 패스키가 들어가지 않고, 가져와도 패스키는 등록되지 않아요. 계정만 가져오고 자동 입력
  사이트는 다시 설정해야 해요. 비밀번호가 없는 보관함은 백업 파일에 쓸 비밀번호를 물어요. 그 파일은 보관함과
  공유하지 않는 별도 키로 암호화돼요.
  - 비밀번호는 확장 프로그램이 백업을 가져오는 방법일 뿐, 백업을 풀 수 있는 유일한 키는 아니에요. 백업의
    계정은 원래 보관함과 같은 데이터 키(DEK)로 암호화되고, 백업에서 패스키를 빼거나 보관함에서 패스키를
    삭제해도 그 키는 바뀌지 않아요. 그 DEK를 가진 사람은 비밀번호 없이 백업과, 보관함이 나중에 같은 DEK로
    암호화한 데이터를 풀 수 있어요. 예를 들어 패스키 슬롯이 남은 이전 보관함 복사본과 그에 맞는 인증기·사용자
    확인을 가진 사람, 또는 잠금이 풀린 세션에서 DEK를 가져간 사람이에요.
  - 패스키를 등록하기 전에 내보낸 백업은 이전 비밀번호 키를 써요. 등록할 때 새 DEK를 만들기 때문이에요.
- **계정 내보내기**: **설정 → 백업 → 계정 내보내기**에서 비밀번호를 다시 입력하고(비밀번호가 없는 보관함은
  건너뛰어요) 계정을 하나 이상 고르면 돼요. **링크 복사**는 `otpauth://` 링크를 한 줄에 하나씩 클립보드에
  넣어요(zauthenticator의 계정 추가도 이 형식을 읽어요). **QR 보기**는 팝업 안에 QR 코드를 그려요. 계정
  하나면 어떤 OTP 앱으로도 스캔하는 `otpauth://` QR이고(Google Authenticator: **+ → QR 코드 스캔**), 여러
  개면 Google Authenticator 이전 QR이에요. 휴대폰에서 **계정 이전 → 계정 가져오기**를 열고 QR을 순서대로
  스캔하세요. Google 형식에는 30초가 아닌 주기나 7자리 코드를 넣을 수 없어서 그런 계정은 따로 otpauth QR로
  이어져요. **계정마다 QR 하나**를 고르면 모든 계정을 otpauth QR로 보여 줘요. 링크와 QR에는 비밀 키가 그대로
  들어 있으니 다른 사람이 보지 않게 하세요. 화면을 떠나거나 잠그면 지워지지만, 복사한 글자는 다른 걸 복사할
  때까지 클립보드에 남아요.
- **0.2.0으로 돌아가려면**: 0.2.0은 처음 보관함 형식만 읽어요. 패스키를 등록하거나 비밀번호를 바꾸거나
  없애면 보관함이 새 형식으로 바뀌고, 나중에 패스키를 삭제해도 이전 형식으로 돌아가지 않아요. 0.2.0은 바뀐
  보관함을 열 수 없고, 거기서 내보낸 백업도 가져올 수 없어요. **바꾸기 전에 백업을 내보내 두세요.** 그래야
  0.2.0이 읽을 수 있는 복사본이 남아요.

### 개인정보와 보안

- 비밀 키, 계정 이름, 자동 입력 사이트는 이 기기의 브라우저 저장소에 AES-256-GCM으로 암호화된 보관함 안에만
  있어요. 비밀번호가 있으면 키는 비밀번호에서 만들고(PBKDF2-SHA-256, 60만 회) 비밀번호 자체는 저장하지 않아요.
  패스키는 같은 데이터 키를 여는 두 번째 방법이에요. 비밀번호가 없으면 브라우저가 이 확장 프로그램을 위해
  추출 불가로 보관하는 키가 보관함을 지켜요. 개발자에게도, 다른 누구에게도 보내지 않고, 서버도 없어요.
- 잠금이 풀려 있는 동안 브라우저 세션 메모리에는 풀린 키, 연장한 잠금 해제 시각, 짧은 자동 입력 기록이 있어요.
  자동 입력 기록에는 코드를 받은 탭과 허용한 사이트마다 탭 번호, 사이트 주소, 계정의 내부 ID, 몇 번째 코드
  주기였는지와 그 시각을 적고, 코드 자체는 적지 않아요. 한 탭에서 한 사이트가 5분에 코드를 3개까지만 받고 같은
  코드를 두 번 받지 않게 하려고만 써요. 잠그면 모두 지워져요.
- 사이트가 받는 건 입력된 6–8자리 코드뿐이에요. 그 사이트의 스크립트는 직접 입력했을 때처럼 이 코드를 읽을
  수 있어요. 비밀 키, 계정 이름, 비밀번호는 페이지에 닿지 않아요.
- 패스키 요청은 확장 프로그램이 아니라 브라우저가 처리해요. 브라우저는 확장 프로그램 ID(RP), 인증 정보 ID,
  챌린지, PRF 솔트를 인증기에 보내요. 인증기는 브라우저의 QR 코드로 연결한 휴대폰일 수도 있어요. 패스키
  제공자는 확장 프로그램과 별개로 패스키를 다른 기기에 동기화할 수 있어요. TOTP 비밀 키와 보관함 내용은 보내지
  않아요.
- 팝업에서 **이 페이지 스캔** 버튼을 누를 때만 지금 탭에서 보이는 부분을 한 장 캡처해요. 이 이미지는 팝업
  안에서 QR 디코더로 읽는 동안만 메모리에 있고, 저장하거나 보내지 않아요. 올바른 2단계 인증 QR 코드라면 거기서
  찾은 계정만 보관함에 추가해요. 자동 입력을 허용한 사이트에서는 코드 입력란을 찾으려고 입력란의 속성(이름,
  레이블, placeholder 등)을 읽고, 읽은 내용은 남기지 않아요.
- 브라우저는 확장 프로그램이 접근할 수 있는 사이트 목록과 자동 입력 스크립트가 등록된 사이트 목록을 보관함
  밖에 따로 기록해요. 브라우저 프로필을 읽을 수 있는 사람은 이 사이트 이름을 볼 수 있어요.
- 권한: `storage`(암호화된 보관함 저장), `activeTab`(툴바 아이콘이나 오른쪽 클릭 메뉴를 쓴 그 탭에서만 QR
  스캔·코드 입력), `contextMenus`(오른쪽 클릭 메뉴), `scripting`(코드 입력과 자동 입력 등록), 그리고 허용한
  사이트 하나씩만 받는 선택적 `https` 사이트 접근이에요. 설치할 때는 어떤 사이트 권한도 받지 않아요.
- 알아 둘 한계: 컴퓨터 시계가 틀리면 코드도 틀려요. 보관함 동기화는 일부러 넣지 않았어요(패스키 제공자는
  패스키를 따로 동기화할 수 있어요). 백업 파일이나 브라우저 프로필을 가진 사람은 비밀번호를 오프라인에서 추측해
  볼 수 있으니 긴 비밀번호를 쓰세요. 패스키 슬롯이 있는 프로필 복사본은 그에 맞는 인증기와 사용자 확인으로도
  열려요. 사용자 계정으로 실행되는 악성 코드, 손상된 브라우저, 잠금이 풀린 브라우저를 쓰는 사람은 막지 못하고,
  복사한 코드는 다른 앱도 읽을 수 있는 클립보드에 남아요. 비밀번호가 없으면 보관함의 안전은 브라우저 프로필에
  달려 있고, 잠금 해제를 연장하면 끝날 때까지 이 브라우저를 쓰는 사람과 AI 에이전트 누구나 코드를 쓸 수 있어요.
- 자세한 내용은 [개인정보처리방침](PRIVACY.md)(영문), [보안 정책](SECURITY.md)(영문),
  [신뢰 주장 검사 방법](docs/trust.md)(영문)에 있어요.

### 개발

`npm ci` 후 `npm test`, `npm run check`, `node scripts/check-policy.mjs --self-test`, `npm run e2e`,
`npm run zip`을 실행해요. `v<버전>` 태그를 올리면 릴리스 워크플로가 GitHub 릴리스를 만들고 같은 zip을
Microsoft Edge 추가 기능에 심사 요청으로 올려요. 자세한 내용은 영문 [Development](#development)에 있어요.
라이선스는 MIT예요.
