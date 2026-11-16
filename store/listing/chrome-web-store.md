# Chrome Web Store listing: zauthenticator 0.2.0

Everything to paste into the Chrome Web Store Developer Dashboard, tab by tab. Requirements were
checked against the official documentation on 2026-11-16; each one names its source. A value the
documentation does not state is marked **unverified**: confirm it in the dashboard itself.

The detailed descriptions below are also used for Microsoft Edge Add-ons
([edge-addons.md](edge-addons.md)). Edge forbids naming other browsers, so keep these texts free of
browser names, and change both listings together. The test notes live in
[edge-addons.md](edge-addons.md#notes-for-certification) and serve both stores.

## Package

- **File to upload:** `zauthenticator-0.2.0.zip`, the asset of the GitHub release `v0.2.0`
  (built by the release workflow from the tagged commit). Locally, `npm run zip` builds the same
  file as `dist/zauthenticator-0.2.0.zip` and prints its sha256; compare it with the release notes.
- **Manifest at the zip root:** required ("place the manifest file in the root directory, not in a
  folder"). `scripts/build-zip.mjs` refuses to finish otherwise.
  source: https://developer.chrome.com/docs/webstore/prepare, checked 2026-11-16
- **Version must grow:** every upload needs a larger `version` than the previous one.
  source: https://developer.chrome.com/docs/webstore/prepare, checked 2026-11-16
- Size limit 2 GB (the zip is far below).
  source: https://developer.chrome.com/docs/webstore/publish, checked 2026-11-16

## Store listing tab

### Item name and summary (from the package, not typed in the dashboard)

- **Name:** `zauthenticator` (manifest `name` → `extName`).
- **Summary:** the manifest `description` (`extDescription` in `extension/_locales/*/messages.json`).
  Limit: no more than 132 characters, plain text.
  source: https://developer.chrome.com/docs/extensions/reference/manifest/description, checked 2026-11-16
  source: https://developer.chrome.com/docs/webstore/best-listing, checked 2026-11-16

| Locale | Summary (must equal `extDescription`) | Characters |
|---|---|---|
| en | Open-source two-factor (TOTP) authenticator. Codes are made on your device, secrets stay encrypted, auto-fill is opt-in per site. | 129 |
| ko | 오픈소스 2단계 인증(TOTP) 앱이에요. 코드는 이 기기에서 만들고 비밀 키는 암호화해 보관해요. 자동 입력은 허용한 사이트에서만 해요. | 77 |

To change a summary, edit `extDescription` in the locale files, release a new version and upload
it; the dashboard takes it from the package.

### Detailed description

Guidance: start with what the item does, then a short list of main features; no keyword stuffing,
superlatives or references to competing extensions.
source: https://developer.chrome.com/docs/webstore/cws-dashboard-listing, checked 2026-11-16
source: https://developer.chrome.com/docs/webstore/best-listing, checked 2026-11-16
Maximum length: **unverified** (the docs give none).

**English (en):**

```text
zauthenticator shows the two-factor (TOTP) codes you use to sign in, and keeps the secret keys behind them on your device, encrypted with your passphrase.

Features
- Add an account by scanning a QR code on the current page, from a QR image, from otpauth:// links, or by typing the setup key.
- Click a code to copy it. A countdown shows when the next code starts.
- Fill a code into a site: right-click the code field and choose the account.
- Optional auto-fill: allow a site once, and on later visits the code field is filled for you while zauthenticator is unlocked. Until you submit, an expiring code is replaced with the new one (at most twice), and if the site rejects the code a fresh one is filled once; the same code is never filled twice, and a site gets at most 3 codes per tab in 5 minutes. Auto-fill stops as soon as you type or delete in the field, leave the page, or lock, and it never submits a form.
- Export and import an encrypted backup.
- Locks when you click Lock, after 15 minutes without use, and when the browser quits.
- English and Korean.

Privacy
- No account, no sync, no analytics, no telemetry. The extension's pages and its background worker cannot connect to any server.
- Secret keys, account names and auto-fill sites are stored only on your device, in a vault encrypted with AES-256-GCM under a key derived from your passphrase (PBKDF2-SHA-256, 600,000 iterations). The passphrase is never stored.
- A site receives only the 6-8 digit code, and only when you allowed that site or right-clicked its field.
- Scanning a QR code on the current page takes one picture of the visible part of that tab, only when you click the scan button. It is decoded on your device and never stored or sent.
- No site access is granted at install. When you allow auto-fill on a site, the browser asks for access to that one site; removing the site gives the access up.

Good to know
- The passphrase cannot be recovered. Backups are encrypted with the same passphrase, so a backup protects you against losing the device or browser profile, not against forgetting the passphrase.
- Codes are computed from your computer's clock, so keep its time set automatically.
- Uninstalling the extension deletes its vault.

Open source (MIT): https://github.com/2lab-ai/zauthenticator
```

**Korean (ko):**

```text
zauthenticator는 로그인할 때 쓰는 2단계 인증(TOTP) 코드를 보여 주는 확장 프로그램이에요. 코드를 만드는 비밀 키는 마스터 비밀번호로 암호화해서 이 기기에만 보관해요.

기능
- 지금 보고 있는 페이지의 QR 코드, QR 이미지, otpauth:// 링크, 설정 키 직접 입력 중 편한 방법으로 계정을 추가해요.
- 코드를 클릭하면 복사돼요. 다음 코드까지 남은 시간도 보여요.
- 사이트의 코드 입력란에서 마우스 오른쪽 버튼을 누르고 계정을 고르면 코드가 입력돼요.
- 원하면 자동 입력도 돼요. 사이트를 한 번 허용해 두면 다음부터는 잠금이 풀려 있는 동안 코드 입력란을 자동으로 채워요. 입력한 코드가 제출 전에 만료되면 새 코드로 바꾸고(최대 두 번), 사이트가 코드를 거부하면 새 코드로 한 번 다시 채워요. 같은 코드를 두 번 넣지 않고, 한 탭에서 한 사이트에 넣는 코드는 5분에 3개까지예요. 입력란에 직접 입력하거나 지우면, 페이지를 떠나면, 잠기면 바로 멈춰요. 폼을 제출하지는 않아요.
- 암호화된 백업을 내보내고 가져올 수 있어요.
- 잠그기 버튼을 누르거나, 15분 동안 쓰지 않거나, 브라우저를 종료하면 잠겨요.
- 한국어와 영어를 지원해요.

개인정보
- 회원 가입, 동기화, 사용 통계 수집이 없어요. 확장 프로그램 화면과 백그라운드 워커는 어떤 서버에도 연결할 수 없어요.
- 비밀 키, 계정 이름, 자동 입력 사이트는 이 기기에만 저장돼요. 마스터 비밀번호에서 만든 키(PBKDF2-SHA-256, 60만 회 반복)로 AES-256-GCM 암호화해요. 비밀번호 자체는 저장하지 않아요.
- 사이트가 받는 건 6–8자리 코드뿐이고, 허용한 사이트나 직접 오른쪽 클릭한 입력란에만 들어가요.
- 지금 페이지의 QR 코드를 스캔할 때는 **이 페이지 스캔** 버튼을 누른 순간에만 탭에서 보이는 부분을 한 장 캡처해요. 이 이미지는 기기 안에서 읽고, 저장하거나 보내지 않아요.
- 설치할 때는 사이트 접근 권한을 받지 않아요. 자동 입력을 허용하면 브라우저가 그 사이트 하나에 접근해도 되는지 묻고, 설정의 자동 입력 사이트에서 삭제하면 그 권한도 반납해요.

알아 둘 점
- 마스터 비밀번호는 복구할 수 없어요. 백업도 같은 비밀번호로 암호화되기 때문에, 비밀번호를 잊었을 때는 도움이 되지 않아요. 백업은 기기나 브라우저 프로필을 잃었을 때를 위한 거예요.
- 코드는 컴퓨터 시계로 계산해요. 시간이 자동으로 맞춰지도록 설정해 두세요.
- 확장 프로그램을 삭제하면 보관함도 함께 지워져요.

오픈소스(MIT): https://github.com/2lab-ai/zauthenticator
```

### Category and language

- **Category:** Privacy & Security. The category exists on the store (its page is
  `https://chromewebstore.google.com/category/extensions/make_chrome_yours/privacy`, group "Make
  Chrome Yours"); the exact label in the dashboard dropdown is **unverified**.
  source: https://chromewebstore.google.com/category/extensions/make_chrome_yours/privacy, checked 2026-11-16
- **Language:** English (the package's `default_locale` is `en`), plus a localized Korean listing.
  The description, screenshots and video can be localized; the promo tiles cannot.
  source: https://developer.chrome.com/docs/webstore/cws-dashboard-listing, checked 2026-11-16
  How the dashboard offers the Korean listing (from the package's `_locales/ko`) is **unverified**.

### Graphic assets

| Asset | File | Required | Size and format |
|---|---|---|---|
| Store icon | `store/assets/chrome-icon-128.png` | yes | 128×128 PNG; artwork about 96×96 with 16 px transparent padding per side |
| Screenshots | `store/assets/screenshots/1-codes.png`, `store/assets/screenshots/2-autofill.png`, `store/assets/screenshots/3-bind.png`, `store/assets/screenshots/4-add.png`, `store/assets/screenshots/5-settings.png` | at least 1, up to 5 | 1280×800 (or 640×400), square corners, no padding (full bleed); shown downscaled to 640×400 |
| Small promo tile | `store/assets/promo-small-440x280.png` | no | 440×280, PNG or JPEG; not localizable |
| Marquee promo tile | `store/assets/promo-marquee-1400x560.png` | no (needed to be featured in the marquee) | 1400×560, PNG or JPEG; not localizable |
| YouTube video | none | no | |

The package itself must also contain a 128×128 PNG icon (`extension/icons/128.png`).
source: https://developer.chrome.com/docs/webstore/images, checked 2026-11-16
source: https://developer.chrome.com/docs/webstore/cws-dashboard-listing, checked 2026-11-16

### Additional fields

| Field | Value |
|---|---|
| Official URL | leave empty (it lists only sites verified in Search Console) |
| Homepage URL | `https://github.com/2lab-ai/zauthenticator` |
| Support URL | `https://github.com/2lab-ai/zauthenticator/issues` |
| Mature content | off |

source: https://developer.chrome.com/docs/webstore/cws-dashboard-listing, checked 2026-11-16

## Privacy practices tab

Fields: single purpose, a justification per permission, remote code, data usage, privacy policy.
source: https://developer.chrome.com/docs/webstore/cws-dashboard-privacy, checked 2026-11-16
Single purpose rule: "An extension must have a single purpose that is narrow and easy to
understand." source: https://developer.chrome.com/docs/webstore/program-policies/quality-guidelines, checked 2026-11-16

### Single purpose description

```text
zauthenticator generates time-based one-time passwords (TOTP, RFC 6238) for the user's two-factor accounts, so the user can copy a code or have it filled into the code field of a site they chose. Everything else it does (adding accounts from QR codes or setup keys, an encrypted backup, locking) serves that purpose.
```

### Permission justifications

**storage**

```text
Stores the user's vault (TOTP secret keys, account names and the sites chosen for auto-fill) in local extension storage, encrypted with AES-256-GCM under a key derived from the user's passphrase, and keeps the unlocked key in session storage (in memory) until the user locks or the browser quits; after 15 minutes without use, the next read removes the key before any code is shown or filled. While unlocked, session storage also holds a small auto-fill record (per tab and allowed site: tab id, site origin, account id, TOTP period number and time; never a code) so that a site gets at most 3 codes per tab in 5 minutes and never the same code twice; entries older than 5 minutes are dropped on the next update and a lock removes the record. Nothing is sent anywhere.
```

**activeTab**

```text
Used only right after a user gesture. (1) When the user clicks the toolbar icon and chooses to scan the page, the visible part of that tab is captured once (one JPEG) to read a QR code that sets up a two-factor account; the picture is decoded in the popup, held in memory only for that, and never stored or sent. (2) When the user chooses an account in the right-click menu, that account's current code is typed into the field the user right-clicked. There is no access to any tab otherwise.
```

**contextMenus**

```text
Adds a "zauthenticator" item to the right-click menu of editable fields. It lists the user's accounts (or "Unlock zauthenticator…" while locked) so the user can choose which code to fill into the field.
```

**scripting**

```text
Two uses, both with code bundled in the package. (1) After the user chooses an account in the right-click menu, executeScript runs one bundled function in the clicked frame; it types the code into the focused field, and only if the frame is still on the origin where the menu was opened. (2) registerContentScripts registers the bundled auto-fill script (lib/fieldfind.js and content/autofill.js) for the exact sites the user allowed, and for no others. No CSS is injected and no remote code is run.
```

**Host permission (optional `https://*/*`)**

```text
Declared only as an optional host permission and requested one exact origin at a time. When the user clicks "Allow" in the extension's "Fill codes automatically?" window, the browser's own prompt asks for access to that single site (https://<host>/*). The access lets the bundled auto-fill script run there on later visits and fill the code field. Nothing is granted at install, and the access is removed when the user removes the site in Settings. The extension makes no network requests: its pages and service worker have the CSP connect-src 'none'.
```

**Background service worker** (the dashboard has no field for it; use this if a reviewer asks)

```text
The module service worker (background.js) builds the right-click menu, fills a chosen account's code through the scripting API, answers the auto-fill script's request for a code only when the request comes from this extension's own script on a site the user allowed and the vault is unlocked (the answer is the code and how long it stays valid, never account names or secrets), and keeps the auto-fill registrations in line with the sites the user allowed.
```

### Remote code

Choose **"No, I am not using remote code."** Manifest V3 does not allow remotely hosted code.
source: https://developer.chrome.com/docs/webstore/cws-dashboard-privacy, checked 2026-11-16

If a justification box is shown anyway:

```text
All code is in the package. The extension pages' CSP is script-src 'self' without unsafe-eval or unsafe-inline, and the code contains no eval, new Function, importScripts or remote script loading. The only third-party code is the QR decoder jsQR 1.4.0, bundled unmodified.
```

### Data usage

Rules (checked 2026-11-16):

- The User Data FAQ, question "Does an extension need to disclose user data handling if the data is
  only processed or stored locally on a user's device?", answers: "Yes. Extensions are required to
  disclose how they handle user data, even when data is processed or stored locally on a user's
  device and is not transmitted to external servers or third parties."
  source: https://developer.chrome.com/docs/webstore/program-policies/user-data-faq, checked 2026-11-16
- The same FAQ lists "Authentication information (such as logins, password, and authentication
  cookies)" among the examples of user data, and says any discrepancy between the dashboard
  disclosures, the privacy policy and the item's behaviour violates the program policies.
  source: https://developer.chrome.com/docs/webstore/program-policies/user-data-faq, checked 2026-11-16
- Items that handle user data must post a privacy policy, even when the data is stored only
  locally, and must show a Limited Use disclosure on the homepage or one click away (PRIVACY.md,
  linked from the README, carries it).
  source: https://developer.chrome.com/docs/webstore/program-policies/user-data-faq, checked 2026-11-16

**What user data do you plan to collect from users now or in the future?** Recommended answer
below. **The checkbox labels in this table are unverified**: the docs show the dashboard only as a
screenshot, so these names come from memory and from the FAQ's list of user data. Map each one by
meaning to what the dashboard shows.

| Checkbox (label unverified) | Tick | Why |
|---|---|---|
| Authentication information | **yes** | TOTP secret keys and account names (logins) are stored in the encrypted vault on the device. While unlocked, an auto-fill record in session memory (tab id, site origin, account id, TOTP period number, time; never a code) limits a site to 3 codes per tab in 5 minutes and no repeated code; a lock removes it. Nothing is sent to the developer. |
| Personally identifiable information | no | Account names are covered above as logins; nothing else about the person is handled. |
| Health information | no | |
| Financial and payment information | no | |
| Personal communications | no | |
| Location | no | |
| Web history | no (see Tensions) | The vault holds only the sites you chose for auto-fill. The session auto-fill record notes, for those sites only, when a code was given (to enforce the 5-minute limit) and is removed on lock. No list of pages visited and no page titles are kept. |
| User activity | no | The extension does not monitor clicks, keystrokes, mouse movement or scrolling. The auto-fill script only compares the value of the field it filled with the code it put there, to stop when you change it. |
| Website content | **yes** | When you click the scan button, a picture of the visible part of the current tab is decoded locally to read a QR code. On sites you allowed, the auto-fill script reads input-field attributes (and whether a field is empty) to find the code field. |

**Certifications:** tick all three. The dashboard wording is **unverified** (screenshot only in the
docs); in meaning they are: user data is not sold or transferred to third parties outside the
approved use cases; it is not used or transferred for purposes unrelated to the item's single
purpose; it is not used or transferred to determine creditworthiness or for lending.
source: https://developer.chrome.com/docs/webstore/program-policies/limited-use, checked 2026-11-16

#### Tensions

The disclosures describe what the extension does. When its behaviour changes, update the ticks
here, the Edge answers and PRIVACY.md together.

- **"Nothing collected" versus ticking what is handled on the device.** One reading of the question is
  "what leaves the device": nothing does, so nothing would be ticked, and some authenticator
  listings on the store show "will not collect or use your data". The User Data FAQ quoted above
  takes the other reading: data handled only on the device must be disclosed too. This kit
  follows the FAQ: the extension handles authentication information and reads website content on
  the device, so both are ticked, and PRIVACY.md describes the same handling in words.
- **Web history.** The FAQ counts "the domains or URLs the browser interacts with" as user data.
  What the extension does with site addresses: the vault holds the exact sites you yourself chose
  for auto-fill (a setting you made, shown and removable in Settings), and the worker looks at the
  origin of the page you right-clicked or of the frame whose auto-fill script asks for a code, only
  to decide whether to fill there. While unlocked, the session auto-fill record also notes, per
  tab, which of those allowed sites got a code and when; entries older than 5 minutes stop
  counting and are dropped on the next update, and a lock removes the record. It keeps no list of
  pages you visit and no page titles, and nothing about sites you did not allow. Default: not
  ticked, because this is a rate limit on sites you chose, not a record of browsing. Tick it if
  the dashboard's description of this box covers any stored site address or visit time, or if a
  reviewer reads it that way, and keep the Edge answer the same.

### Privacy policy URL

`https://github.com/2lab-ai/zauthenticator/blob/main/PRIVACY.md`

It must be reachable when you submit, so merge it to `main` first. The policy must say how data is
collected, used and disclosed, and match the disclosures above.
source: https://developer.chrome.com/docs/webstore/cws-dashboard-privacy, checked 2026-11-16

## Distribution tab

- **Visibility:** Public ("lists your item on the Chrome Web Store for all users to see and
  install"). Unlisted and Private also exist.
- **Regions:** All regions.
- **Payments:** free (no in-app purchases). How the dashboard words this is **unverified**.
source: https://developer.chrome.com/docs/webstore/cws-dashboard-distribution, checked 2026-11-16

## Test instructions tab

Optional ("only if needed"). No login is needed; paste the
[Notes for certification](edge-addons.md#notes-for-certification) text so the reviewer can reach
the auto-fill part quickly.
source: https://developer.chrome.com/docs/webstore/publish, checked 2026-11-16
