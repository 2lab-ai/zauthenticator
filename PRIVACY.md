# Privacy policy

**zauthenticator** browser extension. Effective date: 2026-11-25.

In short: zauthenticator keeps your data on your device, encrypted with your passphrase. The
developer receives nothing. The extension has no server, no account, no analytics and no
telemetry, and it does not sell, share or transfer your data. From version 0.3 you can also
unlock it with a passkey; the browser then exchanges a few values with your own authenticator, as
described under [Passkey unlock](#passkey-unlock-from-version-03). From version 0.4 you can remove
the passphrase; the vault then stays encrypted with a key that only this browser keeps
([Without a passphrase](#without-a-passphrase-from-version-04)).

## Data the extension stores on your device

The extension handles the data you give it so that it can show your two-factor codes and fill them
where you choose:

- **Secret keys** of your two-factor (TOTP) accounts, and their settings (algorithm, number of
  digits, period).
- **Account names**: the service and account name of each entry, for example a service name and
  your username or email address for it.
- **Auto-fill sites**: the exact site addresses (scheme, host and port) where you allowed
  auto-fill, and which account each one uses.

All of this is stored only in the browser's storage for this extension, on your device, inside a
vault encrypted with AES-256-GCM. The encryption key is derived from your passphrase with
PBKDF2-SHA-256 (600,000 iterations).

From version 0.3, once you enroll a passkey, the vault is encrypted with a random data key
instead, and that data key is stored encrypted twice: with a key derived from your passphrase
(PBKDF2-SHA-256, as before) and with a key derived (HKDF-SHA-256) from your authenticator's PRF
output. Outside the encrypted part, the vault then also holds the passkey's credential ID, the
PRF input (a random salt), the label you gave the passkey, when it was added, and the encrypted
data key with its IV. Anyone who can read your browser profile can see these, the label included.
They do not include the PRF output or the data key in plain form, and your secrets stay
encrypted. A vault that never had a passkey keeps the earlier format.

- **Your passphrase is never stored.** After you unlock, the derived key is kept in the browser's
  session storage, in memory, until you lock or the browser quits. After 15 minutes without use,
  the next time the extension reads the key (opening the popup, a menu choice or an auto-fill
  request) it removes the key before any code is shown or filled. From version 0.3, session
  storage holds the key together with the vault's version and identity, and also a random lock
  counter (`lockGen`) that is not secret: each lock replaces it instead of removing it, so a
  passkey request started before a lock cannot be used after it.
- **The auto-fill record.** While the extension is unlocked, the same session storage (in memory,
  not encrypted) also holds a short record of what auto-fill was given: for each tab and allowed
  site that received a code, the tab number, the site's address (origin), the account's internal
  id, the number of the TOTP period the code belonged to, and the time. It never holds a code. It
  exists only so that a site gets at most 3 codes per tab in 5 minutes and never the same code
  twice. Entries older than 5 minutes no longer count and are dropped the next time the record
  is updated; choosing an account from the right-click menu clears the entries for that tab and
  site; every lock removes the whole record together with the key, and it is gone when the
  browser quits.
- **Backup files** that you export contain the vault as stored, still encrypted, and the
  extension imports one only with the passphrase it was made with. They are saved where you
  choose, and the extension does not send them anywhere. From version 0.3, a backup of a vault
  with a passkey leaves the passkey out, and importing a backup never adds a passkey. The
  passphrase is how the extension imports a backup, not the only key that can decrypt it: the
  backup's data is encrypted under the same data key as the vault it came from, and leaving the
  passkey out of the backup, or removing the passkey from the vault, does not change that key.
  Someone who holds that key can decrypt the backup, and data the vault encrypts later under the
  same key, without the passphrase: for example someone with an older copy of the vault that still
  has the passkey slot together with the matching authenticator and its user verification, or
  someone who took the key from an unlocked session. Backups exported before you enrolled use the
  earlier passphrase key, because enrolling draws a new data key.
- **Codes you copy** are placed on your system clipboard, where other applications on your device
  can read them.
- **Exported links and QR codes** (from version 0.4): when you export accounts, the extension
  shows QR codes in the popup or copies `otpauth://` links to your clipboard. They contain the
  secret keys and account names in plain form, so anyone who sees the QR code or the copied text
  can generate your codes. They are made on your device only when you ask, are not stored or sent
  by the extension, and leave the screen when you leave the export view or lock; copied text stays
  on your clipboard until something replaces it.
- **The unlock time** (from version 0.4): if you extend the unlock time, session storage (in
  memory) also holds when the extension is to end it (`unlockedUntil`). Every lock removes it.

## Without a passphrase (from version 0.4)

If you remove the passphrase (Settings, after two confirmations), the vault is encrypted again
under a new random data key, and that data key is stored encrypted with a device key: a random
AES-256 key that the browser generates on your computer as non-extractable (WebCrypto) and keeps in
the extension's IndexedDB storage, in this browser profile. The extension can encrypt and decrypt
with it but cannot read its value, and it never leaves the browser profile; backups and exports
never contain it. The extension does not read disk serial numbers or build a fingerprint of your
computer. Without a passphrase, the extension opens without asking and does not lock for time, so
anyone who can use this browser profile, or copy it whole, can see your codes. Setting a
passphrase again deletes the device key.

## What the extension reads from web pages

- **A picture of the current tab, only when you scan it.** When you click the button to scan the
  current page in the popup, the extension takes one picture (JPEG) of the visible part of that
  tab. The browser allows this only for the tab where you just clicked the extension's toolbar
  icon. The picture is decoded inside the popup by the QR decoder bundled with the extension and
  is held in memory only for that decoding; it is never stored or sent. If it contains a valid
  two-factor (otpauth) QR code, only the account read from it is added to your vault.
- **Input fields on sites where you allowed auto-fill.** To find the code field, the auto-fill
  script looks at the page's input fields (attributes such as type, name, id, label, placeholder
  and autocomplete, and whether a field is empty). It does this inside the page and keeps none of
  what it reads.

## What leaves the extension

To web pages, only the one-time code (6 to 8 digits), typed into the page:

- into the field you right-clicked, after you choose an account from the menu, or
- into the code field of a site where you allowed auto-fill, while the extension is unlocked.
  Until you submit, a newer code may replace it when the filled one expires or the site rejects
  it.

The page receives the code as if you had typed it, and its scripts can read it. The secret key,
the account names and the passphrase never reach any page. From version 0.3, passkey unlock also
involves your authenticator, as described next.

## Passkey unlock (from version 0.3)

Passkey unlock is optional. To enroll, you open Settings in a full tab, enter your passphrase
again, and approve two requests from the browser: one creates the passkey, one uses it. Unlocking
runs in a separate window. The passphrase keeps working and stays the way back in.

During these requests the browser, not the extension, talks to your authenticator, which may be a
phone, a security key or the computer's own passkey store. It sends the relying party (the
extension's ID), the credential ID, a challenge and the PRF salt. The authenticator returns the
PRF output only after it verifies you; the extension uses it to decrypt the data key and does not
store it. Your passkey provider may sync the passkey to your other devices, independently of the
extension. Your TOTP secrets and the vault's contents are never sent to the authenticator or the
provider. This exchange is carried by the browser, outside the extension's content security
policy, which governs only the extension's own network requests.

A passkey is bound to the extension's ID, which differs between the store versions and a manual
install, so each installation enrolls its own. Removing the passkey in Settings removes it from
this vault only; delete it on the phone, key or password manager too. Older copies of the vault,
such as a copied browser profile, keep their passkey slot.

## What the extension does not do

- It does not send what it stores to the developer or to anyone else, and it does not sell, share
  or transfer data. The only exception is the passkey values above, which the browser passes to
  your own authenticator (from version 0.3). The developer has no server and cannot see your data.
- It does not use analytics, telemetry, crash reporting or advertising.
- Its own pages and its background worker cannot connect to any server: their content security
  policy blocks every network connection and remote resource. Passkey requests (from version 0.3)
  are made by the browser, as described above.
- It does not load or run remote code. Everything it runs is in the package you install.
- It does not sync the vault. Each browser profile has its own vault; a passkey provider may sync
  the passkey itself.

## What your browser records

Outside the encrypted vault, the browser itself keeps:

- the list of sites you gave the extension access to (shown on the extension's details page in
  the browser), and
- the list of sites its auto-fill script is registered for.

Anyone who can read your browser profile can see those site names. If you installed the extension
from a browser's add-on store, the browser checks that store for updates, as it does for every
extension installed from there; the extension itself takes no part in that.

## Your controls

- **See your data**: the popup lists your accounts, and Settings lists your auto-fill sites.
- **Export and import** an encrypted backup from Settings. From version 0.4, **export accounts**
  as links or QR codes to move them to another app.
- **Change or remove the passphrase** (from version 0.4) in Settings, or set one again.
- **Delete** an account (its auto-fill sites go with it), or **remove** an auto-fill site, which
  also gives up the extension's access to that site. You can also remove site access from the
  extension's details page in the browser.
- **Remove a passkey** (from version 0.3) in Settings; delete it from the phone, key or password
  manager too. This does not change backups or older copies already made.
- **Lock** the vault at any time; it also locks 15 minutes after the last use (or, from version 0.4,
  when an unlock time you extended ends) and when the browser quits. Without a passphrase it does
  not lock.
- **Uninstall** the extension to delete everything it stored, including the vault.

## Store policies

The extension uses the data above only to provide its single purpose: generating two-factor codes
and filling them where you choose (from version 0.3, also unlocking the vault with a passkey you
enrolled). No person reads it, and the extension does not transfer it to the developer or to any
third party. This use of information complies with the Chrome Web Store User Data Policy,
including the Limited Use requirements, and with the developer policies of Microsoft Edge Add-ons.

## Changes

This policy lives in the extension's public source repository. Any change is made there, with the
effective date above updated, and the repository's history shows every earlier version.

## 한국어 요약: 패스키 잠금 해제 (0.3부터)

0.3부터는 패스키로도 잠금을 풀 수 있어요(선택 사항). 설정을 전체 탭으로 열어 비밀번호를 다시 입력하고,
브라우저의 요청 두 번(패스키 만들기, 패스키 쓰기)을 승인하면 등록돼요. 잠금 해제는 별도 창에서 해요.
비밀번호는 계속 쓸 수 있고, 패스키를 잃었을 때 다시 들어오는 방법이에요.

- 패스키를 등록하면 보관함은 임의의 데이터 키로 암호화되고, 그 키는 비밀번호에서 만든 키(PBKDF2)와
  인증기의 PRF 출력에서 만든 키(HKDF)로 각각 암호화해 두 번 저장돼요. 암호화된 부분 밖에는 패스키의
  인증 정보 ID, PRF 입력(임의의 솔트), 붙인 이름, 등록 시각, 암호화된 데이터 키와 IV가 저장돼요. 브라우저
  프로필을 읽을 수 있는 사람은 이름을 포함해 이 정보를 볼 수 있지만, PRF 출력이나 평문 데이터 키는 저장하지
  않고 비밀 키는 암호화된 채로 남아요. 패스키를 등록한 적이 없는 보관함은 이전 형식을 그대로 써요.
- 세션 저장소에는 풀린 키와 보관함의 버전·식별 정보가 함께 있고, 비밀이 아닌 잠금 카운터(`lockGen`)도
  있어요. 잠글 때마다 이 값을 지우지 않고 새 값으로 바꿔서, 잠그기 전에 시작한 패스키 요청은 잠근 뒤에 쓸 수
  없어요.
- 패스키 요청은 확장 프로그램이 아니라 브라우저가 인증기(휴대폰, 보안 키, 컴퓨터의 패스키 저장소)와
  주고받아요. 이때 RP(확장 프로그램 ID), 인증 정보 ID, 챌린지, PRF 솔트를 보내요. 이 통신은 확장 프로그램의
  콘텐츠 보안 정책 밖에서 브라우저가 처리해요. 패스키 제공자는 확장 프로그램과 별개로 패스키를 다른 기기에
  동기화할 수 있어요. TOTP 비밀 키와 보관함 내용은 인증기나 제공자에게 보내지 않아요.
- 패스키는 확장 프로그램 ID에 묶이고 스토어 설치와 직접 설치의 ID가 달라서, 설치마다 따로 등록해요.
  설정에서 패스키를 삭제하면 이 보관함에서만 지워지니 휴대폰·보안 키·비밀번호 관리자에서도 삭제하세요.
  복사해 둔 브라우저 프로필 같은 이전 보관함 복사본에는 패스키 슬롯이 남아 있어요.
- 백업에는 패스키가 들어가지 않고, 가져오기는 그 백업의 비밀번호로 계정만 병합하며 패스키를 등록하지
  않아요. 비밀번호는 확장 프로그램이 백업을 가져오는 방법일 뿐 백업을 풀 수 있는 유일한 키는 아니에요.
  백업은 원래 보관함과 같은 데이터 키로 암호화되고, 패스키를 빼거나 삭제해도 그 키는 바뀌지 않아요. 그
  키를 가진 사람(패스키 슬롯이 남은 이전 복사본과 그에 맞는 인증기·사용자 확인을 가진 사람, 또는 잠금이 풀린
  세션에서 키를 가져간 사람)은 비밀번호 없이 백업과 같은 키로 나중에 암호화된 데이터를 풀 수 있어요. 패스키를
  등록하기 전에 내보낸 백업은 이전 비밀번호 키를 써요.

## 한국어 요약: 0.4에서 바뀐 점

- **비밀번호 제거**: 설정에서 빨간 확인을 두 번 거쳐 비밀번호를 없애면, 보관함은 새 데이터 키로 다시
  암호화되고 그 키는 브라우저가 이 컴퓨터에서 만든 *추출 불가* 키(WebCrypto, 확장 프로그램의 IndexedDB에
  보관)로 암호화돼요. 확장 프로그램도 이 키 값을 읽을 수 없고, 브라우저 프로필 밖으로 나가지 않으며, 백업과
  내보내기에 들어가지 않아요. 디스크 시리얼이나 컴퓨터 지문은 읽지 않아요. 비밀번호가 없으면 묻지 않고 열리고
  시간이 지나도 잠기지 않으니, 이 브라우저 프로필을 쓸 수 있는 누구나 코드를 볼 수 있어요. 다시 비밀번호를
  정하면 이 키는 지워져요.
- **계정 내보내기**: 요청할 때만 팝업에 QR 코드를 그리거나 `otpauth://` 링크를 클립보드에 복사해요. 여기에는
  비밀 키가 그대로 들어 있어요. 확장 프로그램은 이것을 저장하거나 보내지 않고, 화면을 떠나거나 잠그면 지워요.
  복사한 글자는 다른 걸 복사할 때까지 클립보드에 남아요.
- **잠금 해제 연장**: 연장하면 세션 저장소(메모리)에 끝나는 시각(`unlockedUntil`)을 두고, 잠글 때마다 지워요.

## Contact

Questions: open an issue at <https://github.com/2lab-ai/zauthenticator/issues>.
Security problems: report them privately as described in
[SECURITY.md](https://github.com/2lab-ai/zauthenticator/blob/main/SECURITY.md), through
<https://github.com/2lab-ai/zauthenticator/security/advisories/new>.
