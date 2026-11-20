# Microsoft Edge Add-ons listing: zauthenticator 0.3.0

Everything to enter in Microsoft Partner Center (Edge program), page by page. Requirements were
checked against the official documentation on 2026-11-16; each one names its source. A value the
documentation does not state is marked **unverified**: confirm it in Partner Center itself.

Main source for this file: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension
(page dated 2026-05-05, checked 2026-11-16). Policies:
https://learn.microsoft.com/en-us/legal/microsoft-edge/extensions/developer-policies (checked 2026-11-16).

Edge-specific rule for every text below: the extension and its listing "must not reference other
browsers" (developer policies 1.1.2). The descriptions, search terms, notes and both
`extDescription` values are written without browser names; keep them that way.

## What changed in 0.3.0

0.3.0 adds optional passkey unlock (WebAuthn PRF) beside the passphrase and no new permission.
The descriptions, privacy answers and certification notes below cover it: passkey requests made
by the browser, enrollment in Settings opened in a tab with two prompts, unlock in a separate
window, and the passphrase as the way back in. The 0.2.0 texts are in the git history (commit
`1467eb4`).

## Packages

- **File to upload:** the same `zauthenticator-0.3.0.zip` as for the other store (GitHub release
  `v0.3.0`, or `npm run zip` → `dist/zauthenticator-0.3.0.zip`). For this update, open the
  extension in Partner Center and drop it on the **Packages** page; a first submission uses
  "Drag your package here (.zip)".
- The **Extension name** and the **Short description** come from the manifest (`extName`,
  `extDescription`) and are read-only in Partner Center; to change them, upload a new package.
- Partner Center detects the listing languages from `_locales` when the manifest uses
  `__MSG_…__` for `name` and `description` and sets `default_locale`. zauthenticator does both, so
  English (`en`) and Korean (`ko`) should both appear.
source: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension, checked 2026-11-16

| Locale | Short description (= `extDescription`) | Characters |
|---|---|---|
| en | Open-source two-factor (TOTP) authenticator. Codes are made on your device, secrets stay encrypted, auto-fill is opt-in per site. | 129 |
| ko | 오픈소스 2단계 인증(TOTP) 앱이에요. 코드는 이 기기에서 만들고 비밀 키는 암호화해 보관해요. 자동 입력은 허용한 사이트에서만 해요. | 77 |

## Availability

- **Visibility:** Public (default; discoverable through search and browsing). Hidden is the
  alternative.
- **Markets:** all markets (default, includes markets added later).
source: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension, checked 2026-11-16

## Properties

| Field | Required | Value |
|---|---|---|
| Category | yes | **Productivity**. The list of categories is not in the docs: **unverified**; pick the closest security/privacy or productivity category the dropdown offers. |
| Website | no | `https://github.com/2lab-ai/zauthenticator` (must be your own page, not the add-ons listing) |
| Support contact detail | no | `https://github.com/2lab-ai/zauthenticator/issues` |
| Mature content | no | unchecked |

source: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension, checked 2026-11-16

## Privacy

Same five sections as the other store: Single Purpose, Permission justification, "Are you using
remote code?", Data usage, Privacy policy. Everything must be complete, accurate and consistent with
the extension's behaviour, or the submission may get extra review or be rejected.
source: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension, checked 2026-11-16

Use the texts from [chrome-web-store.md](chrome-web-store.md#privacy-practices-tab) unchanged;
none of them names a browser:

- **Single Purpose Description:** the "Single purpose description" text.
- **Permission justification:** one box per manifest permission (`storage`, `activeTab`,
  `contextMenus`, `scripting`, and the optional `https://*/*` host access); use the matching
  texts. Which of these Partner Center lists for an optional host permission is **unverified**.
- **Are you using remote code?:** "No, I am not using remote code." Remote code is not permitted in
  Manifest V3.
- **Data usage:** the same ticks and certifications as the other store, so both stores and
  PRIVACY.md describe the same handling:
  - **Authentication information**: ticked. TOTP secret keys and account names are kept in the
    encrypted vault on the device. Once a passkey is enrolled, its slot sits next to the
    encrypted data (credential ID, PRF salt, label, creation time and the data key encrypted
    under a key derived from the PRF output; never the PRF output or the plain data key). While
    unlocked, an auto-fill record in session memory (tab id, site origin, account id, TOTP period
    number and time; never a code) limits a site to 3 codes per tab in 5 minutes and no repeated
    code; a lock removes it. During a passkey request the browser passes the credential ID, a
    challenge and the PRF salt to the user's own authenticator; nothing reaches the developer
    (see the [Tensions](chrome-web-store.md#tensions) of the other file).
  - **Website content**: ticked. A picture of the visible part of the current tab is decoded on
    the device when you click the scan button, and on sites you allowed the auto-fill script reads
    input-field attributes to find the code field.
  - **Web history**: not ticked. The vault holds only the sites you chose for auto-fill, and the
    session auto-fill record notes, for those sites only, when a code was given (removed on
    lock); the extension keeps no list of pages visited and no page titles. What would change this is in
    the [Tensions](chrome-web-store.md#tensions) of the other file; if you tick it there, tick it
    here too.
  - Everything else: not ticked. All certifications: ticked.

  The Partner Center checkbox labels are shown only as a screenshot in the docs: **unverified**;
  map them by meaning.
- **Privacy Policy URL:** `https://github.com/2lab-ai/zauthenticator/blob/main/PRIVACY.md`. It
  must be reachable and up to date; the policy must say how data is collected, used and
  disclosed (policies 1.5.2 add: the controls users have over their data, which PRIVACY.md lists
  under "Your controls").
  source: https://learn.microsoft.com/en-us/legal/microsoft-edge/extensions/developer-policies, checked 2026-11-16

#### Tensions

- **One privacy policy for two stores.** Edge policy 1.5.2 says the privacy policy "should
  primarily refer to the Microsoft Edge browser and not other browsers", while the other store
  asks for a Limited Use statement that names its own User Data Policy. PRIVACY.md is written
  without browser names except one closing sentence that names both stores' policies. If a
  reviewer objects, publish a second copy without that sentence (for example `PRIVACY-EDGE.md`)
  and use its URL here.

## Store listings (one page per language)

Required for each language in the package (`en`, `ko`): **Description** and **Extension logo**.
Use **Duplicate** to copy the logo, tiles and screenshots to the other language.
source: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension, checked 2026-11-16

### Description

Limits: minimum 250 characters, maximum 10,000; must describe the full functionality.
source: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension, checked 2026-11-16

Use the **English** and **Korean** detailed descriptions from
[chrome-web-store.md](chrome-web-store.md#detailed-description) unchanged (0.3.0 texts measured on
2026-11-20: see [Text lengths](chrome-web-store.md#text-lengths); both are above 250 and below
10,000 characters, and neither names a browser). Do not use "Generate with AI": the text must
stay identical in both stores.

### Images

| Field | File | Required | Size |
|---|---|---|---|
| Extension logo | `store/assets/edge-logo-300.png` | yes, per language | 1:1, recommended 300×300, at least 128×128 |
| Small promotional tile | `store/assets/promo-small-440x280.png` | no | 440×280 |
| Large promotional tile | `store/assets/promo-marquee-1400x560.png` | no | 1400×560 PNG |
| Screenshots | `store/assets/screenshots/1-codes.png`, `store/assets/screenshots/2-autofill.png`, `store/assets/screenshots/3-bind.png`, `store/assets/screenshots/4-add.png`, `store/assets/screenshots/5-settings.png` | no, up to 6 | 640×480 or 1280×800 |
| YouTube video URL | none | no | |

Screenshots must be clear and not stretched or blurry (policies 1.1.2).
source: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension, checked 2026-11-16
source: https://learn.microsoft.com/en-us/legal/microsoft-edge/extensions/developer-policies, checked 2026-11-16

### Search terms

Limits: at most 7 terms (single words or phrases), each at most 30 characters, at most 21 words
in total; not shown to users; must be relevant (policies 1.1.4).
source: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension, checked 2026-11-16

English (7 terms, 11 words):

```text
authenticator
two-factor authentication
TOTP
2FA
one-time password
OTP code
verification code
```

Korean (7 terms, 11 words):

```text
2단계 인증
OTP
TOTP
인증 코드
일회용 비밀번호
2FA
인증 앱
```

## Notes for certification

Required in Partner Center (at most 2,000 characters; the box opens when you choose "Yes, I need to provide … other info for testers", and Partner Center warns that submissions without notes may fail review). The extension must be fully testable and the notes help testers reach every feature
(policies 1.3). Certification "can take up to seven business days".
source: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension, checked 2026-11-16
source: https://learn.microsoft.com/en-us/legal/microsoft-edge/extensions/developer-policies, checked 2026-11-16

Quoted labels checked against `extension/_locales/en/messages.json` on 2026-11-20 (0.3.0): "Add
account", "Add from links", "Allow", "Not now", "Remove", "Unlock zauthenticator…", "Open in a
tab", "Add passkey", "Unlock with passkey"; the menu is named "zauthenticator" and lists accounts
as "issuer · label".

For an update, the first line says what changed in that version (Partner Center asks for this for
updates).
source: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension, checked 2026-11-16

Length: 1,964 characters (limit 2,000; see [Text lengths](chrome-web-store.md#text-lengths)).
Passkey unlock is optional in the test: it needs an authenticator with the WebAuthn PRF extension,
and every other step works without one.

```text
Changed in 0.3.0: optional passkey unlock (WebAuthn PRF) next to the passphrase. No new permissions.

zauthenticator generates two-factor (TOTP) codes on the device. No account or test credentials are needed. Its own pages and worker make no network requests; passkey requests are made by the browser.

How to test:
1. Click the toolbar icon and create a passphrase of 8 or more characters (for example: certification-test-1).
2. Click "Add account", paste this link into the otpauth:// links box and click "Add from links":
   otpauth://totp/Example:test@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
   The account "Example" appears with a 6-digit code (RFC 6238) and a countdown; clicking the code copies it.
3. On any https page, right-click a text field, open the "zauthenticator" menu and choose "Example · test@example.com". The code is typed in; nothing is submitted.
4. A small window then offers auto-fill on that exact site. Click "Allow" and accept the browser's prompt for that one site ("Not now" stores nothing). Later visits fill the code automatically, but only into a field marked as a code field (autocomplete="one-time-code", or a name, label or placeholder such as "otp" or "2fa"); a plain text field is not filled, by design.
5. Settings lists the site under auto-fill sites; "Remove" deletes it and gives up the access.
6. Click the lock button: the right-click menu then shows "Unlock zauthenticator…" and nothing is filled.
7. Optional: passkey unlock needs a PRF-capable authenticator (a phone over the QR code flow, or a security key with a PIN); everything else can be tested without one. In Settings click "Open in a tab", re-enter the passphrase, click "Add passkey" and approve both prompts. Then lock; in the toolbar popup click "Unlock with passkey" and click it again in the window that opens.

Permission justifications are in the Privacy section. No remote code. Source code (MIT): https://github.com/2lab-ai/zauthenticator
```
