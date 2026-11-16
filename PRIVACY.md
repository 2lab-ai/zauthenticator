# Privacy policy

**zauthenticator** browser extension. Effective date: 2026-11-17.

In short: zauthenticator keeps your data on your device, encrypted with your passphrase. The
developer receives nothing. The extension has no server, no account, no analytics and no
telemetry, and it does not sell, share or transfer any data.

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

- **Your passphrase is never stored.** After you unlock, the derived key is kept in the browser's
  session storage, in memory, until you lock or the browser quits. After 15 minutes without use,
  the next time the extension reads the key (opening the popup, a menu choice or an auto-fill
  request) it removes the key before any code is shown or filled.
- **Backup files** that you export contain the vault exactly as stored, still encrypted with the
  same passphrase, so restoring one also needs that passphrase. They are saved where you choose,
  and the extension does not send them anywhere.
- **Codes you copy** are placed on your system clipboard, where other applications on your device
  can read them.

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

Only the one-time code (6 to 8 digits), typed into a web page:

- into the field you right-clicked, after you choose an account from the menu, or
- into the code field of a site where you allowed auto-fill, while the extension is unlocked.
  Until you submit, a newer code may replace it when the filled one expires or the site rejects
  it.

The page receives the code as if you had typed it, and its scripts can read it. The secret key,
the account names and the passphrase never reach any page.

## What the extension does not do

- It does not send what it stores to the developer or to anyone else, and it does not sell, share
  or transfer data. The developer has no server and cannot see your data.
- It does not use analytics, telemetry, crash reporting or advertising.
- Its own pages and its background worker cannot connect to any server: their content security
  policy blocks every network connection and remote resource.
- It does not load or run remote code. Everything it runs is in the package you install.
- It does not sync. Each browser profile has its own vault.

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
- **Export and import** an encrypted backup from Settings.
- **Delete** an account (its auto-fill sites go with it), or **remove** an auto-fill site, which
  also gives up the extension's access to that site. You can also remove site access from the
  extension's details page in the browser.
- **Lock** the vault at any time; it also locks after 15 minutes without use and when the browser
  quits.
- **Uninstall** the extension to delete everything it stored, including the vault.

## Store policies

The extension uses the data above only to provide its single purpose: generating two-factor codes
and filling them where you choose. No person reads it and it is never transferred to anyone. This
use of information complies with the Chrome Web Store User Data Policy, including the Limited Use
requirements, and with the developer policies of Microsoft Edge Add-ons.

## Changes

This policy lives in the extension's public source repository. Any change is made there, with the
effective date above updated, and the repository's history shows every earlier version.

## Contact

Questions: open an issue at <https://github.com/2lab-ai/zauthenticator/issues>.
Security problems: report them privately as described in
[SECURITY.md](https://github.com/2lab-ai/zauthenticator/blob/main/SECURITY.md), through
<https://github.com/2lab-ai/zauthenticator/security/advisories/new>.
