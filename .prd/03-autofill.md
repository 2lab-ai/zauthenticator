# 03 — Auto-fill OTP into web pages

Status: planned (2026-11-16) — decided contract for v0.2.0; workstream [v0-2-autofill/](v0-2-autofill/).

## User request (verbatim, 2026-11-16)

> 자동으로 otp를 입력해주는 기능 추가해줘. opt 입력란에서 클릭하고 우크릭하면 기존 otp중 선택하게 해주고 그렇게 선택하면 다음부터는 해당 otp 번호가 자동으로 입력되는 기능 추가해줘. (먼저 prd로 옮기고 지금 하던 작업부터 끝까지 완료후 제일 마지막에 작업

## Behaviour (decided)

1. **Menu.** Right-click in any editable field → browser context menu "zauthenticator" with one
   item per account ("issuer · label"). Locked or idle-expired vault → one item "Unlock
   zauthenticator…" that opens the extension's own popup page in a small window.
2. **Fill now.** Choosing an account computes its current code in the service worker and types it
   into the right-clicked field (the focused element of the clicked frame) with `input`/`change`
   events; nothing is submitted. Counts as user activity (refreshes `lastActiveAt`).
3. **Remember (once per site).** Right after a menu fill on an `https:` origin that has no binding
   yet, a small extension window asks: "Fill <issuer · label> automatically on <origin> from now
   on?" [Allow] [Not now]. Allow → the browser's own permission prompt for exactly
   `<origin>/*` → on grant, the binding `origin → account id` is stored inside the encrypted
   vault and the auto-fill content script is (re)registered for the bound origins. Not now or a
   denied prompt → nothing stored.
   Why a window: `chrome.permissions.request` must run in an extension page during a user
   gesture; the window also shows the exact origin before anything is remembered.
4. **Auto-fill.** On later loads of a bound origin (top frame or any frame of that exact origin),
   the content script finds the OTP field and asks the service worker for a code; the worker
   answers only if the vault is unlocked and not idle-expired and the sender's origin has a binding;
   the script fills the field once. Auto-fill does not refresh `lastActiveAt`.
5. **Manage.** Settings lists bindings (origin · account) with Remove; removing the last binding
   for an origin also unregisters it and removes that origin's host permission.

## Security rules

- Binding key = exact origin (`URL.origin`), `https:` only. Look-alike or sub-domains get nothing.
- Host access only for bound origins: manifest `optional_host_permissions: ["https://*/*"]`,
  granted per origin at bind time. No static `content_scripts`, no `host_permissions`.
- The worker validates every content-script message: `sender.id === chrome.runtime.id`,
  `sender.origin` (fallback `new URL(sender.url).origin`) has a binding, vault unlocked, not idle.
  Only the 6–8 digit code crosses into the page; secrets, labels and the key never do.
- Bindings live inside the vault data (encrypted). The browser itself still records granted
  origins and registered script matches — stated in the README.
- Field detection is a heuristic; the script never submits forms and fills a field only if it is
  empty.

## Vertical traces

### S0 — Client surface
- Context menu (browser UI) → `chrome.contextMenus.onClicked(info, tab)` in `background.js`.
- Bind window = `popup/popup.html#bind` (state `bind`): `#bind-origin`, `#bind-account`,
  `#bind-allow`, `#bind-cancel`, `#bind-error`. Settings: `#bindings` list, rows
  `.binding[data-origin]` with `.binding-remove`.

### S1 — Menu fill + bind offer
1. Entry: `contextMenus.onClicked({menuItemId:'acct:<id>', frameId, frameUrl, pageUrl}, tab)`.
2. Input: `menuItemId` must be `acct:<id>` of a current account; `tab.id` present.
3. Flow: worker → `idleOrLocked()` (store.getSessionKey + getLastActive; stale → clear key, treat as
   locked) → `vault.open(key, record)` → account by id → `totp(account, Date.now())` → code →
   `chrome.scripting.executeScript({target:{tabId, frameIds:[frameId]}, func: fillFocused, args:[code]})`
   (activeTab from the menu click) → `store.touch()`.
   `origin = new URL(frameUrl ?? pageUrl).origin`; if `https:` and no binding for it → session
   `pendingBind = {origin, accountId, at}` → `nav.openBindWindow()` (popup window,
   `popup/popup.html#bind`).
4. Side effects: page field value = code; session `lastActiveAt` refreshed; session `pendingBind`.
5. Errors: locked/idle → open unlock window instead, no fill; account missing → rebuild menu, no
   fill; executeScript rejects (e.g. restricted page) → no binding offer.
6. Output: filled field; bind window (when eligible).

### S2 — Bind window → binding stored
1. Entry: `#bind-allow` click in the extension window (user gesture).
2. Input: session `pendingBind` younger than 2 minutes; its `accountId` exists; origin `https:`.
3. Flow: `chrome.permissions.request({origins:[origin+'/*']})` → granted → `session.addBinding
   (origin, accountId)` (vault mutate under the Web Lock: `data.bindings` gets/replaces
   `{origin, accountId, createdAt}`) → worker sync (`storage.onChanged` on the vault) →
   `registerAutofill(origins)` = `chrome.scripting.registerContentScripts` /
   `updateContentScripts` id `autofill`, `matches: origins.map(o => o + '/*')`, `allFrames: true`,
   `runAt: 'document_idle'`, `js: ['content/autofill.js']` → session `pendingBind` removed → window
   closes.
4. Side effects: vault record (bindings), host permission granted, script registration.
5. Errors: prompt denied → no binding, `#bind-error`; pending expired/missing → message, nothing
   stored; locked meanwhile → nothing stored.
6. Output: binding visible in Settings.

### S3 — Auto-fill on revisit
1. Entry: `content/autofill.js` runs in a frame of a bound origin.
2. Input: an OTP field = first visible, enabled, empty `<input>` matching (in order):
   `autocomplete="one-time-code"`; or name/id/aria-label/placeholder matching
   `/(otp|totp|2fa|mfa|one.?time|verification|auth(entication)?.?code|security.?code)/i`; or
   `inputmode="numeric"`/`type="tel"|"number"` with `maxlength` 6–8; or a run of 6–8 sibling
   single-character inputs (split boxes). Watches DOM changes up to 60 s for late fields.
3. Flow: script → `chrome.runtime.sendMessage({type:'autofill-code'})` → worker validates sender
   (rules above) → `vault.open` → binding → account → `totp` → `{code}` → script sets value(s) +
   `input`/`change` events, once per field per page load.
4. Side effects: field value only. No `lastActiveAt` change.
5. Errors: locked/idle/unbound/invalid sender → `{code:null}`, script does nothing.
6. Output: filled field.

### S4 — Remove binding
`.binding-remove` → `session.removeBinding(origin)` → worker sync → `updateContentScripts` (or
`unregisterContentScripts` when none left) → `chrome.permissions.remove({origins:[origin+'/*']})`.

## Contract tests (RED first)
- Unit: binding add/replace/remove in vault data survives seal; origin normalization rejects
  non-https and paths; sender validation (wrong id, unbound origin, locked, idle) → null; field
  detection over fixture DOM snippets (positive and negative cases); menu model from accounts.
- e2e (real Chromium; the test copies the extension and adds `host_permissions` for the routed test
  origins so no native prompt appears — the shipped manifest is untouched and gated): bind via the
  `#bind` window → registration exists → routed `https://otp.test/login` gets the reference code;
  `https://evil.test/login` (same field) gets nothing; lock → reload → nothing; remove binding →
  reload → nothing; menu fill through the worker's click handler.
