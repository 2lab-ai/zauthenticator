# 03 — Auto-fill OTP into web pages

Status: shipped (2026-11-16, v0.2.0) — the implemented auto-fill contract, not a future target; workstream record in [v0-2-autofill/](v0-2-autofill/).

## User request (verbatim, 2026-11-16)

> 자동으로 otp를 입력해주는 기능 추가해줘. opt 입력란에서 클릭하고 우크릭하면 기존 otp중 선택하게 해주고 그렇게 선택하면 다음부터는 해당 otp 번호가 자동으로 입력되는 기능 추가해줘. (먼저 prd로 옮기고 지금 하던 작업부터 끝까지 완료후 제일 마지막에 작업

## Behaviour (decided)

1. **Menu.** Right-click in any editable field → browser context menu "zauthenticator" with one
   item per account ("issuer · label"). Locked or idle-expired vault → one item "Unlock
   zauthenticator…" that opens the extension's own popup page in a small window.
2. **Fill now.** Choosing an account computes its current code in the service worker and types it
   into the right-clicked field (the focused element of the clicked frame) with `input`/`change`
   events; nothing is submitted. Counts as user activity (refreshes `lastActiveAt`).
3. **Remember (per site, per chosen account).** Right after a menu fill on an `https:` origin that is
   not yet bound to the account just chosen (unbound, or bound to another account — then the window
   also says which account it replaces, `#bind-replaces`), a small extension window asks: "Fill <issuer · label> automatically on <origin> from now
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
  Only the 6–8 digit code (and, to the content script, how many milliseconds it stays valid) crosses
  into the page; secrets, labels and the key never do.
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
3. Flow: worker → `session.readUnlocked({touch: true})` (under the vault Web Lock; stale → clears
   the session keys and returns null) → account by id → `totp(account, Date.now())` → code →
   `expected = new URL(frameId === 0 ? pageUrl : frameUrl).origin` (a subframe without `frameUrl`
   → stop) → `chrome.scripting.executeScript({target:{tabId, frameIds:[frameId]}, func: fillFocused,
   args:[code, expected]})` (activeTab from the menu click); `fillFocused` writes nothing unless
   `location.origin === expected` at injection time.
   If the fill succeeded and `normalizeOrigin(expected)` is an https origin not already bound to this account →
   `session.setPendingBind({origin, accountId})` (true only while unlocked) → `nav.openOwnWindow('bind')`.
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
   `runAt: 'document_idle'`, `persistAcrossSessions: false`, `js: ['lib/fieldfind.js', 'content/autofill.js']` (one field-finder source shared with the unit tests) → session `pendingBind` removed (only the offer this window showed) → window
   closes. The binding is stored before the offer is cleared, and the reconciler decides which
   grants to remove inside `session.withVaultState` (vault Web Lock held), so a just-granted origin is
   never revoked from a stale snapshot.
4. Side effects: vault record (bindings), host permission granted, script registration.
5. Errors: prompt denied → no binding, `#bind-error`; pending expired/missing → message, nothing
   stored; locked meanwhile → nothing stored.
6. Output: binding visible in Settings.

### S3 — Auto-fill on revisit
1. Entry: `content/autofill.js` runs in a frame of a bound origin.
2. Input: an OTP field = first visible, enabled, empty `<input>` matching (in order):
   `autocomplete="one-time-code"`; or name/id/aria-label/placeholder containing the whole word
   `otp|totp|mfa|2fa` (names split on non-alphanumerics, camelCase and letter→digit) or the phrase
   `one.?time.?(code|pass|password|pin)`, `verification.?code`, `auth(entication)?.?code`; or a run
   of 6–8 sibling single-character inputs (split boxes) that carries a code sign (a box marked
   one-time-code or named for a code, or a group element whose aria-label/id names a code). A field
   that is only sized like a code (numeric, maxlength 6–8) has no sign and is never filled
   unattended — the right-click menu still fills it. A box run is also skipped when its group's
   aria-label/id names another number (e.g. "code sent to your phone"); hidden inputs inside a run are
   passed over, any other shown non-code input ends it. Rules 2–3 skip a field whose names contain a whole word for
   another number (zip, postal, phone, tel, mobile, amount, price, card, cc, cvv, cvc, csc, birth,
   bday, dob, date, year, month, day, search, account, qty, quantity, captcha, …) or whose
   `autocomplete` is anything but empty/on/off/one-time-code. After a fill the script follows only the
   filled field(s) (see "Fresh code and retry after a failed attempt": keep-fresh ≤ 1 replacement, ≤ 2 fills,
   never the same code twice, 5-minute window, same path, a user edit ends it; the worker's per-tab limits
   hold across page loads); no other field is filled while they are present. Looks again on DOM changes, on `resize`/`load`/`pageshow`/`visibilitychange`, and every 500 ms, for up to 60 s (an iframe can start with a 0x0 viewport); one request in flight at a time.
3. Flow: script → `chrome.runtime.sendMessage({type:'autofill-code'})` → worker validates sender
   (rules above) → under the vault Web Lock: `vault.open` → binding → account → `totp` → per-tab record
   (`autofillServed`) → `{code, validMs}` (or `{code: null, validMs}` = wait) → script sets value(s) +
   `input`/`change` events.
4. Side effects: field value; session `autofillServed` (tab, origin, account id, TOTP counter, time —
   never a code). No `lastActiveAt` change.
5. Errors: locked/idle/unbound/invalid sender, or the tab's limit reached → `{code:null}`, the script
   stops.
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

## Cross-unit contract (binding for the v0-2-autofill work units)

Committed on main before the units start: `extension/manifest.json` (v0.2.0: permissions
`storage, activeTab, contextMenus, scripting`; `optional_host_permissions: ["https://*/*"]`;
`background: {service_worker: "background.js", type: "module"}`) and `extension/lib/nav.js`
(`openOwnView('add-file'|'settings')` tab, `openOwnWindow('bind'|'unlock')` popup window). No unit
edits these two files.

Session storage (amends 02-architecture Round 2): `chrome.storage.session` holds a subset of
{`vaultKey`, `lastActiveAt`, `pendingBind`, `autofillServed`}. `pendingBind = {origin, accountId, at}` is
written only by the worker after a menu fill. `autofillServed = [{tab, origin, account, counter, at}]`
(see "Fresh code and retry after a failed attempt") is written only by the worker, under the vault Web
Lock while a key is stored. Every lock path (manual, propagated, idle, `lockIfIdle`, stale-key clearing)
removes all four keys (`store.clearSessionKey()`).

`extension/lib/bindings.js` (pure, AF-A):
- `normalizeOrigin(url)` → `'https://host[:port]'` or `null` (non-https, invalid, opaque → null).
- `bindingsOf(data)` → array of `{origin, accountId, createdAt}` (malformed entries ignored).
- `withBinding(data, origin, accountId, now)` → new data with that origin bound (replaces).
- `withoutBinding(data, origin)` → new data. `withoutAccountBindings(data, accountId)` → new data.
- `bindingFor(data, origin)` → binding or null. `boundOrigins(data)` → sorted unique origins whose
  account exists.

`extension/popup/session.js` (AF-A), usable from extension pages AND the worker:
- `bindings()` → `bindingsOf(data)` while unlocked, `[]` while locked.
- `addBinding(origin, accountId)` → mutate; throws `SessionError('bad-origin'|'no-account')`.
- `removeBinding(origin)` → mutate → boolean.
- `deleteAccount(id)` also removes that account's bindings in the same mutate.
- `readUnlocked({ touch = false } = {})` → vault data or `null`; under the `zauthenticator-vault`
  Web Lock re-reads key + `lastActiveAt`; stale → clears all session keys (incl. `pendingBind`) and
  returns null; `touch: true` refreshes `lastActiveAt`. This is the worker's only read path.
- `setPendingBind({origin, accountId})`, `takePendingBind(maxAgeMs = 120000)` (returns and keeps it
  until `clearPendingBind()`), `clearPendingBind()` via `lib/store.js` (AF-A owns store.js).

Worker (AF-B): `extension/background.js` only wires listeners to `extension/lib/autofill-worker.js`,
which exports `handleMenuClick(info, tab)`, `handleMessage(message, sender)` (returns
`{code}`/`{code:null}`), `rebuildMenu()`, `syncRegistrations()`, `onStorageChanged(changes, area)`.
The shipped worker has no test hooks. The e2e (AF-C) runs a test copy whose manifest points at a
test-only entry `e2e/fixtures/background.test.js` that imports the same module, wires the same
listeners and exposes `globalThis.__zauthTest = { handleMenuClick, frameIdFor }` (frameIdFor: test-only, frame URL → frameId); the test copy also adds
`host_permissions` for the routed test origins.

Reconciliation (AF-B): `syncRegistrations()` is the single reconciler, run on `onStartup`,
`onInstalled`, and every vault change while unlocked: registered matches = `boundOrigins(data)`;
granted optional origins not bound (and not a stored offer, of any age) are removed with
`permissions.remove`, decided under the vault Web Lock. Locked or idle → the `autofill` script is
unregistered (registrations are not persisted across sessions); permissions are left as they are.

Menu lifetime (AF-B): `rebuildMenu()` runs on `onStartup`, `onInstalled`, session-key removal, vault
change, and at the start of every worker event; locked → single "Unlock zauthenticator…" item.
Documented limit: if the worker is asleep when the 15-minute idle time passes, account names stay
in the menu until the next worker event or browser restart; choosing one then opens the unlock
window instead of filling.

Trust-claim updates (AF-C): README trust table and 01-spec carry the v0.2 permission set and the
background/content-script facts; the gate policy widens exactly to the manifest above,
`content_scripts`/`host_permissions`/`web_accessible_resources` stay forbidden, `chrome.scripting`
calls are allowed only in `lib/autofill-worker.js`, tab/window opening only in the pinned `nav.js`.

Manual checks (not automatable): the native permission prompt in S2; the browser context menu UI.

## Fresh code and retry after a failed attempt (v0.2.0, from the user's hand test)

User report (verbatim, 2026-11-16, cachy-z13 Edge, v0.2.0 = main e474db8): "잘 작동되는데, 첫번째 시도에서 시간 지난 2fa 입력해서 실패남 이거 한번 실패난경우 다시 입력하도록해줘"

Cause (code at main 90ddb49): the code is computed once when the field is found (worker `handleMessage`,
`totp(account, Date.now())`) and the content script stops after the first fill
(`content/autofill.js:98-102`) and never asks again for a field it filled (`seen`, :36/:79/:110). A code
filled late in its period, or submitted after the period ended, is expired; if the site rejects it and
clears or re-renders the field, nothing fills it again. Clocks were checked: cachy-z13 within 1 s of the
reference, NTP synchronized.

Contract (S3 additions):
- The worker answers `{code, validMs}` — `validMs` = milliseconds left in the code's period.
- Fill late in a period is avoided: when `validMs < 3000` the script waits for the next period and asks again.
- Keep fresh: after a fill, while the filled field(s) are still in the page and still hold exactly the
  code the script put, the script asks for a new code when the period ends and replaces it.
- Retry after a failure: if the filled field becomes empty again, or is removed and a code field is shown
  again, the script fills it again with a current code.
- Bounds: the follow window ends 5 minutes after the first fill; at most 1 + 3 fills per page load; a field
  the user typed into (value differs from what the script put and is not empty) is never touched again;
  still at most one filled field set at a time (no other candidate field is filled while the filled one
  is present), still never submits, and auto-fill still never refreshes `lastActiveAt`.
- Locked/idle/unbound reply (`{code: null}`) still ends the watch.
- Decided 2026-11-17 (owner-side calls by the dispatcher): a refill never puts the same code twice into a
  field after it was rejected/emptied — if the reply equals the code last put there, wait for the next
  period and fill that one (an expired code gets the current, different code at once); keep-fresh is capped
  at 3 replacements per filled field set (sites that submit on `input` would otherwise resubmit every
  period). A field the user empties by hand is refilled like a page-emptied one (indistinguishable).
  Superseded by the round-4 rules below (main d8636a4 review, 2 REJECT / 1 APPROVE).

### Final rules (round 4, 2026-11-17; supersede the bounds above where they differ)

Owner's words "한번 실패난경우 다시 입력하도록" = one retry. Content script (`content/autofill.js`), per page load:
- Every reply is checked: `validMs < 3000` → no fill; wait `validMs + 250` ms and ask again. 3 waits in a row
  without a fill (late codes, worker waits, the code filled last) end the watch (covers periods of a few
  seconds).
- Never the same code twice: after any fill, a reply whose code equals the code the script last put is not
  written to any field (the old set emptied, or a new field put in its place) — wait for the next period.
- At most 2 fills (first + one retry); at most 1 keep-fresh replacement per filled field set (a refill of
  the same set does not start a new count). Round 5 (2026-11-17, fable SHOULD adopted by the dispatcher):
  1, not 2, so the first fill, one replacement and the one retry fit in the worker's 3 codes per tab — with
  2, a fill and two replacements used all 3 within 60–90 s and the owner's one retry
  ("한번 실패난경우 다시 입력하도록") got `{code: null}`. After the replacement the code is left as is; a
  rejection then gets the current code as the retry.
- A user edit ends the watch: an `input` event with `isTrusted` on a followed field (typing, deleting,
  pasting). The page setting `value` fires none; the script's own and a page's events are untrusted.
- The follow ends when the page's path (`document.URL` up to `?`/`#`; read-only, unlike
  `location.pathname`) differs from the path at the first fill.
- Still: follow window 5 minutes from the first fill, no other field set while the filled one is in the
  page, never submits, `{code: null}` ends the watch.

Worker (`lib/autofill-worker.js` `handleMessage`), per (sender tab id, origin), across page loads and worker
restarts — a site that submits on `input` and reloads on a rejection resets every in-page count:
- Each (account id, TOTP counter) is served once: asked again in its period → `{code: null, validMs}`
  (`validMs` = ms to the next period) = wait; the script waits and asks again (no fill, no stop).
- At most 3 code replies in any 5 minutes (first fills, retries, keep-fresh and late codes alike) → then
  `{code: null}` = stop.
- A context-menu fill (the user's explicit choice) on that tab and origin drops its record (a new budget).
- State in `chrome.storage.session.autofillServed` = `[{tab, origin, account, counter, at}]` (counters and
  times, never codes); entries older than 5 minutes are dropped on write; read, decided and written under the
  vault Web Lock (two frames asking at once get one code; a lock cannot interleave), only while unlocked;
  removed by every lock path. A sender without a tab (none expected) has a record of its own (tab `-1`).
- Known cost: a code served with under 3 s left is counted although the script does not fill it.
