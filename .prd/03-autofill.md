# 03 — Auto-fill OTP into web pages

Status: planned (2026-11-16) — implemented after v0.1 ships (user ordering, quoted below).

## User request (verbatim, 2026-11-16)

> 자동으로 otp를 입력해주는 기능 추가해줘. opt 입력란에서 클릭하고 우크릭하면 기존 otp중 선택하게 해주고 그렇게 선택하면 다음부터는 해당 otp 번호가 자동으로 입력되는 기능 추가해줘. (먼저 prd로 옮기고 지금 하던 작업부터 끝까지 완료후 제일 마지막에 작업

## Behaviour

1. Right-click inside an OTP input on any page → context menu "zauthenticator" lists the
   vault's accounts (issuer · label). Locked vault → one item "Unlock zauthenticator…" that opens
   the popup page in a tab.
2. Choosing an account fills the current code into that input (and dispatches `input`/`change`
   events so frameworks see it) and **remembers the binding** `origin → account id`.
3. Next visits to the same **exact origin** (scheme + host + port) auto-fill the bound account's
   code into the detected OTP input without a click, while the vault is unlocked.
4. Bindings are listed (and removable) in Settings.

## Security constraints

- Binding key = exact origin. Never fill on a different origin (phishing resistance: a look-alike
  domain gets nothing). Sub-domains are different origins.
- Auto-fill needs host access only for bound origins: request the origin as an
  `optional_host_permissions` grant at bind time and register a content script for just that
  origin (`chrome.scripting.registerContentScripts`). No `<all_urls>` content script.
- Codes travel service worker → content script per request; secrets never leave the extension
  context; the vault key stays in `chrome.storage.session` (trusted contexts only).
- Adds permissions `contextMenus`, `scripting` and a background service worker; the trust gate's
  allow-list is widened in the same change, nothing else.

## Open design questions (resolve when this is picked up)

- `permissions.request` needs a user gesture in an extension document; a context-menu click in
  the service worker may not qualify — fallback: one-shot `activeTab` fill on the click, plus a
  "remember on this site" confirmation page that performs the permission request.
- OTP input detection heuristics: `autocomplete="one-time-code"`, `inputmode="numeric"` with
  `maxlength` 6–8, name/id containing `otp|totp|2fa|mfa|code|token`.
