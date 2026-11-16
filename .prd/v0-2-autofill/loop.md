# v0-2-autofill — loop (open work only)

Status: in-progress (2026-11-16)

## Round 1 plan

| ID | Status | Branch | Scope (owned files) |
|---|---|---|---|
| AF-A | 🟡 | feat/af-core | `extension/lib/bindings.js` (new, pure), `extension/popup/session.js` (addBinding/removeBinding/bindings), `test/bindings.test.mjs`, `test/session.test.mjs` |
| AF-B | 🟡 | feat/af-runtime | `extension/background.js`, `extension/content/autofill.js`, `extension/lib/nav.js`, `extension/lib/fieldfind.js` (new, pure), `extension/manifest.json`, `extension/popup/{popup.html,popup.js,settings.js,popup.css}`, locales, `test/fieldfind.test.mjs` |
| AF-C | 🟡 | feat/af-gate | `scripts/check-policy.mjs`, `e2e/*`, `README.md`, `SECURITY.md` |

## Gaps

| ID | Status | Gap |
|---|---|---|
| AG1 | 🔴 | S1–S4 not observed |
| AG2 | 🔴 | trust gate policy not yet widened for contextMenus/scripting/background/optional https host permissions |
