# v0-2-autofill — loop (open work only)

Status: in-progress (2026-11-16)

## Round 1 plan

| ID | Status | Branch | Scope (owned files) |
|---|---|---|---|
| AF-A | 🟡 | feat/af-core | `extension/lib/bindings.js` (new, pure), `extension/lib/store.js`, `extension/popup/session.js`, `test/bindings.test.mjs`, `test/session.test.mjs` |
| AF-B | 🟡 | feat/af-runtime | `extension/background.js`, `extension/lib/autofill-worker.js`, `extension/content/autofill.js`, `extension/lib/fieldfind.js` (new, pure), `extension/popup/{popup.html,popup.js,settings.js,popup.css}`, locales, `test/fieldfind.test.mjs` |
| AF-C | 🟡 | feat/af-gate | `scripts/check-policy.mjs`, `e2e/*` (incl. `e2e/fixtures/background.test.js`), `README.md`, `SECURITY.md`, `.prd/01-spec.md` (trust claims) |

## Gaps

| ID | Status | Gap |
|---|---|---|
| AG1 | 🔴 | S1–S4 not observed |
| AG2 | 🔴 | trust gate policy not yet widened for contextMenus/scripting/background/optional https host permissions |

## Order

Shared contracts committed first on main (manifest v0.2.0, nav.js). AF-A and AF-B in parallel (AF-B codes
against the session/bindings interface in 03-autofill). AF-C after the spike result (permissions.request
with pre-granted host_permissions, dynamic content script on routed https pages, Playwright access to the
module worker). Review pack includes `git diff a1dcfb1..HEAD` for session.js, format.js and list.js
(changed after the last v0.1 external review).
