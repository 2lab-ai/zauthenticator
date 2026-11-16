# v0-2-autofill — done (append-only)

Loop: ./loop.md · Each round close appends one block at the bottom; nothing above it ever changes. Rows here are snapshots (Last Measured frozen at move time). A later pass is a `re-verified` line in a loop.md round section; a regression reopens as a new loop.md row with Source `regression:<ID>`.

## R1 — closed 2026-11-16

- measured: build + three external review rounds green · result: auto-fill implemented to the 03-autofill contract, reviewed to unanimous approval · closed rows: AF-A AF-B AF-C AG1 AG2 · commit: main b76be5d (+ docs)

### Closed rows

| ID | Source | Universe Item | Observable Acceptance | AS-IS Evidence | Status | Gap | Dispatch | Verification Evidence | Last Measured |
|---|---|---|---|---|---|---|---|---|---|
| AF-A | plan | bindings in the vault; session API for pages and the worker | unit tests incl. two-page and never-resumed worker instances | none | ✅ | — | opus-coder, feat/af-core | 178/178 at 9237383 (65 new, RED 64 first) | 2026-11-16 |
| AF-B | plan | worker (menu, fill, messages, reconciler), content script, bind window, settings bindings | worker contract tests + real-Chromium S1–S4 | none | ✅ | — | opus-coder, feat/af-runtime | 229/229 at a72cfef (31 worker contract tests, RED by mutation) | 2026-11-16 |
| AF-C | plan | widened pinned gate policy, S1–S4 e2e, v0.2 trust docs | gate + self-test + e2e green | none | ✅ | — | opus-coder, feat/af-gate | gate 20/20, self-test 299/299 at 31b52d6 | 2026-11-16 |
| AG1 | gap | S1–S4 observed | real-Chromium e2e green, repeated | not observed | ✅ | native permission prompt + real context-menu UI stay manual | dispatcher | main d5c2a05: e2e 113/113 ×3 (incl. iframe menu bind = frame origin, origin change under the click, one fill per page, no-signal page, locked = unregistered) | 2026-11-16 |
| AG2 | gap | gate widened exactly to the manifest | gate green on the real extension, every widened rule has violating fixtures | not widened | ✅ | lexical limits documented (ambiguous `/`, unnamed global object) | dispatcher | gate 21/21, self-test 538/538 at d5c2a05 | 2026-11-16 |

### Round section (as it was in loop.md)

Three work units (AF-A core, AF-B runtime, AF-C gate/e2e), file ownership disjoint, shared contracts (manifest
v0.2.0, nav.js, cross-unit interfaces in 03-autofill) committed on main first; a spike confirmed the e2e
mechanics (permissions.request with pre-granted host permissions, dynamic content scripts on routed https
pages and cross-origin iframes, Playwright access to the module worker).

Integration findings fixed before review: iframe first-look miss at a 0x0 viewport (7/20 → 0/20, re-look on
resize/load/pageshow/visibilitychange + 500 ms retry); content-script DOM/network sinks default-denied in the gate.

Review log (external, per unit):
- R1 (main 1210ce5): trinity grok-4.7 / gpt-6-astra / fable all REJECT (menu fill not bound to the clicked
  frame's origin; subframe without frameUrl bound the embedder; reconciler revoked a just-granted origin from a
  stale snapshot; cascade fill; field rules too broad); GATE REJECT (inline insertCSS; fillFocused rebinding);
  SESSION and POPUP approve with SHOULDs (stable repaired ids; conditional offer clear).
- Fixes: fix/v2-app 19b76a2, fix/v2-gate a6fd8b1, test/e2e-v2 f1e2bf2 → main 0509ebf.
- R2: grok APPROVE, fable APPROVE, SESSION APPROVE, POPUP APPROVE; gpt-6 REJECT (bare numeric fallback);
  GATE REJECT (destructuring rebinding via `func:` exception).
- Fixes: fix/v2-rules 7d8c766 (positive OTP sign required), fix/v2-rebind 152d434 (offer to switch accounts on a
  bound site), fix/v2-gate-r2 5c7aa59 (func authorized only in executeScript options; no string computed keys;
  no computed access/aliasing of global objects or Reflect) → main d5c2a05.
- R3: trinity unanimous APPROVE (gpt-6, grok, fable); GATE release-ready. Post-approval narrowing per fable's
  SHOULDs: fix/v2-group 2387795 (group labels for another number skip a box run; a shown non-code input ends a
  run) → main b76be5d.
