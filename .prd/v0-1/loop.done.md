# v0-1 — done (append-only)

Loop: ./loop.md · Each round close appends one block at the bottom; nothing above it ever changes. Rows here are snapshots (Last Measured frozen at move time). A later pass is a `re-verified` line in a loop.md round section; a regression reopens as a new loop.md row with Source `regression:<ID>`.

## R1 — closed 2026-11-16

- measured: build + review rounds R1–R3 green · result: v0.1 implemented, reviewed to unanimous approval, gates green locally and in CI · closed rows: WU-A WU-B WU-C G1 G2 · commit: main 51cf065

### Closed rows

| ID | Source | Universe Item | Observable Acceptance | AS-IS Evidence | Status | Gap | Dispatch | Verification Evidence | Last Measured |
|---|---|---|---|---|---|---|---|---|---|
| WU-A | plan | core crypto: base32, HOTP/TOTP, otpauth, vault | `npm test` green incl. RFC 4226/6238 vectors | none | ✅ | — | opus-coder, feat/core | 56/56 at 8f98088; RFC 6238 SHA1/256/512 codes cross-checked with Python hmac | 2026-11-16 |
| WU-B | plan | MV3 manifest, popup UI, storage glue, QR import, icons, vendored jsQR 1.4.0 | gate + e2e green against the DOM contract | none | ✅ | — | opus-coder, feat/ui | gate 14/14, e2e 30/30 on combined snapshot at 3634d92 | 2026-11-16 |
| WU-C | plan | trust gate, e2e harness, zip, CI + release workflows, docs | gate self-test + fixture smoke green | none | ✅ | — | opus-coder, feat/tooling | self-test 76/76, smoke 13/13 at 9da2cbb | 2026-11-16 |
| G1 | gap | public repo | github.com/2lab-ai/zauthenticator exists, public, main pushed | repo absent | ✅ | — | dispatcher (gh, after user re-auth) | `gh repo view` PUBLIC; push 552dfd3, 51cf065 | 2026-11-16 |
| G2 | gap | acceptance A1–A10 observed | A1–A9 observed by automated gates; A10 by the release run | not observed | ✅ | A9 toolbar-click activeTab grant is a manual check (decode path + captureVisibleTab call automated) | dispatcher | main 51cf065: unit 113/113, gate 17/17, self-test 218/218, e2e 64/64 (incl. A8 export→delete→import, A9 QR image + SVG refusal); CI run 43841272070 green on 552dfd3 | 2026-11-16 |

### Round section (as it was in loop.md)

Three work units, file ownership disjoint, one coder each, one worktree each
(`.worktrees/<branch-with-dashes>`). Merge order: WU-A → WU-B → WU-C, then the dispatcher
runs `npm test`, `npm run check`, `npm run e2e` on a snapshot and reviews.

Review log (all reviewers external to the coding units):
- R1 (main 289adbf): 3-engine panel (grok-4.7 / gpt-6-astra / fable) on vault+store+session, plus gpt-6 reviewers on UI-1 (popup/settings/session), UI-2 (list/add/qr/otpauth), GATE (check-policy + workflows) → all REJECT. Blockers: cross-page lost updates, lock not invalidating in-flight work, inputs not cleared on lock, image limits after decode, gate CSP incomplete, network claim broader than CSP, vault loss on move/uninstall (README).
- Round 2 fixes (contract in 02-architecture "Round 2"): fix/state 07cd5c1, fix/inputs 841b495, fix/tooling 6fb65e3, fix/list-race 4094bdc → main a1dcfb1 (unit 91, gate 16, self-test 180, e2e 47; new e2e assertions RED on R1 code).
- R2: panel unanimous APPROVE (fable, gpt-6-astra, grok-4.7); UI-1 approve; UI-2 REJECT (unsniffed formats decoded unbounded); GATE REJECT (navigation exemption prefix-only; CSP Unicode whitespace).
- Round 3 fixes (contract in 02-architecture "Round 3"): nav.js wrapper 901c0a5, fix/qr-format e856562, fix/app-r3 940738f, fix/gate-r3 b9192a1, fix/r3b 073fa93 → main 35abe8a/552dfd3.
- R3: UI-2 approve, GATE approve (lexical gaps accepted under the stated tripwire claim). Follow-ups: README vendor scope 80fdd58, ids faf2488, delete-false/array entries d1c989c, e2e A8/A9 + language-aware text checks e8e49ca → main 51cf065.
