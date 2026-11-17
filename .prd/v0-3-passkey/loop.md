# v0-3-passkey — loop

Status: round 1 (build). Spec rev 4 with frozen module contracts (04-passkey-unlock.md
"Module contracts"). R0 (spec + gate A0) is in loop.done.md.

## Round 1 — work units

Integration branch `feat/v0.3-passkey`, worktree `.worktrees/feat-v0.3-passkey`. Each unit owns
only its files; the dispatcher re-runs every gate on a `git archive` snapshot and commits.

| ID | Files | Needs | Status |
|---|---|---|---|
| WU-V | extension/lib/vault.js, test/vault.test.mjs | contracts | 🟡 vault 30/30; internal open → openRecord (navigation tripwire); awaits trinity |
| WU-G | scripts/check-policy.mjs (rule `credentials-api`, PINNED_POLICY, self-test cases) | contracts | 🟡 self-test 562/562, check 22 PASS; gpt6-reviewer APPROVE |
| WU-S | extension/lib/store.js, extension/popup/session.js, test/session.test.mjs, test/autofill-worker.test.mjs fixture adaptation | WU-V APIs | 🟡 session+worker 115/115 (worker assertions unchanged, fixture drains rebuild); awaits trinity |
| WU-U | extension/popup/passkey.js (new), popup.js, popup.html, settings.js, format.js, popup.css, _locales/{en,ko}/messages.json, test/passkey.test.mjs | WU-S APIs, WU-G | 🟡 R1 REJECT (hidden passphrase kept; orphan notice lost) + unlock-cancel bug → fixed, passkey 24/24; R2 APPROVE. Manifest 0.3.0 bump refused by the auto-mode classifier → stays 0.2.0 until the release gate |
| WU-E | e2e/passkey.e2e.mjs (new, run from e2e/popup.e2e.mjs), e2e/reference.mjs, e2e/autofill.e2e.mjs session-shape assertions | WU-U | 🔴 |
| WU-D | README.md, PRIVACY.md, store/listing/*, 04 → shipped | WU-U | 🟡 R1 REJECT (passphrase-only backup overclaim) → fixed; README/PRIVACY version-scoped (main PRIVACY backs the v0.2.0 submission); R2 REJECT (2 wording lines) → fixed; R3 APPROVE. 04 → shipped after merge |

Then: trinity on the security core (vault + store + session diff), one gpt6-reviewer per
change-set (UI, gate, e2e, docs), merge to main, CI green, z13 install, owner hand test (A6).
The v0.3.0 tag is an owner gate.

## Build facts

Gates (snapshot): `npm test` · `npm run check` · `node scripts/check-policy.mjs --self-test` ·
`E2E_HEADLESS=1 npm run e2e`. Baseline at main 86073de: unit 306, gate 0 FAIL, self-test 542,
e2e 119.
