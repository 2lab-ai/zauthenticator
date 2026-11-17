# v0-3-passkey — loop

Status: round 1 (build). Spec rev 4 with frozen module contracts (04-passkey-unlock.md
"Module contracts"). R0 (spec + gate A0) is in loop.done.md.

## Round 1 — work units

Integration branch `feat/v0.3-passkey`, worktree `.worktrees/feat-v0.3-passkey`. Each unit owns
only its files; the dispatcher re-runs every gate on a `git archive` snapshot and commits.

| ID | Files | Needs | Status |
|---|---|---|---|
| WU-V | extension/lib/vault.js, test/vault.test.mjs | contracts | 🔴 |
| WU-G | scripts/check-policy.mjs (rule `credentials-api`, PINNED_POLICY, self-test cases) | contracts | 🔴 |
| WU-S | extension/lib/store.js, extension/popup/session.js, test/session.test.mjs | WU-V | 🔴 |
| WU-U | extension/popup/passkey.js (new), popup.js, popup.html, settings.js, format.js, popup.css, _locales/{en,ko}/messages.json | WU-S, WU-G | 🔴 |
| WU-E | e2e/passkey.e2e.mjs (new, run from e2e/popup.e2e.mjs), e2e/reference.mjs | WU-U | 🔴 |
| WU-D | README.md, PRIVACY.md, store/listing/*, 04 → shipped | WU-U | 🔴 |

Then: trinity on the security core (vault + store + session diff), one gpt6-reviewer per
change-set (UI, gate, e2e, docs), merge to main, CI green, z13 install, owner hand test (A6).
The v0.3.0 tag is an owner gate.

## Build facts

Gates (snapshot): `npm test` · `npm run check` · `node scripts/check-policy.mjs --self-test` ·
`E2E_HEADLESS=1 npm run e2e`. Baseline at main 86073de: unit 306, gate 0 FAIL, self-test 542,
e2e 119.
