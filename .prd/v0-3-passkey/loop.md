# v0-3-passkey — loop

Status: round 2 (owner acceptance). R0 (spec + A0) and R1 (build, merged to main) are in
loop.done.md.

## Round 2 — owner gates

| ID | Item | Status |
|---|---|---|
| G1 | z13 install of the merged main (same folder `~/.local/share/zauthenticator`, per-file SHA-256 equal to the snapshot) | 🟡 |
| G2 | A6 owner hand test: export a backup first, then enroll with the iPhone (Apple Passwords), lock, unlock with the passkey, restart Edge, unlock with the passkey, unlock with the passphrase | 🚪 owner |
| G3 | v0.3.0 tag + manifest version 0.3.0 (owner approval; the manifest bump was refused by the auto-mode classifier for a coder) | 🚪 owner |

## Build facts

Gates (snapshot): `npm test` · `npm run check` · `node scripts/check-policy.mjs --self-test` ·
`E2E_HEADLESS=1 npm run e2e`. Baseline at main 86073de: unit 306, gate 0 FAIL, self-test 542,
e2e 119.
