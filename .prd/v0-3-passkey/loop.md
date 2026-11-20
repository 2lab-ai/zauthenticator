# v0-3-passkey — loop

Status: round 2 (release). R0 (spec + A0), R1 (build) and the G3 release are in loop.done.md.

## Round 2 — owner gates

Owner instruction (verbatim, 2026-11-20): "v0.3 배포해주고 익스텐션도 버전업한고 올려줘" (release
v0.3, bump the extension version and upload it to the stores). It authorizes the v0.3.0 release
(G3). The A6 real-phone hand test (G2) has not been performed; the release goes ahead on that
instruction without it, and G2 stays open.

| ID | Item | Status |
|---|---|---|
| G1 | Owner-device install of the merged main (same unpacked folder, so the extension id and vault stay; per-file SHA-256 equal to the snapshot) | 🟡 |
| G2 | A6 owner hand test: export a backup first, then enroll with the owner's phone, lock, unlock with the passkey, restart Edge, unlock with the passkey, unlock with the passphrase. Not performed; v0.3.0 is released without it on the owner's 2026-11-20 instruction | 🚪 owner (recommended after the release) |

## Build facts

Gates (snapshot): `npm test` · `npm run check` · `node scripts/check-policy.mjs --self-test` ·
`E2E_HEADLESS=1 npm run e2e`. Baseline at main 86073de: unit 306, gate 0 FAIL, self-test 542,
e2e 119.
