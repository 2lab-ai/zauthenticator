# v0-1 — loop (open work only)

Status: in-progress (2026-11-16)

## Round 1 plan

Three work units, file ownership disjoint, one coder each, one worktree each
(`.worktrees/<branch-with-dashes>`). Merge order: WU-A → WU-B → WU-C, then the dispatcher
runs `npm test`, `npm run check`, `npm run e2e` on a snapshot and reviews.

| ID | Status | Branch | Scope (owned files) |
|---|---|---|---|
| WU-A | 🟡 | feat/core | `extension/lib/{base32,totp,otpauth,vault}.js`, `test/*.test.mjs` |
| WU-B | 🟡 | feat/ui | `extension/manifest.json`, `extension/popup/*`, `extension/lib/{store,qr}.js`, `extension/vendor/*`, `extension/icons/*` |
| WU-C | 🟡 | feat/tooling | `package.json`, `scripts/*`, `e2e/*`, `.github/workflows/*`, `README.md`, `LICENSE`, `SECURITY.md` |

## Gaps

| ID | Status | Gap |
|---|---|---|
| G1 | 🔴 | Publishing: GitHub repo `2lab-ai/zauthenticator` not created yet. |
| G2 | 🔴 | A1–A10 not yet observed. |

## Build facts

- Node v26.9.0 (`node --test`, global WebCrypto). Playwright 1.65.1 with cached Chromium builds.
