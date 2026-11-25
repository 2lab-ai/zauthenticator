# v0-4 — loop

| ID | Item | Status |
|---|---|---|
| U1 | Unlock time + Extend (#3), branch feat/unlock-time | ✅ unit, CI e2e (unlock-time, extend-*) |
| U2 | Passphrase change / removal / set (#4), branch feat/passphrase | ✅ unit, CI e2e 223/223 |
| U3 | Export: vendored qrcode-generator 2.0.4, migration encoder, view (#5), branch feat/export | ✅ unit, CI e2e 228/228 |
| U4 | Input source + Caps Lock hints (#6), branch feat/input-hints | ✅ unit; layout-shift fix 42b5378; CI e2e key-hints |
| U5 | Docs, store texts, manifest 0.4.0 (#7), branch release/v0.4.0 | ✅ PR #8 merged a9876e7 after an independent review (7 findings fixed in b9aee63); CI e2e 229/229 |
| G1 | Merge to main, tag v0.4.0, release zip sha256 check | ✅ release run 45585159219; zauthenticator-0.4.0.zip 204,400 B, sha256 fd9a0f98…073f = release notes; contents = `git archive v0.4.0 extension` (44 files) |
| G2 | Edge Add-ons: upload zauthenticator-0.4.0.zip as an update, notes, submit | ✅ 2026-11-25 via Partner Center: package 0.4.0 verified, en/ko descriptions replaced, notes 1,768 chars; status In review |
| G3 | Publish API automation (owner choice 'aside-login-api') | ✅ key `zauthenticator-ci` (expires 2027-02-05), repo secrets set and checked (404 vs 401 probe), PR #1 merged 91d99ce |
