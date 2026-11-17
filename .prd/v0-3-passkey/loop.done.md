# v0-3-passkey — done

## R0 — closed

Spec approved (trinity R3 unanimous) and gate A0 passed with an iPhone (Apple Passwords) on 2026-11-17.

### Closed rows

| ID | Item | Status |
|---|---|---|
| P0 | Edge extension origin scheme for WebAuthn measured on the owner's Linux laptop: Edge 153 headless, CDP virtual authenticators — origin/RP ID = `chrome-extension://<id>` (not edge-extension://), rpIdHash = SHA-256 of that string, PRF 32 B (hasPrf on create+get; usb hasHmacSecret without -mc: enabled on create, bytes on get) | ✅ |
| P1 | trinity on the spec — R1 3×REJECT → rev 2 → R2 2 APPROVE + 1 REJECT (M1 rev vs id, M2 wording) → rev 3 → R3 unanimous APPROVE (grok-4.7, gpt-6-astra, fable) | ✅ |
| P2 | A0 owner probe #1 (2026-11-17, Edge 153 Linux, Android phone over hybrid): create ok (2nd try; 1st NotAllowedError), get ×2 ok, RP ID `chrome-extension://<id>` accepted, flags UP/UV/BE/BS, transports hybrid+internal, `prf.enabled` false and no PRF on get. Probe #2 (below) identified the provider as Samsung Pass | ✅ |
| P3 | A0 probe #2, probe 0.0.2 (records the AAGUID → provider), 2026-11-17, Edge 153 Linux over hybrid. **Android phone, Samsung Pass** (AAGUID 53414d53-554e-4700-0000-000000000000): create ok, `prf.enabled` false; get1 and get2 ok, `prf` key present with no `results` (the probe requests `prf.eval.first` on both gets, probe.js L235) → no unlock key. **iPhone, Apple Passwords** (AAGUID fbfc3007-154e-4ecc-8c0b-6e020557d7bd): create ok, `prf.enabled` true, 32 B; get1 and get2 32 B each; PRF outputs equal on create, get1 and get2 (the probe compared full SHA-256 digests; values omitted) → **A0 met**. Google Password Manager over hybrid not measured (optional owner probe) | ✅ |

### R0 receipts

| ID | What | Where |
|---|---|---|
| R-spike | WebAuthn + PRF from an extension page, Chromium 159, CDP virtual authenticator: create/get ok, rpId = `chrome-extension://<id>`, PRF 32 B stable per salt | session scratchpad passkey-spike/results.json (not in repo) |
| R-device | Edge 153 on the owner's Linux laptop: UVPA false, hybridTransport true, extension:prf true; IR camera present; no howdy/fprintd; Bluetooth powered | owner's device notes (not in repo) |
| R-docs | Primary-source research (Chromium @7d2c6b8, W3C, Apple/Google/Microsoft/Yubico docs) | 04-passkey-unlock.md Platform facts |
| R-probe2 | Both probe 0.0.2 result JSONs as pasted by the owner | session transcript 2026-11-17 (not in repo) |

## R1 — closed

Build merged to main 2026-11-17; every work unit reviewed and re-gated on a snapshot.

### Closed rows

Integration branch `feat/v0.3-passkey`, worktree `.worktrees/feat-v0.3-passkey`. Each unit owns
only its files; the dispatcher re-runs every gate on a `git archive` snapshot and commits.

| ID | Files | Needs | Status |
|---|---|---|---|
| WU-V | extension/lib/vault.js, test/vault.test.mjs | contracts | ✅ vault 30/30; trinity T1 unanimous APPROVE R1 (be30988); P1 probes run by dispatcher (cred 16/20/64/1023 B round trip, v1 revision key-order independent) |
| WU-G | scripts/check-policy.mjs (rule `credentials-api`, PINNED_POLICY, self-test cases) | contracts | ✅ self-test 562/562, check 22 PASS; gpt6-reviewer APPROVE |
| WU-S | extension/lib/store.js, extension/popup/session.js, test/session.test.mjs, test/autofill-worker.test.mjs fixture adaptation | WU-V APIs | ✅ trinity T2 R1 2×REJECT (absent lockGen at capture + failed lock write → stale unlock commits) → f21b6dd ensureLockGen, RED→GREEN; R2 unanimous APPROVE. a3e45aa: saved enrollment never rejects (fable residual). bac5fd8/b622854 pin both-writes-fail (gpt6-reviewer R2 APPROVE); unit 362/362 |
| WU-U | extension/popup/passkey.js (new), popup.js, popup.html, settings.js, format.js, popup.css, _locales/{en,ko}/messages.json, test/passkey.test.mjs | WU-S APIs, WU-G | ✅ R1 REJECT (hidden passphrase kept; orphan notice lost) + unlock-cancel bug → fixed, passkey 24/24; R2 APPROVE. Manifest 0.3.0 bump refused by the auto-mode classifier → stays 0.2.0 until the release gate |
| WU-E | e2e/passkey.e2e.mjs (new, run from e2e/popup.e2e.mjs), e2e/reference.mjs, e2e/autofill.e2e.mjs session-shape assertions | WU-U | ✅ R1 REJECT (no-op v2 import passes; window removal race never delivers; A3 import/idle/identity unpinned) → 79cd635, mutants fail each new test; R2 APPROVE; variant filter rejects unknown names |
| WU-D | README.md, PRIVACY.md, store/listing/*, 04 → shipped | WU-U | ✅ R1 REJECT (passphrase-only backup overclaim) → fixed; README/PRIVACY version-scoped (main PRIVACY backs the v0.2.0 submission); R2 REJECT (2 wording lines) → fixed; R3 APPROVE. 04 status → shipped |

Result: trinity T1 (vault) unanimous R1; trinity T2 (session) R1 2×REJECT → f21b6dd → R2 unanimous;
one gpt6-reviewer per change-set (UI R2, gate R1, docs R3, e2e R2, a3e45aa/bac5fd8 R2). Snapshot
gates on 79cd635: unit 362/362, check 22 PASS, self-test 562/562, e2e 199/199 (baseline 306 · 542 · 119).
The About string (d60779c) no longer says the key comes from the passphrase alone.
