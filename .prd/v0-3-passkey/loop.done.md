# v0-3-passkey — done

## R0 — closed

Spec approved (trinity R3 unanimous) and gate A0 passed with an iPhone (Apple Passwords) on 2026-11-17.

### Closed rows

| ID | Item | Status |
|---|---|---|
| P0 | Edge extension origin scheme for WebAuthn measured on the Z13: Edge 153 headless, CDP virtual authenticators — origin/RP ID = `chrome-extension://<id>` (not edge-extension://), rpIdHash = SHA-256 of that string, PRF 32 B (hasPrf on create+get; usb hasHmacSecret without -mc: enabled on create, bytes on get) | ✅ |
| P1 | trinity on the spec — R1 3×REJECT → rev 2 → R2 2 APPROVE + 1 REJECT (M1 rev vs id, M2 wording) → rev 3 → R3 unanimous APPROVE (grok-4.7, gpt-6-astra, fable) | ✅ |
| P2 | A0 owner probe #1 (2026-11-17 03:48–03:50Z, Edge 153 Linux, Android phone over hybrid): create ok (2nd try 10.2 s; 1st NotAllowedError 16.9 s), get ×2 ok (18.7 s, 11.8 s), RP ID `chrome-extension://<id>` accepted, flags UP/UV/BE/BS, transports hybrid+internal, `prf.enabled` false and no PRF on get. Probe #2 (below) identified the provider as Samsung Pass | ✅ |
| P3 | A0 probe #2, probe 0.0.2 (records the AAGUID → provider), 2026-11-17 05:28–05:30Z, Edge 153 Linux over hybrid. **Android phone, Samsung Pass** (AAGUID 53414d53-554e-4700-0000-000000000000): create ok 15 s, `prf.enabled` false; get1 8.3 s, get2 8.6 s, `prf` key present with no `results` (the probe requests `prf.eval.first` on both gets, probe.js L235) → no unlock key. **iPhone, Apple Passwords** (AAGUID fbfc3007-154e-4ecc-8c0b-6e020557d7bd): create ok 23.4 s, `prf.enabled` true, 32 B; get1 10.3 s, get2 15.4 s, 32 B each; SHA-256 prefix fb7682b6 on create, get1 and get2 → **A0 met**. Google Password Manager over hybrid not measured (optional owner probe) | ✅ |

### R0 receipts

| ID | What | Where |
|---|---|---|
| R-spike | WebAuthn + PRF from an extension page, Chromium 159, CDP virtual authenticator: create/get ok, rpId = `chrome-extension://<id>`, PRF 32 B stable per salt | session scratchpad passkey-spike/results.json (not in repo) |
| R-z13 | Edge 153 on cachy-z13: UVPA false, hybridTransport true, extension:prf true; IR camera /dev/video2; no howdy/fprintd; Bluetooth powered | zbrain workflow/home/rog-flow-z13.md (2026-11-17 bullet) |
| R-docs | Primary-source research (Chromium @7d2c6b8, W3C, Apple/Google/Microsoft/Yubico docs) | 04-passkey-unlock.md Platform facts |
| R-probe2 | Both probe 0.0.2 result JSONs as pasted by the owner | session transcript 2026-11-17 (not in repo) |
