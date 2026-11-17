# v0-3-passkey — loop

Status: round 0 (spec approved). Next: A0 owner phone probe on the Z13 (P2) → WU split → code.

## Receipts behind 04 (2026-11-17)

| ID | What | Where |
|---|---|---|
| R-spike | WebAuthn + PRF from an extension page, Chromium 159, CDP virtual authenticator: create/get ok, rpId = `chrome-extension://<id>`, PRF 32 B stable per salt | session scratchpad passkey-spike/results.json (not in repo) |
| R-z13 | Edge 153 on cachy-z13: UVPA false, hybridTransport true, extension:prf true; IR camera /dev/video2; no howdy/fprintd; Bluetooth powered | zbrain workflow/home/rog-flow-z13.md (2026-11-17 bullet) |
| R-docs | Primary-source research (Chromium @7d2c6b8, W3C, Apple/Google/Microsoft/Yubico docs) | 04-passkey-unlock.md Platform facts |

## Open

| ID | Item | Status |
|---|---|---|
| P0 | Edge extension origin scheme for WebAuthn measured on the Z13: Edge 153 headless, CDP virtual authenticators — origin/RP ID = `chrome-extension://<id>` (not edge-extension://), rpIdHash = SHA-256 of that string, PRF 32 B (hasPrf on create+get; usb hasHmacSecret without -mc: enabled on create, bytes on get) | ✅ |
| P1 | trinity on the spec — R1 3×REJECT → rev 2 → R2 2 APPROVE + 1 REJECT (M1 rev vs id, M2 wording) → rev 3 → R3 unanimous APPROVE (grok-4.7, gpt-6-astra, fable) | ✅ |
| P2 | A0 owner probe #1 (2026-11-17 03:48–03:50Z, Edge 153 Linux, one phone over hybrid): create ok (2nd try 10.2 s; 1st NotAllowedError 16.9 s), get ×2 ok (18.7 s, 11.8 s), RP ID `chrome-extension://<id>` accepted, flags UP/UV/BE/BS, transports hybrid+internal — **`prf.enabled` false, no PRF on get** → A0 FAILED for this phone/provider. Cause (provider vs Edge hybrid) not yet separated | 🔴 |
| P3 | A0 probe #2 with probe 0.0.2 (records AAGUID → passkey provider): same phone again + the other phone | 🚪 owner |
