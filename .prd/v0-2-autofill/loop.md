# v0-2-autofill — loop (open work only)

Status: done (2026-11-16) — closed rows and the review log are in [loop.done.md](loop.done.md).

## Next

1. Owner hand test of main (black & white UI, merges 5960300 + c9dcace, 2026-11-17) on cachy-z13 Edge
   (reload the extension): black & white popup and icon, auto-fill, a rejected code refilled with a fresh one.
2. Release `v0.2.0` (tag → release workflow attaches `zauthenticator-0.2.0.zip`) — owner gate, after 1.
3. Store submission (Chrome Web Store, Edge Add-ons) by the owner from `store/listing/` + `store/assets/`.

## Manual checks (not automatable)

- The native permission prompt in the bind flow (S2) on a real site.
- The browser context menu UI (right-click in an OTP field lists the accounts).

## Open for v0.3 (from the reviews, by decision)

- Per-origin "don't ask again" for the bind offer (also covers two accounts on one site).
- Non-default-port origin e2e; sandboxed frame bind offer uses `location.origin` (auto-fill later refused, fails closed).
- Measure the 500 ms / 60 s re-look cost on input-heavy pages.
- Box runs: ending a run at a shown non-code input can split an over-long group into a qualifying run
  (e.g. 4 boxes + checkbox + 6 boxes); pin with fixtures and decide whether a group with more than 8 boxes
  is skipped outright. A group named for another number also blocks boxes marked one-time-code — document
  or let the box-level mark win (fable, post-approval confirm of 2387795, APPROVE).
- Origin-wide code cap across tabs (budget is per tab+origin; fable R5 SHOULD-1).
- Unit case: fill → refresh → retry into a replaced node → period end → 4th request gets {code:null}
  (fable post-approval confirm of 161f0b4).
