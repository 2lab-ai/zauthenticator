# v0-2-autofill — loop (open work only)

Status: done (2026-11-16) — closed rows and the review log are in [loop.done.md](loop.done.md).

## Next

- Release `v0.2.0` (tag → release workflow attaches `zauthenticator-0.2.0.zip`).

## Manual checks (not automatable)

- The native permission prompt in the bind flow (S2) on a real site.
- The browser context menu UI (right-click in an OTP field lists the accounts).

## Open for v0.3 (from the reviews, by decision)

- Per-origin "don't ask again" for the bind offer (also covers two accounts on one site).
- Non-default-port origin e2e; sandboxed frame bind offer uses `location.origin` (auto-fill later refused, fails closed).
- Measure the 500 ms / 60 s re-look cost on input-heavy pages.
- A second code prompt on the same page load (single-page apps) gets no auto-fill (one fill per page load).
- Box runs: ending a run at a shown non-code input can split an over-long group into a qualifying run
  (e.g. 4 boxes + checkbox + 6 boxes); pin with fixtures and decide whether a group with more than 8 boxes
  is skipped outright. A group named for another number also blocks boxes marked one-time-code — document
  or let the box-level mark win (fable, post-approval confirm of 2387795, APPROVE).

## Round 2 (2026-11-16) — user hand test

- Manual checks done by the user on cachy-z13 Edge with v0.2.0 (main e474db8): "잘 작동되는데" — context
  menu fill, bind window + native permission prompt and auto-fill on revisit observed working.
- Open: first attempt submitted an expired code → fresh-code + retry contract in 03-autofill.md
  ("Fresh code and retry after a failed attempt"). Tag v0.2.0 after this lands.
