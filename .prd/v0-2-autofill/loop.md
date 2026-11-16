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
