# v0-1 — loop (open work only)

Status: done (2026-11-16) — closed rounds and rows are in [loop.done.md](loop.done.md).

## Next

- Release `v0.1.0` (tag → release workflow attaches `zauthenticator-0.1.0.zip`).
- Next workstream: auto-fill, spec [../03-autofill.md](../03-autofill.md).

## Manual check (not automatable)

- A9 toolbar path: click the toolbar icon on a page showing an otpauth QR, Add → "Scan this tab". The activeTab grant only exists after a real toolbar click.

## Build facts

- Node v26.9.0 locally, Node 22 in CI (`node --test test/*.test.mjs`, global WebCrypto). Playwright 1.65.1.
