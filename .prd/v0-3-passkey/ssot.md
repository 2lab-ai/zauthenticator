# v0-3-passkey — SSOT (fixed target)

## User directive (verbatim, 2026-11-17)

> 그리고 이거 암호 패스키로 처리하도록해줘 아이폰, 안드로이드폰, 맥북, 리눅스에서는 패스키 어케하지? 내 리눅스는 z13인데 이거 카메라로 페이스 인증 패스키 못쓰나?

## Reading (decided 2026-11-17, reversible)

- "암호 패스키로 처리" = unlock the vault with a passkey. The passphrase stays as the recovery
  path; removing it is out of scope (irreversible data-loss class, owner decision only).
- Ordering: v0.2.0 (auto-fill + black & white UI) ships first after the owner's Edge test; this
  is v0.3.

## Fixed scope

- Behaviour, record format and flows in [../04-passkey-unlock.md](../04-passkey-unlock.md).
- Done = merged on main, gates green locally and in CI (unit, trust gate, self-test, e2e with
  virtual authenticators), external review approved, owner hand test on the Z13 with a phone,
  release `v0.3.0` published (release tag = owner gate).
