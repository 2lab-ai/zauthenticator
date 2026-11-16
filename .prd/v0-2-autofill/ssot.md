# v0-2-autofill — SSOT (fixed target)

## User directive (verbatim, 2026-11-16)

> 자동으로 otp를 입력해주는 기능 추가해줘. opt 입력란에서 클릭하고 우크릭하면 기존 otp중 선택하게 해주고 그렇게 선택하면 다음부터는 해당 otp 번호가 자동으로 입력되는 기능 추가해줘. (먼저 prd로 옮기고 지금 하던 작업부터 끝까지 완료후 제일 마지막에 작업

Ordering satisfied: v0.1.0 shipped first (release 2026-11-16, loop closed in ../v0-1/loop.done.md).

## Fixed scope

- Behaviour, security rules and traces S0–S4 in [../03-autofill.md](../03-autofill.md).
- Done = merged on main, gates (unit, trust gate with the widened policy, e2e incl. the S1–S4
  paths) green locally and in CI, external review approved, release `v0.2.0` published.
