# v0-4 — SSOT (fixed target)

## Owner directives (verbatim, 2026-11-25)

SSOT_1:

> 2lab-ai/zauthenticator 개선하고 릴리즈 배포 + 엣지 스토어에 배포
> - 비밀번호 변경 기능(비밀번호 제거 가능. 단 빨갛게 2번 다시 물어보고 그래도 하겠다고 하면 변경 - 이때는 로컬 하드디스크 시리얼이든 현재 컴퓨터 핑거프린트로 암호화 처리)
> - 클립보드로 export 기능 otpauth://... 뭐 이런걸로 익스포트해서 다른 곳에서 임포트할 수 있는 기능 (하나만 혹은 여러개 선택할수 있고 출력으로 QR을 보여주게 할수 있다. (구글 authentificator에서 바로 import 할수 있도록)
> - 비밀번호 입력시 입력 소스와 capslock 여부 표시

SSOT_2:

> 또 개선사항
> - 디폴트로 암호를 풀면 15분동안 사용할수 있는데 익스텐션 앱을 클릭하면 이게 디폴트로 15분씩 늘어나게 해줘
> - 그리고 클릭시에 이 15분 unlock 기간을 표시해주고 여기에 매뉴얼 extend할수 있게해줘. 1시간, 24시간, 7일 이런식으로. ai 에이전트가 사용할 수 있게 풀어놓을 수 있는 기능이고 이렇게 extend를 시도하려고하면 빨간표시로 2번 컨펌받게 해줘

## Reading (decided 2026-11-25, reversible)

- Tracking: epic #2, sub-issues #3 (unlock time), #4 (passphrase), #5 (export), #6 (input hints),
  #7 (release and Edge update).
- "로컬 하드디스크 시리얼이든 현재 컴퓨터 핑거프린트" is read as "bound to this computer, no
  passphrase". An extension cannot read a disk serial without a native helper, and a browser
  fingerprint changes (drivers, monitors), which would lose the vault. The device key is a random
  non-extractable WebCrypto AES-GCM key kept in the extension's IndexedDB.
- "빨갛게 2번 다시 물어보고": a red warning and a red final check, each starting on Cancel, the
  red button armed after 600 ms (a double click cannot pass both). The same component guards
  Extend.
- "클릭하면 15분씩 늘어나게": opening or using the extension moves the lock time to at least
  15 minutes from now (the idle rule, made visible); it never shortens a manual extension.
- "입력 소스": the input source the keys produce (script of the produced character, or an input
  method composing), never the characters.
- Change passphrase follows spec 04's rule: new DEK, new id, passkey slots dropped.

## Fixed scope

Done = merged on main, gates green locally and in CI, v0.4.0 released with its zip, the same zip
submitted to Edge Add-ons as an update.
