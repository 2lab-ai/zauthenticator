# v0-1 — SSOT (fixed target)

## User directive (verbatim, 2026-11-16)

> 다음의 엣지 프로파일로 2FA 인증이 확장 프로그램 설치 했는데 이거 믿을수가 없잖아? 이거 소스 확인해주고 /zworkflow:using-dotprd 이용해서 2lab-ai/zauthentificator로 크롬 확장 프로그램으로 만들어주고 오픈소스로 공개해줘

Name correction (verbatim, 2026-11-16): "z authenticator임 오타였음" → the name is `zauthenticator`
(the GitHub repo was renamed from `zauthentificator`; GitHub keeps a redirect from the old name).

Follow-up (ordering, verbatim): auto-fill is specified in [../03-autofill.md](../03-autofill.md) and is
built **after** this workstream ships ("지금 하던 작업부터 끝까지 완료후 제일 마지막에 작업").

## Fixed scope

- Repository name exactly `2lab-ai/zauthenticator`, public, open-source license (MIT).
- A Chromium Manifest V3 TOTP extension meeting [../01-spec.md](../01-spec.md) A1–A10 under
  [../02-architecture.md](../02-architecture.md).
- Done = public repo on GitHub + green CI + a `v0.1.0` release zip + the extension observed working
  in a real Chromium (codes match an independent implementation, network blocked).
