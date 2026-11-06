# Hermes #761 - dependency source inventory (e76c04a77ba9)

> **STATUS: PARTIAL / SOURCE_INVENTORY.** This report is not a passing dependency-audit/security gate, not a fresh full CVE scan, and not proof of the installed production runtime. Generated 2026-11-06 against [immutable main](https://github.com/MikeMoore1337/hermes/commit/e76c04a77ba9446ebb3fc959aa95fd57ea6ab12d).

Machine-readable complete **frontend lockfile package records** (not installed packages): [H-761-dependency-inventory-2026-11-06.json](H-761-dependency-inventory-2026-11-06.json). No external automation or dependency manager has been introduced.

## Scope and observed inventories

| Surface | Observed from source | Missing runtime/security evidence |
|---|---|---|
| Python | 2 direct exact pins in `deploy/requirements-gsc-readonly.txt`: `google-auth==2.62.0`, `requests==2.33.0` | No fresh isolated install, transitive resolution, Python 3.14 wheel proof, `pip-audit`/unused-import full scan. Historical image inventory: 146 venv distribution records, 145 unique names and 274 OS packages on 2026-10-15. Not re-scanned here. |
| React/Vite | `control_center/frontend/package.json` + package-lock v3: **120 nonroot package records**, 121 including root; exact versions preserved in JSON | No fresh npm audit (all dependencies), npm ci/build/Playwright or compiled web bundle check on this SHA in this source-only review |
| Docker | **5 Dockerfiles**: immutable digest references for NousResearch agent and Node BRC relay; devtools base requires a supplied immutable digest | No fresh exact-image OS/package scan, new vulnerability DB, build/runtime smoke or source-to-image provenance |
| GitHub Actions | **23 YAML workflows** in main | Reviewed explicit `uses` references; exact-SHA pin update in [PR #822](https://github.com/MikeMoore1337/hermes/pull/822). H454 candidate workflow mutable tags are deferred due to overlapping [PR #692](https://github.com/MikeMoore1337/hermes/pull/692). No full CI acceptance of all workflows claimed |
| External upstream | Hermes Agent v0.22.2, BRC fork, ECC, Harness² pinned according to source docs and issue #764 | No automatic upstream bump, no E2E/activation; issues #199/#632/#629 keep independent scopes |

### Exact Docker FROM references (source-only)

| Dockerfile | FROM reference(s) |
|---|---|
| `deploy/h15/Dockerfile.brc-relay` | `FROM node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS builder`, `FROM node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS runtime` |
| `deploy/h15/devtools/Dockerfile` | `FROM ${BRC_BASE_IMAGE}` |
| `docker/v0221-native-tool-policy-test/Dockerfile` | `FROM nousresearch/hermes-agent@sha256:cd9cb455576d27c9b6311de1104494ad7e221b6e68dc77e9ac2a8af661a4dc21` |
| `docker/v0222-native-tool-policy-test/Dockerfile` | `FROM nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05` |
| `docker/v0222-pyjwt-fixed-candidate/Dockerfile` | `FROM nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05` |

Note: the devtools `FROM ${BRC_BASE_IMAGE}` is a variable: its exact permitted value must be confirmed at build invocation. The H-15 offline workflow also performs `docker pull python:3.13-slim` without an immutable digest; this is a separate **REVIEW_REQUIRED** provenance risk and **was not** silently changed in PR #822.

## Decisions and applicability

- **KEEP**: GSC `requests==2.33.0` already fixed in merged [PR #765](https://github.com/MikeMoore1337/hermes/pull/765). `google-auth==2.62.0` has no newly established applicable advisory in this review; lack of proof is **not** a claim of safety.
- **UPDATE (PR #822)**: replace mutable `checkout@v4` and `upload-artifact@v4` in the H-15 ephemeral offline workflow with official verified SHA (v4.2.2 and v4.6.2). Only source proposed, no owner production change. [Official action pin recommendation](https://docs.github.com/en/actions/reference/security/secure-use).
- **REVIEW_REQUIRED**: `react/react-dom 19.2.0` -> verified upstream release 19.2.9 / 19.3.1; `@playwright/test 1.56.1` -> upstream 1.65.0. Do not update `package.json` alone: committed `package-lock.json`, generated `control_center/web` bundle, npm checks and actual browser regression are mandatory. Earlier successful isolated tests on old `main` (comment in #761) do not prove current compatibility. [React releases](https://github.com/facebook/react/releases) / [Playwright releases](https://github.com/microsoft/playwright/releases).
- **DEFER**: Vite 7 -> 8, `@vitejs/plugin-react` 5 -> 6, lucide-react 0.x -> 1.x: potential breaking/visual changes require a separately reviewed upgrade, not a security-driven silent major bump.
- **NOT_APPLICABLE to locked graph**: October 2026 critical RSC advisories affect `react-server-dom-*`, **zero such packages** found in this `package-lock.json`. This is not a runtime security attestation. [Official RSC advisory](https://github.com/react/react/security/advisories/GHSA-xqc2-xf4c-x3h3).
- **NOT_APPLICABLE to this Vite version**: published CVE-2026-39364 lists Vite 7.1.0-7.3.1; main pins 7.3.7. [Advisory](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-124/).
- **DEFER separate #199**: v0.22.2 Hermes Agent image historical scan on 2026-10-16 yielded 4 CRITICAL / 270 HIGH records; this review did **not** reproduce or reclassify them. An isolated PyJWT 2.15.1 derivative and 3 remaining historical CRITICAL findings are documented at [H-18](H-18-v0222-pyjwt2151-target-2026-10-16.md), but that is not a production update. Preserve exact upstream image pin and owner GO gate.
- **KEEP completed scope #764**: Zod/transitive BRC fork source fixes already merged; do not reset or repeat them. BRC production runtime remains unverified in this audit.

## Checks and explicit remaining work

- Static source inspection **PASS** for manifest, lockfile, 5 Dockerfiles, action references, relevant upstream documentation and open PR file overlaps. No secrets or private package inventories were loaded from VPS.
- Current full `npm ci && npm run check && npm run test && npm run build && npm audit` = **NOT_RUN** in isolated main checkout. Direct sandbox Git/network lookup failed due DNS; it cannot fetch dependencies. A passing existing unrelated build must not be treated as the updated frontend acceptance.
- Full Python runtime dependency resolution, OS image vulnerability scan, Docker build, browser UI interaction, source-to-image SBOM and independently executed review = **NOT_RUN**. Historical reports are referenced rather than relabelled.
- Production deployment workflow uses **manual `workflow_dispatch`**, exact owner-approved cumulative SHA and required checks. This source-only PR does not run it.
- Open PR overlap check: #746, #743, #742, #692; do not change shared H15/H454 workflow/runtime/transport files.

**Exit decision**: #761 remains OPEN until fresh vulnerability inventory (including transitive/install/runtime), risk classification and justified fixes, dependency audit, regression and exact-head CI, and independent review are actually completed. This report itself must not be used as a security waiver or production GO.

## Сверка с новым `main` и результаты реального CI (06.11.2026)

После исходной инвентаризации `main` продвинулся до [`7cc4237721107434425c0e7638606aeb6296e253`](https://github.com/MikeMoore1337/hermes/commit/7cc4237721107434425c0e7638606aeb6296e253), но **blob SHA `package-lock.json` и GSC requirements не изменились**, поэтому следующие аудиты относятся к тому же набору версий. Изменения в Control Center JS/CSS не означают, что эта документация проверила каждую live-функцию.

| Область | Точное проверенное основание | Результат | Ограничение |
| --- | --- | --- | --- |
| Frontend, включая dev/transitive | [PR #825](https://github.com/MikeMoore1337/hermes/pull/825), SHA `5b22a34f0847754e4442d76051e6ee74010466ca`, [CI #42228040544](https://github.com/MikeMoore1337/hermes/actions/runs/42228040544) | `npm ci` PASS, полный `npm audit --audit-level=moderate` **found 0 vulnerabilities**, production-only audit 0; Vite/committed bundle/Playwright browser CI SUCCESS | Результат на дату CI; не signed SBOM, не проверка production-сервера |
| Python 3.14 GSC | [PR #826](https://github.com/MikeMoore1337/hermes/pull/826), SHA `4fd191d8d2e130ff6bca8ede719518c035f83b9a`, [CI #42228544921](https://github.com/MikeMoore1337/hermes/actions/runs/42228544921) | `pip check` PASS, импорт `google.auth` и `requests==2.33.0` PASS; `pip-audit==2.10.1` **No known vulnerabilities found** с учётом транзитивных зависимостей; 11 сторонних установленных пакетов GSC | Это изолированный CI, без Google OAuth, VPS или resident Hermes |
| H-15 disposable proof | [PR #822](https://github.com/MikeMoore1337/hermes/pull/822), SHA `e2b9f07e0eef5cc3f1d41f299ef60144b516021c`, [CI #42228801514](https://github.com/MikeMoore1337/hermes/actions/runs/42228801514) | Подтверждённый Docker Hub digest `sha256:09a17cad02668ae61ece136b4fd36ac3849e14f670ebedb637ea3e15580525bc`, испытание изоляции после закрепления PASS | Не является аттестацией издателя или обновлением Hermes Agent image |

**Источник угроз и оставшиеся риски:** Нет оснований объявить отсутствие неизвестных CVE только по `npm audit`/`pip-audit`; для Hermes Agent v0.22.2 исторические findings и остаточная применимость остаются в #199 (не подменяются свежими результатами этой #761). BRC security #764 уже принят. Открытый #692 редактирует H454 CI, поэтому отдельные mutable Actions там оставлены для неконфликтующей последующей правки.

**Границы приёмки:** Docker SBOM/Trivy с обновлённой базой по фактическим runtime образам, полное перечисление установленного upstream Python 3.14.7, ОС/host kernel/SSH/XML reachability, независимое внешнее code/security review и установка на production **NOT_RUN/DEFERRED**. Статус #761 не может считаться полным GO из-за этого раздела. Выводы относятся только к указанным SHA и CI, а не автоматически к любому будущему `main`.
