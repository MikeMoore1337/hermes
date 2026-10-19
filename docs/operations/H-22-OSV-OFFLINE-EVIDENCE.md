# H-22 / #189 - OSV-Scanner: bounded offline evidence pilot

**State:** repository-only experimental reviewer. No OSV binary, local OSV database or real project lockfile was used in this PR. **No finding count, package safety, scanning success or vulnerability remediation is claimed.** Production, CI security checks and external credentials unchanged.

## Why this is separate from Trivy

- Hermes immutable OCI image v0.22.2: #185 and #199 already use Syft/Trivy, so OSV lockfile scan **does not substitute** OCI SBOM or source-to-image attestation.
- YFC: existing CodeQL/Trivy/dependency-audit controls; general OSV addition now would duplicate work without a proven gap.
- Second Brain: `uv.lock` exists and dependency SCA coverage might be missing. It is a *candidate* for a separate approved code-repository-only pilot, never for private vault or source upload.
- Hermes itself: exact pinned upstream image plus private runtime must keep #33 resident **NO-GO**.

## Authoritative upstream contracts

- [OSV-Scanner v2.7.0](https://github.com/google/osv-scanner/releases/tag/v2.7.0) (released 2026-10-12) is the fixed version chosen for future execution; **publisher binary signature and archive SHA256 are not verified**.
- [Offline mode](https://github.com/google/osv-scanner/blob/main/docs/offline-mode.md): `--offline` prohibits vulnerability API queries and local database updates; the database must already exist. With missing or stale database, no clean PASS is permitted. `--offline-vulnerabilities` **is not equivalent**: other features may access the network.
- [JSON format](https://github.com/google/osv-scanner/blob/main/docs/output.md): `results[].source.type=lockfile`, `results[].packages[].package`, `vulnerabilities[].id/aliases`; absolute source paths and package names may be present and must not be published.
- [Source scan](https://github.com/google/osv-scanner/blob/main/docs/usage.md): supported `-L <lockfile>`; no `fix` subcommand, autofix, registry resolution or vulnerability DB downloads in restricted execution.

## Implemented in Hermes (no scanner execution)

`scripts/review_osv_offline_scan.py` is a Python stdlib-only **input evidence reviewer**, not an OSV implementation or a wrapper that executes `osv-scanner`. It accepts a locally supplied OSV JSON report, the lockfile and an unsigned operator manifest. Schema `hermes-h22-osv-evidence-v1` requires:

- exact claimed scanner version `2.7.0`, SHA256 for scanner executable, selected ecosystem DB archive, report and lockfile;
- ecosystem/lockfile limited to `PyPI/uv.lock` or `npm/package-lock.json`, `scan_offline=true`, recorded scan exit code, UTC DB snapshot timestamp;
- valid bounded JSON, duplicate-key refusal, matching report/lockfile hashes, lockfile-type source and package ecosystem checks.

Every valid report returns `INCONCLUSIVE` (exit 2): a *self-reported* scanner hash, DB hash, timestamp and scan exit code are **not independently attested**, and an empty vulnerabilities array says nothing about the completeness/freshness of a database or extractor. The sanitized machine-readable result contains only counts of observed affected package entries / vulnerability records / CVE-GHSA aliases, not raw paths, package names, lockfile contents, text, CVSS claims, fixes or tokens. Invalid input also exits 2 with a **fixed error code**.

The flag `--execute` means **read the three supplied evidence files**, not run any binary or a scanner. Without it, CLI returns `NOT_EXECUTED`. This distinction prevents accidental project scans.

### Local verification (no network)

```bash
python3 -m unittest discover -s tests -p 'test_h22_osv_evidence.py' -v
python3 scripts/review_osv_offline_scan.py
# Prints NOT_EXECUTED; no files read.
```

Tests use only fictional dependencies and vulnerability IDs. Negatives cover hash mismatch, unsupported ecosystem, online mode, unknown scanner version, malformed and duplicate-key JSON, missing evidence, leaking a hypothetical private package name/path, output sanitization and the prohibition against a false PASS.

### Future opt-in external scan, NOT performed

A standalone, non-production Linux sandbox would need vetted exact v2.7.0 binary + independent SHA256/signatures, OS network isolation, **pre-downloaded and hash-pinned** PyPI or npm offline database, a synthetic lockfile, locked-down user/storage, no secret mounts, and explicit approval for the external binary:

```bash
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/absolute/path/to/prepared-readonly-db
osv-scanner scan source --offline -L /absolute/path/to/synthetic/uv.lock --format json > /isolated-private/report.json
# Never use --download-offline-databases in the scan sandbox.
```

Capture the real exit code and external evidence manifest **outside this verifier**. Compare findings with Trivy/CodeQL and existing dependency-audit signals. Audit severity, false negatives and fixed versions via authoritative advisories manually; do not equate absence of reported vulnerabilities with safety. Do not publish raw vulnerability output (source path may identify private files).

## Decision

**Pilot code only; OSV binary/DB and real private project access NOT_RUN.** No new CI job or scanner runtime dependency is justified until there is a confirmed incremental detection gap and authorized, pinned isolated scan. #189 remains OPEN; no implementation of a production hard-stop or release GO.


## 19 October 2026 - pinned binary / DB preflight (no scanner run)

The independently consulted official [v2.7.0 release metadata](https://github.com/google/osv-scanner/releases/tag/v2.7.0) lists the Linux amd64 executable asset `osv-scanner_linux_amd64` (57,725,088 bytes) with SHA256
`160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b`.
Release metadata also exposes `multiple.intoto.jsonl`, but its attestation signature and subject identity have **not** been verified: `PUBLISHER_PROVENANCE_NOT_VERIFIED`. A GitHub-supplied digest is useful for pinning; it is not independent publisher provenance. Do not claim successful supply-chain verification.

`scripts/preflight_osv_offline_scan.py` is a *separate* opt-in, stdlib-only, **read-only prerequisite check**, never an OSV runner. It:

1. Checks the explicit Linux amd64 executable's exact length, ELF architecture, and digest against pinned release metadata. Does **not** execute this binary.
2. Reads only the explicitly named `uv.lock` or `package-lock.json`; validates TOML/JSON and counts entries independently of OSV, without claiming complete scanner extraction.
3. Checks the `<db-root>/osv-scalibr/PyPI/all.zip` or `.../npm/all.zip` local ZIP, bounds entry sizes and aggregate expanded size, forbids traversal/encryption, parses **one** JSON advisory sample, and computes an archive digest. This does **not** validate all advisory records, database coverage, provenance or freshness.
4. Emits only sanitized counts/digests and fixed-status fields. A successfully prepared input set still returns `INCONCLUSIVE` (exit 2, `pilot_inputs_ready=true`) and explicitly records `scanner_executed=false`, `db_freshness_verified=false`, `db_completeness_verified=false`, `offline_network_boundary_verified=false` and `resident_agent_allowed=false`. Invalid/missing data also return `INCONCLUSIVE` with `pilot_inputs_ready=false`.

Without `--check`, the preflight prints `NOT_EXECUTED` without opening any files. Test without network or dependency installs:

```bash
python3 -m unittest discover -s tests -p 'test_h22_osv_preflight.py' -v
python3 -m unittest discover -s tests -p 'test_h22_osv_evidence.py' -v
python3 scripts/preflight_osv_offline_scan.py
```

**Future authorized pilot only, not executed in this change.** Preparation and scan must remain separate. On a dedicated non-production machine obtain exact v2.7.0 asset and independent verification material through a reviewed process, then fetch official PyPI/npm `all.zip` archives into private storage, record source URLs, acquisition UTC time, archive hashes and available publisher attestations. An acquisition timestamp alone does not prove DB snapshot time. No networked download is attempted by the preflight:

```bash
python3 scripts/preflight_osv_offline_scan.py --check \
  --binary /private/prepared/osv-scanner_linux_amd64 \
  --db-root /private/prepared/db \
  --lockfile /private/public-fixtures/uv.lock
# Exit 2 with sanitized INCONCLUSIVE, including readiness of the inputs only.
```

In a **separate** bounded and independently isolated scan stage, mount the prepared executable, DB and selected lockfile read-only, mount only a private writable report directory, and require an OS-enforced `--network none` / equivalent boundary, non-root UID, dropped capabilities, no Docker socket/secrets, read-only root FS, explicit CPU/RAM/PID limits and timeout. Set `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` to the *mounted* parent of `osv-scalibr/PyPI` and `osv-scalibr/npm`; use `osv-scanner scan source --offline --lockfile /input/uv.lock --format=json`. Do not use `--offline-vulnerabilities` as a network-isolation guarantee or `--download-offline-databases` during the scan. Record exit code 0/1, exact binary/DB/lockfile hashes, actual report, runtime, extraction warnings and egress-denial test in **private** evidence storage, then review with the existing sanitized reviewer. The reviewer deliberately remains `INCONCLUSIVE` until separate independently checked execution, DB and extraction evidence exists. No live machine, VPS, CI job or dependencies are modified here.

### Verified public repository scope (GitHub tree / workflow inspection)

| Project | Files present | Existing SCA evidence | Provisional decision |
| --- | --- | --- | --- |
| Hermes (main `ca540d07a2c2bf3fe1dc8f035c914250f23349d6`) | `control_center/frontend/package-lock.json`; no top-level `uv.lock` | #185 handles pinned OCI/Syft/Trivy; lockfile scanning would be separate frontend coverage | `DEFER` targeted OSV until measured gap |
| Your Fitness Coach (master tree `42a75a5f1fbea025204c5d1e1a928bfd6581b1a1`) | `uv.lock`, `frontend/package-lock.json`, `frontend/scheduled-report/package-lock.json` | `.github/workflows/security-audit.yml`: scheduled CodeQL, dependency-audit, Trivy FS | `KEEP_TRIVY_DEPENDENCY_AUDIT` unless OSV gives distinct confirmed findings |
| Second Brain (main tree `e70cc82b4aa592909a74dbf66da3c88fed5ec90a`) | `uv.lock`, `web/package-lock.json` | Inspected `.github/workflows/ci.yml`: `uv sync --locked`, Ruff, mypy, pytest and frontend checks; no independent CVE job found | `DEFER_OWNER_GO` for real scan; public tree review is not access to vault |

None of these conclusions claims that package versions were scanned or that any CVE is absent. The Second Brain private vault and production runtime were never accessed. For YFC, a side-by-side package/version/advisory comparison with the actual Trivy/dependency-audit artifacts remains **NOT_RUN**. No new security CI gate is justified without measured incremental value.

**Environment limitations observed 2026-10-19:** isolated ChatGPT container has no scanner binary/DB and cannot resolve public download hosts; no local Docker or Podman executable is present. All linked Remote Desktop Commander devices were offline. Therefore `scanner_execution=NOT_RUN`, `DB_available=NOT_VERIFIED`, `DB_freshness=NOT_VERIFIED`, `actual_findings=NOT_VERIFIED`, and `CI_performance=NOT_MEASURED`. OSV v2.7.0 offline behaviour is described in the [upstream guide](https://github.com/google/osv-scanner/blob/v2.7.0/docs/offline-mode.md); those descriptions are not proof that a local scan took place.

**Decision:** `KEEP_OFFLINE` preparation, `REJECT_BROAD_ADOPTION` for now. Issue #189 remains open pending real isolated scanner/DB execution, effectiveness comparison, and the distinct Second Brain owner gate. The new preflight is *not* a complete implementation of #189.
 

## Реальный изолированный пилот OSV v2.7.0 19 октября 2026 года

**Первое воспроизводимое экспериментальное выполнение (синтетические публичные зависимости):** [GitHub Actions #39291775096](https://github.com/MikeMoore1337/hermes/actions/runs/39291775096), шаг `H-22 OSV ephemeral synthetic pilot`. Статус workflow **FAILURE**, так как npm-проверка не подтвердила известный advisory, а не потому, что реальный PyPI scan не запускался. Одноразовые скрипт и workflow не являются продукционным CI-контрактом и должны быть удалены перед merge подготовительного PR.

### Доказательства реального выполнения

- OSV-Scanner `v2.7.0`, linux/amd64, 57 725 088 байт, SHA256 `160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b`; проверено совпадение с официальным GitHub Release. `PUBLISHER_PROVENANCE_NOT_VERIFIED` - независимая проверка attestation и подписанта не выполнялась.
- PyPI `all.zip`: SHA256 `c311268f05d4446c0a6bfab7f2b46f3ec538b04431a5fe4188afa8e4dd395268`, 36 455 718 байт, HTTP Last-Modified `2026-10-19 17:03:25 UTC`. npm `all.zip`: SHA256 `d2f03c6f71d6340ee313a86314186bda66de91a85bf2c8c1744d80a2361cdd55`, 218 582 033 байта, HTTP Last-Modified `2026-10-19 16:48:24 UTC`. Даты изменения объектов и локальные SHA не доказывают независимо полноту, подлинность или точный DB snapshot.
- Docker image `ubuntu:24.04` идентифицирован на runner как `sha256:6277ab668b2ad3c3ab851d370faa1690d324b30db29d342527f61fed28f20f36`; контейнер без сети `--network=none` и проверкой `lo_only`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, непривилегированный UID, CPU/RAM/PID и таймауты ограничены. Исходный ZIP расположен в read-only mount; OSV v2 требует отдельный **одноразовый записываемый кеш** для локального индексирования. Продакшен и приватные проекты не подключались.
- **Важная обнаруженная несовместимость документации:** при явном запуске OSV v2.7.0 используется `scan source --offline` (а не `--offline scan`), а используемый компонент `osv-scalibr` обращается к каталогу `<db-root>/osv-scalibr/<ecosystem>/all.zip`. Первые эксперименты с `osv-scanner` в имени папки возвращали ложную недоступность PyPI DB; ошибка зафиксирована и исправлена в предохранительном валидаторе и тестах.
- Временные публичные файлы содержали только `requests` и `lodash`, без credentials и исходников Hermes/YFC/Second Brain.

### Синтетическая проверка CVE/GHSA

| Экосистема / установленная версия | Ожидаемая уязвимость | Результат реального OSV |
| --- | --- | --- |
| PyPI `requests==2.19.0` | `CVE-2018-18074` / `GHSA-x84v-xcm2-53pg` | **PASS:** advisory найден; 10 записей vulnerability, выход 1, около 2.40 с |
| PyPI `requests==2.32.5` | та же `CVE-2018-18074` | **PASS:** конкретный advisory не найден; 2 другие записи, выход 1, около 2.37 с |
| npm `lodash@4.17.15` | `CVE-2020-8203` / `GHSA-p6mc-m468-83gw` | **INCONCLUSIVE:** идентификатор пакета/версия извлечены, но 0 findings, выход 0, около 0.21 с |
| npm `lodash@4.17.23` | та же `CVE-2020-8203` | Совместимо с исправленной версией, но **не подтверждает положительное npm-обнаружение**, 0 findings, около 0.20 с |

Эталонные advisories: [requests](https://github.com/advisories/GHSA-x84v-xcm2-53pg), [lodash](https://github.com/advisories/GHSA-p6mc-m468-83gw). **npm результат не считать `NOT_AFFECTED` или `PASS`**, пока не установлено, содержится ли соответствующий advisory в локальном ZIP и почему matcher вернул 0. Вывод `FALSE_NEGATIVE` также преждевременен без подтверждённого DB coverage. Для requests нельзя называть версию `2.32.5` полностью безопасной: сканер вернул две другие записи.

Фактически выполнен **настоящий офлайн OSV scan публичных синтетических lockfiles**. Реальные файлы проекта и прямое сравнение OSV с Trivy на одинаковых версиях проектов не сканировались. Полное покрытие (direct/transitive/dev/optional) и нагрузка на CI для реальных проектов **NOT_VERIFIED**.

### Сравнительная основа Your Fitness Coach

[Security Audit YFC #39225025515](https://github.com/MikeMoore1337/your-fitness-coach/actions/runs/39225025515), commit `bc48d09c3415c4b146a0400efc18cb9031413d18`, 19.10.2026, `SUCCESS`. `uv audit` проверил 86 пакетов и не обнаружил известных уязвимостей; `npm audit --omit=dev --audit-level=high` - 0; Trivy 0.73.0 по `uv.lock` и двум npm lockfiles показал 0 находок в политике `HIGH/CRITICAL`, `ignore-unfixed=true`. CodeQL Python и JavaScript/TypeScript также прошёл. **Это не доказательство отсутствия всех уязвимостей, а профиль существующего контроля**. Без OSV-сканирования того же commit с сопоставимыми категориями реальная incremental value **NOT_MEASURED**.

### Архитектурный вердикт

- Hermes: `DEFER` - образ/SBOM/Syft/Trivy остаются задачей #185/#199; npm Control Center можно проверять точечно после устранения диагностического разрыва.
- YFC: `KEEP_TRIVY_DEPENDENCY_AUDIT` - не вводить вторую широкую блокировку PR.
- Second Brain: `DEFER_OWNER_GO` - возможен отдельный opt-in public-repo-only scan, без `second-brain-vault`.
- Общий: `KEEP_OFFLINE / REJECT_BROAD_ADOPTION` на текущих доказательствах.

**Issue #189 пока `PARTIAL`** - самостоятельный scanner execution и подтверждение PyPI-доступности выполнены; npm sensitivity / advisory coverage, независимая DB provenance, полное сравнение с существующими проверками и real-lockfile pilot остаются недоказанными. Не менять зависимости, runtime, production VPS и Cloudflare ради OSV.

### Дополнительная проверка полноты advisory ZIP

[Диагностический эксперимент #39292529281](https://github.com/MikeMoore1337/hermes/actions/runs/39292529281) просмотрел **имена записей** реальных архивов, без публикации содержимого advisory и raw scanner reports:

- PyPI `all.zip`: 26 387 записей, в ZIP присутствует файл с `GHSA-x84v-xcm2-53pg`; синтетический `requests==2.19.0` соответствует advisory (реальное обнаружение PASS).
- npm `all.zip`: 230 502 записи, в ZIP **присутствует файл с `GHSA-p6mc-m468-83gw`**; при этом `lodash@4.17.15` распознан как npm-зависимость, но scanner v2.7.0 в строго офлайн-режиме вернул **0 findings и exit 0**. Дополнительных предупреждений в stderr нет. Эталонный GitHub Advisory подтверждает, что lodash `4.17.15` относится к затронутому диапазону. Это **подозрение на пропуск обнаружения при наличии advisory в snapshot**, не `NOT_AFFECTED`. Фактическое чтение и сопоставление содержимого конкретной записи ZIP не исследовано, поэтому окончательный корень проблемы `INCONCLUSIVE`.
- Изолированный Docker продолжал использовать `--network=none`, непривилегированный UID, одноразовый записываемый кеш и read-only исходные ZIP. Оба Python-примера дали прежний ожидаемый результат, время около 1.38-1.39 секунды каждый. Реальные проекты, production и секреты не участвовали.

**Важное ограничение:** наличие advisory-файла в архиве не доказывает, что все affected/version/events корректно прочитаны, обработаны и сопоставлены. До диагностики этого разрыва OSV нельзя считать достоверным дополнительным контролем для npm в Hermes/YFC/Second Brain. Широкую CI-интеграцию не включать.


## 19 октября 2026 - итоговый публичный пилот (заменяет прежний предварительный INCONCLUSIVE по npm)

**Актуальные подтверждённые результаты:** [изолированный npm-контроль #39299602120](https://github.com/MikeMoore1337/hermes/actions/runs/39299602120) - SUCCESS; [точечное сканирование реальных публичных lockfiles #39299982094](https://github.com/MikeMoore1337/hermes/actions/runs/39299982094) - SUCCESS. Предыдущие выводы выше о предполагаемом дефекте npm и отсутствии реальных project scans относились к *более раннему этапу*. Не использовать их как текущую оценку.

### Исправление ложной тревоги на синтетической npm-фикстуре

- В исходном тесте `lodash@4.17.15` был записан в минимальный вручную собранный `package-lock.json`, которого хватало для извлечения имени/версии, но **недостаточно для надёжного подтверждения CVE**.
- В повторном запуске стандартный npm lockfile v3 был получен через `npm install --package-lock-only --ignore-scripts --no-audit --no-fund --save-exact` **в подготовительной среде, а не внутри офлайн-контейнера**. `OSV-Scanner v2.7.0` с той же официальной локальной npm DB обнаружил `GHSA-p6mc-m468-83gw` / `CVE-2020-8203` в `lodash@4.17.15` (6 записей), но не в `lodash@4.17.23` (2 *другие* записи). [GHSA: High 7.4, исправлено в 4.17.19](https://github.com/advisories/GHSA-p6mc-m468-83gw).
- **Вердикт:** подтверждённая способность OSV обнаруживать npm advisory при настоящем lockfile; вывод о *дефекте сканера* снят. Конкретное отсутствовавшее поле старой фикстуры НЕ установлено - не выдавать гипотезу за найденный корень.
- Правило на будущее: использовать реальные manager-generated lockfiles либо отдельно подтверждать полноту синтетического формата; нулевой результат одной сокращённой фикстуры не означает `NOT_AFFECTED`.

### Изолированное сканирование публичных проектов

Публичные lockfiles были загружены в подготовительную среду по **точным commit SHA**, а затем проверены настоящим OSV внутри Docker (`--network=none`, подтверждён только loopback, непривилегированный UID, read-only rootfs, no privileges, лимиты CPU/RAM/PID). **Никаких сетевых запросов внутри сканера, private vault, токенов, зависимостей для установки, production или новых полномочий.** Всё временное экспериментальное обеспечение необходимо удалить до merge этого отчёта.

| Проект и закреплённый коммит | Lockfile | Зависимости в OSV-отчёте | Совпадения OSV |
| --- | --- | ---: | --- |
| Hermes `79104b83136e03f33fec0a23494cd042848d3d0a` | `control_center/frontend/package-lock.json` | 120 | **5** записей для `vite@7.1.11` |
| YFC `bc48d09c3415c4b146a0400efc18cb9031413d18` | `uv.lock` | 109 | **3** записи для `aiohttp@3.14.3` |
| YFC, тот же SHA | `frontend/package-lock.json` | 344 | 0 |
| YFC, тот же SHA | `frontend/scheduled-report/package-lock.json` | 79 | 0 |

SHA256 входных lockfiles в указанном порядке:
`80ed28558da4d8c5eb9a13cae8a0a2c8db3f322579021394a37712064d689a70`,
`d0925901c471a54b1249eb5516e8795ad48134c78866687b0d5f67b4965ea392`,
`efa223759b3e0e276c0950952636a6b7b484ed0abf4174dd1e6e3a4070c575c9`,
`b75fc1ae560c952f24c6a7e5c8e576a82d4ccd06`.

Файлы DB текущего эксперимента: npm 218 582 931 байт, SHA256
`88e0d0fc50cb30a4a4e360069d6d6bff853449bac87ec31b1910c6dcac7e6faa`;
PyPI 36 468 536 байт, SHA256
`3526b5868fdcb3c398595948e8a2941794e27ae7f1fe146c1f8774c48e8a3efe`.
Полнота и независимая аутентичность DB, подпись поставщика бинарника и точная дата состава DB **NOT_VERIFIED**. Ноль находок по отдельному lockfile - не доказательство безопасности всех версий/режимов работы.

#### Hermes: `vite@7.1.11` (devDependency)

| CVE / GHSA | Важность согласно GitHub Advisory | Исправление в ветке 7.x |
| --- | --- | --- |
| `CVE-2026-39365` / [`GHSA-4w7w-66w2-5vf9`](https://github.com/advisories/GHSA-4w7w-66w2-5vf9) | Moderate (CVSS 6.3), чтение исходных `.map` | 7.3.2 |
| `CVE-2026-53571` / [`GHSA-fx2h-pf6j-xcff`](https://github.com/advisories/GHSA-fx2h-pf6j-xcff) | High (8.2), Windows/NTFS dev-server `fs.deny` | 7.3.5 |
| `CVE-2026-39363` / [`GHSA-p9ff-h696-f583`](https://github.com/advisories/GHSA-p9ff-h696-f583) | High (8.2), чтение файлов через WebSocket dev-server | 7.3.2 |
| `CVE-2026-39364` / [`GHSA-v2wj-q39q-566r`](https://github.com/advisories/GHSA-v2wj-q39q-566r) | High (8.2), обход `fs.deny` через query | 7.3.2 |
| `CVE-2026-53632` / [`GHSA-v6wh-96g9-6wx3`](https://github.com/advisories/GHSA-v6wh-96g9-6wx3) | Moderate, Windows UNC/NTLM в `launch-editor` | 7.3.5 |

Все пять относятся преимущественно к использованию **Vite dev-server**. `control_center/frontend/package.json` объявляет `vite: 7.1.11` в `devDependencies`, скрипт `dev` запускает локальный `vite --host 127.0.0.1`. **Это не свидетельство эксплуатации production Control Center**, собранного в статические файлы. Если разработчик или CI включает сетевой dev-server/запускает Windows, сценарии воздействия зависят от конфигурации. Разумный *отдельный* шаг - целевое обновление Vite до совместимой безопасной версии **не ниже 7.3.5** с регрессионными тестами фронтенда. Это **не выполнено** в #189, потому что Issue запрещает автообновление.

#### Your Fitness Coach: `aiohttp==3.14.3` (через optional `bot`)

| CVE / GHSA | Важность | Исправление |
| --- | --- | --- |
| [`GHSA-2g87-pp6c-29x5`](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-2g87-pp6c-29x5) | Moderate, исчерпание памяти/CPU; CVE не присвоен | 3.14.4 |
| `CVE-2026-111063` / [`GHSA-494j-54xm-rwp3`](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-494j-54xm-rwp3) | Low, атрибут `Secure` у shared cookie | 3.14.4 |
| `CVE-2026-111064` / [`GHSA-5wr8-gcqf-gqf3`](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5wr8-gcqf-gqf3) | Low, отсутствие начального timeout заголовков HTTP-сервера | 3.14.4 по выпуску исправлений октября 2026; прямой текст GHSA при проверке недоступен |

По публичным `pyproject.toml` и `uv.lock` на этом SHA: `[project.optional-dependencies].bot` включает `aiogram` и `aiohttp-socks`, **оба** зависят от `aiohttp`; это зависимость optional bot-группы, а не обязательной пустой `[project].dependencies`. Проверять фактическую установленную конфигурацию bot отдельно, не считать автоматически уязвимым production.

**Сравнение с существующими инструментами YFC по тому же commit:** [Security Audit #39225025515](https://github.com/MikeMoore1337/your-fitness-coach/actions/runs/39225025515) `uv audit --locked --no-group dev --no-group scheduled-report` проверял 86 пакетов, `npm audit --omit=dev` - production-only, Trivy 0.73.0 - `HIGH/CRITICAL`, `ignore-unfixed=true`, без dev-зависимостей по логам; всё SUCCESS/0 находок. OSV анализировал **все записи** четырёх lockfiles (`--all-packages`), включая optional и dev. Это **показанный разрыв в областях сканирования**, но ещё не доказательство, что инструменты с **одинаковым включением групп и severity** дали бы разные ответы. Не вводить второй блокирующий CI без полного сопоставления областей.

### Решение по #189 после реального публичного пилота

1. **Hermes:** подтверждены пять advisory для сборочного/dev-инструмента Vite в pinned версии; зафиксировать их и планировать совместимый отдельный апгрейд после оценки dev-server exposure, без автоматических правок по #189.
2. **YFC:** подтверждены три advisory для optional bot-зависимости `aiohttp` в конкретном историческом SHA; проверить использование в активном bot-runtime и целесообразность целевого обновления до 3.14.4+ отдельным процессом. Сохранить действующие `uv audit`, npm audit и Trivy, не заменять их OSV.
3. **Second Brain:** реальная проверка не проводилась из-за отдельного owner gate. Ни приватный `second-brain-vault`, ни production не читались.
4. **Охват OSV:** настоящее сканирование и обнаружение в **обеих экосистемах доказаны**, но широкую обязательную интеграцию `REJECT_BROAD_ADOPTION` пока оставить: нужны решения о scope/dev/optional и независимая проверка DB/binary provenance. Сами эти шаги не блокируют другую разработку Hermes.

**Статус #189: `PARTIAL`** по требованию полного охвата Second Brain и уточнению отличий существующих аудиторов. Этот отчёт исправляет ошибочные прежние предположения, но не даёт runtime GO, не закрывает #33 и не обновляет зависимости автоматически.
