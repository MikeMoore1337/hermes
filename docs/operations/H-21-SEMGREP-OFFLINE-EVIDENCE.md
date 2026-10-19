# H-21 #188 - Semgrep CE: verified synthetic-only sandbox experiment

Дата: 2026-10-16. Ветвь: `feat/h21-semgrep-synthetic-rules-20261016`. **Нет live/production сканирования.**

## Измеренное доказательство

- В Docker Desktop на отдельном Windows 11 хосте присутствовал локальный `linux/amd64` образ `semgrep/semgrep@sha256:c47e426f7f0cfa19af6d7877560d0a7135f683b8090ad0efc97c4ec7810dc435`. `semgrep --version` вернул `1.181.0`. Не проверены независимая издательская подпись, SLSA provenance и полный upstream source-to-image mapping.
- Контейнер запускался со всеми ограничениями: `--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, лимитами CPU/RAM/PID, отдельным временным `/tmp`, без сетевых провайдеров и без mounts приватных файлов. В `/work` переданы **только синтетические** YAML/Python-фикстуры в режиме read-only.
- После исправления YAML quoting и ограничения `metavariable-regex` реальная команда `semgrep test /work` вернула **5/5 PASS**, exit 0. Это проверяет заявленные match/no-match внутри фикстур, а **не** подлинную защиту Hermes.
- Правила: `subprocess.*(shell=True)`, `os.system`, `requests/httpx verify=False`, `jwt.decode(..., verify_signature=False)`, прямое логирование секретных значений из `os.environ`. Подробности и команда запуска: [локальная инструкция](../../evals/semgrep_offline/README.md).
- На момент PR #204 сканировались только синтетические примеры. YFC и Second Brain **не сканировались**. Сравнение с CodeQL/Trivy на реальных задачах, инвентарь false positives/false negatives, решение о CI-интеграции - **NO_DATA**. Отдельный последующий Hermes code scan описан ниже.

## Решение

`OFFLINE_PILOT_PASS / PROJECT_ADOPTION_NOT_APPROVED`. Вносить Semgrep в CI сразу всех проектов **нецелесообразно**: у YFC уже существуют CodeQL и Trivy; у Second Brain нельзя вовлекать приватный vault; Hermes не должен расширять полномочия резидентного Agent. #188 остаётся открытой до независимой проверки пользования сканером, лицензии/поставки, безопасности правил и отдельного решения по целевому проекту. `resident_agent_allowed=false`.

## Дополнение 16.10.2026 — локальный scan выбранного кода Hermes

После завершения синтетического этапа в том же отдельном Windows Docker
Desktop проведён **отдельный read-only scan** именно кодовых директорий
локального репозитория Hermes: `scripts/` и `qa_advisor/`. Версия
сканера и Linux/AMD64 image digest остались прежними:
`semgrep/semgrep@sha256:c47e426f7f0cfa19af6d7877560d0a7135f683b8090ad0efc97c4ec7810dc435`.
Второй запуск выполнен после расширения синтетического каталога до
**всех пяти правил** (пять правил отдельно подтвердили `semgrep test`
**5/5 PASS**). Дерево сканируемого кода соответствует содержимому
в ветке `feat/h21-semgrep-synthetic-rules-20261016` на `8126018e...`;
исходники между base `25eb06b...` и этим commit не менялись.

### Зафиксированный метод

`semgrep scan --quiet --json --config /rules /code/scripts /code/qa_advisor`
выполнялся из Docker с `--pull=never --network none --read-only`,
непривилегированным UID 65534, `--cap-drop ALL`,
`--security-opt no-new-privileges`, лимитами CPU 1, памяти 1024 MiB
и PID 80, а также `SEMGREP_SEND_METRICS=off`. Три mount-point были
**только для чтения**: правила, `scripts/` и `qa_advisor/`.
Никакие папки `second-brain-vault`, production конфигурации,
ключи или Docker socket внутрь контейнера не передавались.
YFC, Second Brain, VPS и постоянный Hermes Agent не сканировались.

| Показатель | Фактическое наблюдение |
| --- | --- |
| Количество обработанных файлов в JSON `paths.scanned` | **42** |
| Совпадения из JSON `results` | **0** |
| Ошибки из JSON `errors` | **0** |
| Пропущенные правила из JSON `skipped_rules` | **0** |
| Exit code | **0** |
| SHA256 локального JSON отчёта | `f549211ce51c638ef82d6e280dfc0306fcd2b4c0f35d9323070c08ca93ac01cd` |

Raw JSON сохранён **только в локальной `.artifacts`** директории:
публикация исходных строк, машинного отчёта или внутренних путей в
GitHub не выполнялась. Этот fingerprint позволяет соотнести отчёт
с результатами данного прохода, но не является внешней attestation.

**Вывод: NO_FINDINGS_FOR_SELECTED_PATTERNS_ONLY.** Нулевое количество
совпадений **не означает**, что 42 файла не содержат уязвимостей.
Пилотные правила не покрывают SSRF, OAuth ошибки, prompt injection,
ошибки прав реальных tools, зависимости, динамическую диспетчеризацию,
private проектные данные и большинство security-риск-сценариев.
Безопасность продакшен-системы ими не доказана. Для YFC уже работают
CodeQL/Trivy, и дополнительная польза Semgrep по-прежнему **NO_DATA**.

#188 оставлена открытой для измерения false positives и incremental
value, отдельного одобрения целевых репозиториев и проверки scanner
provenance. **Нет автоматического CI-инсталлятора, постоянного
контейнера, новых разрешений, backend/provider calls и production deploy.**
#33 остаётся `resident_agent_allowed=false`.


## 19.10.2026 - ограниченный независимый review и решение о границах внедрения

Это **обзор зафиксированных результатов и исходников**, а НЕ повторный запуск
Semgrep. Проверка Docker на отдельном Windows-хосте в этой сессии недоступна:
устройства Desktop Commander offline, Docker/Semgrep нет в доступном
изолированном контейнере. Ни один новый production scanner scan не проводился.

**Точные исследованные версии веток:** Hermes main
`49e9aaf73aa45e0c5b136cd71c651c808dd04834`;
YFC main `42a75a5f1fbea025204c5d1e1a928bfd6581b1a1`;
Second Brain main `e70cc82b4aa592909a74dbf66da3c88fed5ec90a`.
Исходники были прочитаны через GitHub connector. Это выборочная
проверка, не repository-wide code audit.

### Реально воспроизведённые и непроверенные измерения

| Показатель | Результат | Достоверность |
| --- | --- | --- |
| Прежний pinned Semgrep CE Docker `semgrep test` | 5/5 suites PASS | Ранее зафиксированный live запуск 16.10, не повторён |
| Разметка текущих пяти fixture-файлов | 12 `ruleid`, 8 `ok` | Подсчёт в committed файлах на main, не отдельный re-run |
| TP/FP/FN/TN для исходных 20 примеров | **12/0/0/8 предполагаются только при полном совпадении** прежнего PASS и текущей разметки | Вывод из успешного Semgrep rule-test, без сохранённого per-case report |
| Precision / recall на этих 20 примерах | Условно 100%/100% при указанном предположении | **НЕ** production precision/recall, нет независимого отчёта по каждому примеру |
| Scan исходников Hermes | 42 Python-файла, 0 matches/errors/skips, exit 0 | Ранее зафиксированный read-only scan 16.10 |
| Повторный mutation scan по alias/kwargs/SSRF/HMAC | **NOT_RUN** | Нет исполняемого scanner |
| Ручной triage находок Hermes | 0 наблюдавшихся findings | Нельзя установить false negatives по нулю |
| Peak RAM, CPU, wall time, CI delta, report size | **NOT_MEASURED** | Нет оснований приводить оценки как измерения |
| Совпадения с CodeQL на одинаковом commit/scope | **NOT_VERIFIED** | Нет сопоставимого сырого CodeQL finding inventory |
| Publisher signature / OCI SLSA provenance | **NOT_VERIFIED** | Зафиксирован digest, нет независимой аттестации |

### Оценка качества пяти существующих правил

| Rule | Риск / boundary | Вероятные FP | Явные ограничения / FN | Блокировать CI сейчас? |
| --- | --- | --- | --- | --- |
| `shell-true` | Shell injection, выполнение процессов | Константный shell-командный текст | Wrapper, динамический `**kwargs`, alias с неопределённым связыванием | Нет |
| `shell-os-system` | Прямое shell-выполнение вне разрешённой границы | Константный локальный административный вызов | Alias, shell через другие библиотеки | Нет |
| `tls-disable` | MITM, доверие к HTTP/TLS | Заведомо локальная лабораторная среда | `requests.Session.verify=False`, `httpx.AsyncClient(verify=False)`, `ssl._create_unverified_context`, kwargs/alias | Нет |
| `jwt-no-verify` | Доверие к неподписанным JWT claims | Диагностическое чтение неподтверждённого токена после отказа auth | Словарь options через переменную, чужие JWT wrappers; контекст допуска установить нельзя | Нет |
| `token-log` | Секреты в stdout/logging | Синтетические имена типа `FAKE_SECRET` | f-strings, промежуточные переменные, `os.getenv`, другие logger methods, межпроцедурная передача | Нет |

Здесь FP/FN - **теоретически возможные сценарии**, а не измеренные
срабатывания в текущем прогоне. Semgrep CE поддерживает семантические
сопоставления и локальное распространение констант, поэтому нельзя
автоматически объявлять каждый alias или `kwargs` доказанным обходом.
Каждый вариант должен пройти через точную версию 1.181.0, затем
проверяться по фактическому scan JSON. Межфайловый taint нельзя
приписывать пяти search-pattern правилам.

### Сопоставление с уже имеющимися инструментами

| Категория | Hermes 5 rules | CodeQL Python security-extended в YFC | Вывод |
| --- | --- | --- | --- |
| Shell/command injection | Только literal shell=True и os.system | Имеет запросы для unsafe shell commands / command injection | Incremental finding NOT_VERIFIED |
| HTTP/TLS | Четыре literal-паттерна verify=False | Имеет request without certificate validation | Incremental finding NOT_VERIFIED |
| SSRF | Нет правила | Имеет partial SSRF query | Semgrep не даёт добавочной проверки |
| JWT без verify_signature | Узкий синтаксис | Проверять на точном источнике данных; общий CodeQL запрос не доказывает этот бизнес-контекст | Incremental finding NOT_VERIFIED |
| Секреты в логах | Прямой os.environ в 3 sinks | Имеет clear-text logging sensitive information | Incremental finding NOT_VERIFIED |
| Webhook/HMAC/nonce | Нет правила | Нет доказанной полноты проверки конкретных entrypoints | Не заменяет security/unit tests |
| Unsafe file operations | Нет правила | Имеет, в частности, произвольную запись при распаковке tar | Incremental finding NOT_VERIFIED |
| Dependency CVE / misconfig | Не область этих правил | Trivy и dependency audit отдельно | **Не** SAST gap |

Источник характеристик CodeQL:
[официальный каталог Python-запросов](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-queries/python-built-in-queries).
В текущем YFC `.github/workflows/security-audit.yml` CodeQL/Trivy
срабатывают по расписанию/ручному dispatch, **не непосредственно на
каждый pull_request**. Это gap в частоте проверки, но само по себе не
основание автоматически добавлять ещё один сканер. В выборочно
просмотренном `backend/fitminiapp_api/services/jwt.py` YFC
подпись проверяется через `jwt.decode(..., settings.secret_key,
algorithms=["HS256"])`; исследован только этот callsite,
полное покрытие auth не установлено.

В Second Brain актуальный `.github/workflows/ci.yml` использует
Ruff/mypy/pytest/frontend; отдельный универсальный SAST в этом
workflow отсутствует. Выборочный `src/second_brain/adapters/commands.py`
запускает `subprocess.run(list(argv), shell=False)`, а Safe Write в
`src/second_brain/application/goal_progress_safe_write.py` разделён
на reviewed draft / plan / apply. Простое правило `shell=True`
не доказывает добавочную ценность для такой архитектуры. Исходники
приватного `second-brain-vault` **не читались**.

### Проверка evidence reviewer

PR, подготовленный 19.10, усиливает _только_ чтение JSON evidence:
допускает известные scoped пути `/code/scripts/`,
`/code/qa_advisor/` или эквивалентные относительные пути;
отклоняет нормализованные дубли, path traversal, неразрешённые roots,
unknown rule ID, finding вне scanned inventory, отсутствующие координаты
и дубли findings. В выдаче дополнительно явно записано
`rule_execution_inventory_verified=false` и
`scan_exit_code_verified=false`: пустой JSON `results` сам по себе
**не доказывает**, что все правила выполнились, а JSON не подтверждает
exit code процесса. Synthetic unit tests используют только
фиктивные пути/токены и не исполняют scanner.

### Итоговые решения на имеющихся доказательствах

- **Hermes: KEEP_OFFLINE.** Сохранить пять локальных правил и
  реальный ранний pilot, улучшить проверку отчётов, **не вводить**
  постоянный Semgrep в PR CI до подтверждённого incremental signal
  и измерения стоимости.
- **YFC: KEEP_CODEQL_TRIVY.** Не трогать workflow; если нужно
  обязательное PR-gating, сначала рассмотреть изменение частоты
  существующих проверок, не предполагать, что Semgrep его заменяет.
- **Second Brain: DEFER_OWNER_GO.** Потенциально целевые Safe Write
  и path/auth правила, но никакого CI или PR в этом проекте
  без отдельного разрешения владельца.

Общая оценка: **REJECT_BROAD_ADOPTION**. Для пяти правил недостаточно
доказательств независимого повышения security-гарантий или разумной
стоимости постоянного CI. Это отрицательное решение **о расширении**
Semgrep, а не заключение о защищённости проектов.

Состояние #188 для полного первоначального перечня приёмки:
**PARTIAL** (нет нового исполняемого mutation scan, измеренных FP/FN
на более богатом корпусе, CodeQL same-scope compare и CI overhead).
Разумный управленческий итог - сохранить офлайн-пилот и не создавать
нужды в платном SaaS или ежедневной проверке ради самой проверки.
Никаких изменений production runtime, H-01 timers, permissions,
Cloudflare, YFC или Second Brain в рамках этого изменения.
