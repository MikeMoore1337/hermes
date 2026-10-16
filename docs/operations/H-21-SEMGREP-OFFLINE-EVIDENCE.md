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
