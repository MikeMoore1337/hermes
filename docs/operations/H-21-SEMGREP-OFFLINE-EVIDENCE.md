# H-21 #188 - Semgrep CE: verified synthetic-only sandbox experiment

Дата: 2026-10-16. Ветвь: `feat/h21-semgrep-synthetic-rules-20261016`. **Нет live/production сканирования.**

## Измеренное доказательство

- В Docker Desktop на отдельном Windows 11 хосте присутствовал локальный `linux/amd64` образ `semgrep/semgrep@sha256:c47e426f7f0cfa19af6d7877560d0a7135f683b8090ad0efc97c4ec7810dc435`. `semgrep --version` вернул `1.181.0`. Не проверены независимая издательская подпись, SLSA provenance и полный upstream source-to-image mapping.
- Контейнер запускался со всеми ограничениями: `--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, лимитами CPU/RAM/PID, отдельным временным `/tmp`, без сетевых провайдеров и без mounts приватных файлов. В `/work` переданы **только синтетические** YAML/Python-фикстуры в режиме read-only.
- После исправления YAML quoting и ограничения `metavariable-regex` реальная команда `semgrep test /work` вернула **5/5 PASS**, exit 0. Это проверяет заявленные match/no-match внутри фикстур, а **не** подлинную защиту Hermes.
- Правила: `subprocess.*(shell=True)`, `os.system`, `requests/httpx verify=False`, `jwt.decode(..., verify_signature=False)`, прямое логирование секретных значений из `os.environ`. Подробности и команда запуска: [локальная инструкция](../../evals/semgrep_offline/README.md).
- Других исходников и данных не читали: YFC и Second Brain **не сканировались**. Сравнение с CodeQL/Trivy на реальных задачах, инвентарь false positives/false negatives, решение о CI-интеграции - **NO_DATA**.

## Решение

`OFFLINE_PILOT_PASS / PROJECT_ADOPTION_NOT_APPROVED`. Вносить Semgrep в CI сразу всех проектов **нецелесообразно**: у YFC уже существуют CodeQL и Trivy; у Second Brain нельзя вовлекать приватный vault; Hermes не должен расширять полномочия резидентного Agent. #188 остаётся открытой до независимой проверки пользования сканером, лицензии/поставки, безопасности правил и отдельного решения по целевому проекту. `resident_agent_allowed=false`.
