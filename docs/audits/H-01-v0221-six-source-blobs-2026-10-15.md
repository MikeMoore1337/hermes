# H-01 #33 - выборочная побайтовая сверка исходников в опубликованном образе v0.22.1

**Дата:** 15.10.2026. **Среда:** отдельный Windows Docker Desktop `DESKTOP-U6JEQP9`, не production VPS. Образ: `nousresearch/hermes-agent@sha256:cd9cb455576d27c9b6311de1104494ad7e221b6e68dc77e9ac2a8af661a4dc21`. Источник ожидаемых Git blob SHA-1: официальный Git tree **точного** коммита `297552a9d646119871391d202509822cd86330df`, откуда сформирован release claim v0.22.1.

## Подтверждённые файлы

| Путь | Git blob SHA-1 | Проверка |
| --- | --- | --- |
| `agent/tool_guardrails.py` | `258ca3ab9293e81595fee82945bcfe22e65ae7aa` | MATCH |
| `agent/tool_executor.py` | `4bd1bab397e5bc1432ec4f5bdda6f18a9a15e850` | MATCH |
| `agent/auxiliary_fallback_recovery.py` | `d479845e534be583477fda405325c47a92834153` | MATCH |
| `agent/billing_usage.py` | `e3fc1ba7af077bd842ea81761d24ffbfc04b36d7` | MATCH |
| `hermes_cli/main.py` | `47aa9814a12e07e4a60b8958b0447ec4e7a72dd3` | MATCH |
| `providers/base.py` | `9183cf3074ef0425d5af5cecc29a8a938b4cada1` | MATCH |

Сравнение является **Git blob hashing** `SHA1("blob "+len+"\\0"+bytes)` и поэтому сверяет целые байты выбранного исходного файла, а не только имя, размер или embedded stamp. Проверка всех шести - `SAMPLED_GIT_BLOBS_MATCH_UNATTESTED`, `mismatched_paths=[]`, `sample_byte_parity_verified=true`. Код выхода `2` специально сохраняется: это выборка, не допуск runtime.

Команда: `py -3.14 -m scripts.verify_v0221_source_sample --execute` из корня репозитория. До `--execute` - `NOT_EXECUTED`. Внутри `docker image inspect` + `docker run` pinned digest, `--pull=never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges --cpus 0.25 --memory 256m --pids-limit 25`, без монтирований, модели, SSH, провайдеров или ключей.

Дополнительно в **этом же** v0.22.1 образе повторён локальный physical duplicate check: Python `importlib.metadata` показывает две записи `hermes-agent`; `samefile=true`, `unique_resolved=1`, `unique_inode=1`. Это один физический каталог dist-info, а не две отдельные установки в наблюдаемом контейнере.

Полный набор owner-репозитория по коммиту проверки прошёл в другом already-local Linux-контейнере (`mcr.microsoft.com/playwright:v1.62.1-noble`), `--network none`, repo readonly: **583/583 тестов, OK, 4.139 с**.

## Что остаётся неизвестным

Это **не** полная source-to-image parity, официальная подписанная build provenance/SLSA attestation, проверенная полная SBOM, анализ уязвимостей, доказанный bill hard limit или тест полезного вызова модели внутри нового образа. Выбранные шесть файлов никак не удостоверяют остальные файлы, собранные слои, build-time hooks и зависимости. В этом исследовании отсутствовали внешняя сеть контейнера, production VPS и модельные вызовы. `resident_agent_allowed=false` остаётся неизменным; H-01 #33 остаётся открытым, без включения Cloudflare proxy/agent.
