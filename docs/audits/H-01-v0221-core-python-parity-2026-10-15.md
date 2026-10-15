# H-01 #33 - проверка 1410 файлов Python в закреплённом v0.22.1

**Дата:** 15 октября 2026 года. **Среда:** отдельный Windows Docker Desktop `DESKTOP-U6JEQP9`, не production VPS. Источник: официальный публичный Git tree `NousResearch/hermes-agent@297552a9d646119871391d202509822cd86330df` (исходный коммит release claim v0.22.1). Образ: `nousresearch/hermes-agent@sha256:cd9cb455576d27c9b6311de1104494ad7e221b6e68dc77e9ac2a8af661a4dc21` (linux/amd64).

## Результат реального offline-сравнения

| Каталог | Обнаружено в upstream Git tree | Проверено в Docker image | Отсутствующих/лишних/отличающихся |
| --- | ---: | ---: | ---: |
| `agent/` | 362 | 362 | 0 / 0 / 0 |
| `gateway/` | 302 | 302 | 0 / 0 / 0 |
| `hermes_cli/` | 729 | 729 | 0 / 0 / 0 |
| `hermes_platform/` | 15 | 15 | 0 / 0 / 0 |
| `providers/` | 2 | 2 | 0 / 0 / 0 |
| **Всего** | **1410** | **1410** | **0 / 0 / 0** |

Все **1410 файлов** в фиксированной области имеют **точно те же Git blob SHA-1 и размеры**, что и соответствующие записи официального исходного дерева. Проверена не только сумма/имя пакета, а байты каждого файла через Git blob hashing `sha1(b"blob " + length + b"\\0" + content)`. Итог реального вызова: `CORE_PYTHON_BLOBS_MATCH_UNATTESTED`, `sampled_scope_matches=true`, код выхода **2**; `resident_agent_allowed=false`.

Это более широкая независимая байтовая сверка по сравнению с шестью ранее проверенными файлами [PR #121](https://github.com/MikeMoore1337/hermes/pull/121). Она не требует клон source репозитория или секретов внутри Docker. Манифест содержит `source_commit`, фиксированный набор каталогов и пути/размеры/Git blob hashes из **одного** upstream GitHub tree, сохранённый в `scripts/v0221_core_python_manifest.json` для воспроизводимости.

## Повторение

Только на отдельном Docker-хосте, где этот immutable digest **уже загружен и проверен**:

~~~sh
python3 -m scripts.verify_v0221_core_python
# {"status":"NOT_EXECUTED"}
python3 -m scripts.verify_v0221_core_python --execute
# CORE_PYTHON_BLOBS_MATCH_UNATTESTED, exit 2 / UNKNOWN, exit 2
~~~

При `--execute`: только `docker image inspect` и одна ограниченная проверка `docker run --pull=never --platform linux/amd64 --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges --cpus 0.25 --memory 256m --memory-swap 256m --pids-limit 25`, без томов, API/model calls, новых image pulls, внутренних токенов, отправки сообщений или записи файлов. Контейнер считает Git blob SHA-1, возвращает только локальный ограниченный JSON для сравнения. Скрипт выводит агрегированные количества, не содержимое файлов или приватные каталоги. Обработка ошибок выдаёт фиксированный `UNKNOWN` и отказывает в GO.

Проверки после внедрения: **13/13** специальных негативных и позитивных тестов; полный Linux offline suite на отдельном контейнере должен выполняться перед merge. CI проверяет собственные контракты скрипта, но **не выполняет** live Docker-inspection в Actions.

## Ограничение заключения

Это частичная `source-to-image` **байтовая** сверка только Python-файлов из пяти фиксированных каталогов. **Она не доказывает воспроизводимость Docker build, signed provenance/SLSA attestation, полную SBOM, лицензии, отсутствие уязвимостей, правильность конфигурации, поведение плагинов или отсутствие платного bill fallback.**

Не проверены `tools/`, где в offline образе обнаружено 1529 Python-файлов против 353 в Git tree того же коммита: избыточные файлы могут быть штатными зависимостями/скриптами, но до отдельной классификации объявлять их безопасными нельзя. Также остаются непроверенными другие Python/JS/Rust файлы, docker layers, executable binaries и build-time hooks. Нельзя называть весь образ идентичным исходникам.

**Итог H-01 #33:** `resident_agent_allowed=false`, **NO-GO** для постоянного AI Agent. Нельзя автоматически устанавливать или включать новый образ на VPS, прокси, Telegram-отправку или платного провайдера; работающие news/Ops/Research службы не затронуты.
