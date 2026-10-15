# H-01 #33 - исходные файлы tools/ и встроенные среды исполнения

Дата: **15.10.2026**. Отдельный Windows Docker Desktop, immutable Linux/AMD64 Hermes Agent v0.22.1 `sha256:cd9cb455576d27c9b6311de1104494ad7e221b6e68dc77e9ac2a8af661a4dc21`. Официальный upstream source tree `297552a9d646119871391d202509822cd86330df`.

## Почему внутри tools/ больше файлов, чем в Git

Первичная проверка выявила 1529 Python-файлов `/opt/hermes/tools` против **353** в исходном Git tree. Причину удалось локализовать без чтения секретов и интернета контейнера:

| Область | Python-файлов |
| --- | ---: |
| `tools/` без вложенных каталогов сред | 278 |
| `tools/bot_desktop/` | 10 |
| `tools/computer_use/` | 13 |
| `tools/connectors/` | 32 |
| `tools/environments/` | 20 |
| **Итого исходники Hermes tools/** | **353** |
| `tools/node-26.7.0-linux-x64/` | 59 |
| `tools/npm-12.0.2-linux-x64/` | 58 |
| `tools/python-3.14.7+20260901-linux-x64/` | 1059 |
| **Итого дополнительные файлы встроенных сред** | **1176** |

Все первые пять групп **по числу файлов совпали** с официальным Git tree. Скрипт `scripts.verify_v0221_tools_python` дополнительно сравнил каждый из этих 353 файлов по **точному Git blob SHA-1 и размеру** с файлом официального source commit: **353 совпадения, 0 отсутствующих, 0 лишних и 0 отличающихся**. Названия и количество файлов встроенных сред учтены раздельно, но **их байты/происхождение/лицензии/уязвимости не проверены**.

Команда из корня чистого owner-repo:

~~~sh
python3 -m scripts.verify_v0221_tools_python
# NOT_EXECUTED
python3 -m scripts.verify_v0221_tools_python --execute
# TOOLS_PYTHON_BLOBS_MATCH_UNATTESTED, expected exit 2; resident_agent_allowed=false
~~~

Использует фиксированный Git-манифест `scripts/v0221_tools_python_manifest.json` из официального Git tree. Наследует тот же offline pinned Docker inspector (no pull, no network, no host mounts, read-only, nonroot 65534, 256MiB/0.25CPU/pids25), не загружает плагины, не обращается к модели или платным сервисам, не затрагивает production и не публикует отчёты. Подменённый digest, файл, недостающий скрипт, лишний файл вне исключённых сред или неожиданное число файлов встроенной среды -> NO-GO.

## Суммарное заключение H-01

Этот результат расширяет предыдущие [1410 совпавших Python файлов](H-01-v0221-core-python-parity-2026-10-15.md) до **1763 совпавших исходных Python-файлов в шести фиксированных каталогах**, из которых 353 - инструменты. Это не полная цепочка source-to-build attestation: нет проверки всех non-Python файлов, 1176 файлов встроенных сред, системных пакетов, собранных бинарников, подписи Docker-поставщика, SBOM, лицензий/уязвимостей или runtime-платёжного ограничителя. Любой Docker digest/commit вне зафиксированных не покрыт.

**Статус: NO-GO для resident agent.** Никакой загрузки нового образа на VPS, включения Cloudflare proxy, перезапуска таймеров и model calls не проводилось.
