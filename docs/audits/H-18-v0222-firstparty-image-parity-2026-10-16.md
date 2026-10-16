# H-18 / #199: полный byte-level parity first-party Python в immutable v0.22.2

**Дата:** 2026-10-16. **Итог:** `FIRST_PARTY_SUBSET_PARITY_NO_GO`; **resident Agent P0 NO-GO**. Не доказаны signed source-to-build-to-image provenance, отсутствие CVE или исполнимые runtime/OS/MCP границы.

## Контур и доверие к входам

На выделенном Windows Docker Desktop ранее локально присутствовал образ `nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05`, `linux/amd64`. С остановленного контейнера, созданного через `docker create` и **не запускавшего** Hermes Agent, ранее `docker cp` извлечены **только восемь** каталогов Python-кода и `pyproject.toml` из `/opt/hermes`. Статический snapshot хранится вне Git и не публикуется. [Предшествующий аудит](H-18-v0222-installed-jwt-image-snapshot-2026-10-16.md) подтвердил 5 Git blobs. Контейнер был удалён после извлечения; **для этой новой сверки Docker или контейнер заново не запускался**.

Официальный public upstream checkout `NousResearch/hermes-agent` закреплён на **полном** commit `d923a5eb487a17c0a68801bba9ef0f56c81040a8`. `scripts/audit_v0222_firstparty_image_parity.py` перед чтением проверяет локальный `git HEAD`, чистоту отслеживаемых Git-файлов и получает актуальный список всех `*.py` через уже имеющийся fail-closed helper `scripts.audit_v0222_python_surface._verified_git_filenames`. Дополнительных сетевых запросов, downloads, `docker exec`, исполняемых upstream Python/import или реальных exploit-тестов нет.

Сравнение строго по полным байтам каждого Python-файла и относительному пути; проверяются 8 roots: `agent`, `hermes_cli`, `gateway`, `cron`, `plugins`, `tools`, `acp_adapter`, `pm`. Непредусмотренные дополнительные Python-файлы, удалённые файлы, симлинки на исходники, превышение размера/числа файлов, некорректный Git snapshot → `INCONCLUSIVE`, фиксированная ошибка и exit 2. Расхождение известных байтов → `FIRST_PARTY_SOURCE_DRIFT`, а не PASS. Прямые raw source, приватные пути и содержимое временного snapshot не попадают в JSON.

## Фактические результаты (проверены на реальных байтах)

| Каталог | First-party Git Python | Побайтно совпали |
| --- | ---: | ---: |
| `agent` | 357 | 357 |
| `hermes_cli` | 682 | 682 |
| `gateway` | 184 | 184 |
| `cron` | 40 | 40 |
| `plugins` | 223 | 223 |
| `tools` (без bundled runtime) | 350 | 350 |
| `acp_adapter` | 14 | 14 |
| `pm` | 52 | 52 |
| **Итого** | **1902** | **1902** |

Найдено 3078 Python-файлов в восьми каталогах образа. **Все 1176 image-only Python-файлов точно отнесены к трём отдельным вендорским деревьям** (никаких иных extras):

| Отдельный unverified embedded component | Python-файлов |
| --- | ---: |
| `tools/python-3.14.7+20260901-linux-x64/` | 1059 |
| `tools/node-26.7.0-linux-x64/` | 59 |
| `tools/npm-12.0.2-linux-x64/` | 58 |

Этот список не является полной SBOM поставки: здесь **только файлы с расширением .py**, не JS, .so, wheels, dpkg, binary, runtime network tools и лицензии. Node/npm содержат Python-файлы вспомогательных пакетов (например, node-gyp). Сам Python 3.14.7 остаётся известным блокером обновления, потому что 3.14.8 устраняет проблемы безопасности; не смешивать подтверждённый source parity **Hermes** с безопасностью бинарного Python.

Reproducible SHA256 of sorted `relative-path NUL SHA256(file-bytes)` streams:
- First-party matched snapshot: `e275a6141c13cd16614470401f4719c7626e78f3ef5de0a18d94a2825e37af0e`.
- Extra runtime/vendor Python bytes: `fe22140964fd2bbad859822e0abbeff3ff6654ba4c26d0b35b2b20794cd66880`.

Выполнены **15/15 синтетических unit tests** и реальные byte comparisons. Отрицательные проверки: неизвестная/новая версия vendor runtime, внезапные и отсутствующие файлы, drift, замена путей, сырые секретные строки, симлинк, размер, неверная фикстура, отсутствие ложного GO и `NOT_EXECUTED` без opt-in. GitHub Linux CI отдельно проверяет код/фикстуры, **не** исходный Docker image.

### Ручной реплей (offline snapshots, без Docker invocation)

```bash
python3 -m unittest tests.test_h18_firstparty_image_parity -v
python3 -m scripts.audit_v0222_firstparty_image_parity
# NOT_EXECUTED, exit 0. Никаких файлов не читает.
python3 -m scripts.audit_v0222_firstparty_image_parity --execute \
  --source-tree /verified/clean/NousResearch-hermes-v0222-checkout \
  --image-tree /local/offline/image_source
# FIRST_PARTY_SUBSET_PARITY_NO_GO, exit 2 даже при всех совпадениях.
```

Скрипт не выполняет Docker, только статическую проверку ранее извлечённых локальных файлов. Подготовка нового полного образа или исходников - отдельное действие, на этой стадии не выполняется.

## Остаточный риск и gates

- Доказана **byte parity 1902 selected first-party .py files из остановленного образа**, не полный source-to-image provenance.
- Не проверены остальные `8503-1902=6601` Python-файлов полного исходного Git (их отсутствие в snapshot **не означает отсутствие в образе**) и все прочие OCI пути. Пятёрка отдельно проверенных JWT/pyproject files уже аттестована по Git blob hash в PR #213.
- Не проверены vendor binaries, bundled PyJWT в `site-packages`, native executable restrictions, SSH reachability, XML, SBOM coverage/лицензии и CVE исправления. Только offline filesystem evidence, **не** runtime security audit.
- Точный официальный v0.22.2 всё ещё имеет PyJWT 2.13.0, Python 3.14.7 и открытые CRITICAL/HIGH scanner findings; ни CVE applicability, ни исправления не закрыты.
- Независимая подписанная builder/publisher аттестация, новый исправленный immutable image, согласованный peak burn-in, zero-paid fallback enforcement и OS/native/MCP denies требуются отдельно. **`resident_agent_allowed=false`; Issue #199 и #33 OPEN.**
