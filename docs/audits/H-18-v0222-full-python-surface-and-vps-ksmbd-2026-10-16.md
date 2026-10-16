# H-18 / #199 — полный просмотр отслеживаемой Python-поверхности v0.22.2 и read-only ядра VPS

**Дата:** 16.10.2026. **Статус:** `SOURCE_STATIC_REVIEW_ONLY / P0_REVIEW_REQUIRED`. Исходная зависимость PyJWT 2.13.0 по-прежнему уязвима, образ не обновлён. Измерения не являются доказательством безопасности Docker image или разрешением запуска постоянного агента. Ветвь — отдельная чистая worktree, без изменения рабочих Docker/systemd.

## Точный охват и воспроизводимость

- Public repository: `NousResearch/hermes-agent`, точный checkout Git tag `v0.22.2`, peeled commit `d923a5eb487a17c0a68801bba9ef0f56c81040a8`, shallow read-only clone на отдельном Windows ПК. `git rev-parse HEAD` и `git status --porcelain --untracked-files=no` проверены перед анализом.
- `scripts/audit_v0222_python_surface.py` обходит **все отслеживаемые Git-файлы с суффиксом .py**, читает локальные bytes, хеширует каждый файл вместе с относительным путём в отсортированном порядке; не импортирует/не запускает upstream код и не выполняет network requests. Только кандидаты с заранее известными маркерами исследуются посредством Python AST. Версия Python: 3.14.
- **Измерено:** `python_files_examined=8503`, `python_bytes_examined=100807398` (100,8 MB), `candidate_python_parse_errors=0`. SHA256 определённого в скрипте отсортированного потока `<relative_filename> NUL <SHA256(file_bytes)>`: `268702e4971cc0e22c6d01818d81972e29b956901d008e803c3bea29264672e4`. Это воспроизводимый локальный отпечаток прочитанного snapshot, **не** подпись publisher и не гарантированная привязка содержимого Docker image.
- Исходный pinned immutable image: `nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05`, linux/amd64. Подписанная attestation `source -> build -> image` отсутствует. Нельзя утверждать, что каждый прочитанный Git-файл точно соответствует байтам в данном образе.
- CLI требует явно `--execute --source-tree`, предварительно проверяет pinned HEAD и отсутствие изменений отслеживаемых файлов; иначе возвращает `INCONCLUSIVE`. Даже успешный статический просмотр завершается **exit 2**, `resident_agent_allowed=false`. При отсутствии `--execute` возвращает `NOT_EXECUTED`; нет скрытой загрузки/клонирования.

## JWT: конкретные callsites

В полном снимке всех 8 503 отслеживаемых Python-файлов обнаружены **3 прямых вызова `jwt.decode()`** и **2 обёрточных вызова `verify_jwt()`** (AST, с разрешением `import jwt` и `from jwt import decode` в пределах файлов):

| Файл | Строка v0.22.2 | Статическое наблюдение |
| --- | ---: | --- |
| `plugins/cron_providers/chronos/verify.py` | 63 | `jwt.decode` получает `**decode_kwargs`; нужно учитывать значение, проверенное отдельным точечным аудитом PR #201 (RS/ES only) |
| `plugins/dashboard_auth/_shared.py` | 248 | Проверяющий `jwt.decode` использует передаваемый `algorithms`; два upstream вызывающих обработчика (Nous/self-hosted) исследованы в PR #201 |
| `plugins/dashboard_auth/_shared.py` | 263 | **Явно `verify_signature=False`**, но внутри диагностического/exception path после отказа основной проверки; это требует контроля обращения с логами и токенами, а не доказательство авторизации по неподписанным данным |

Обработчики Nous `RS256`, self-hosted `RS256/ES256/RS384/RS512/ES384/ES512` и Chronos `RS256/RS384/RS512/ES256/ES384` уже проверены по пяти конкретным Git blob IDs в [предыдущем акте](H-18-v0222-four-critical-cve-applicability-2026-10-16.md).

Нельзя считать обширный набор Python-файлов доказательством отсутствия динамически загружаемого кода, плагинов вне checkout, native FFI, сторонних wheel и нестатически обнаружимых вызовов. В том числе literal mixed-HS/asymmetric flags `false` при динамическом `**kwargs` **не** означает, что комбинация формально исключена; это показано полем `has_expanded_kwargs=true`.

**CVE-2026-102268:** PyJWT `2.13.0` по-прежнему находится в pinned v0.22.2 образе; исправление `2.14.0` указано upstream GHSA. Указанные три обработчика не показали опасной смешанной конфигурации HS и RS/ES, однако статус остаётся **INCONCLUSIVE глобально**, требуется исправленная immutable сборка. Источник: https://github.com/advisories/GHSA-ffc3-869f-jxw9 .

## XML и SSH: не путать текстовое присутствие с reachable vulnerability

В непохожих на тесты `*.py` модулях есть XML-imports, в том числе `plugins/platforms/wecom/wecom_crypto.py`, `tools/read_extract.py`, `hermes_cli/gateway_windows.py`. Они используют `xml.etree` / `xml.parsers` в Python. Это **не доказательство** ни использования, ни отсутствия уязвимого C-кода libxml2: транзитивные зависимости и native libraries отдельно не проверены, а плагины могут иметь сетевые входы. **CVE-2026-6653: INCONCLUSIVE** до полного связи external XML -> конкретный parser/native library -> разрешённый tool.

Сканер обнаружил `ssh`-подобный текст в **143 непомеченных как тестовые** отслеживаемых Python-файлах. Текстовое вхождение не равно исполнению SSH; вместе с тем обнаружен **реальный код исходящих SSH вызовов** в `tools/environments/ssh.py`, `hermes_cli/setup_terminal.py`, `hermes_cli/_subprocess_compat.py`. В upstream существует полноценный SSH execution backend, поэтому без проверенного **OS/native** deny-by-default нельзя закрыть `CVE-2026-60002` утверждением «SSH не используется». Действительный resident Hermes по #33 inactive. **Применимость к будущему агенту: INCONCLUSIVE**, требуется доказать недостижимость SSH tool/backend в OS sandbox.

## Отдельная read-only проверка канонического VPS Hermes

Выполнено только на **`vps1777112993`** (host подтверждён в прежних repository Ops Watch и reboot audits); команды `uname`, чтение `/proc/modules` и `/sys/module/ksmbd`, `ss -H -lnt` с локальным фильтром порта `445`, `systemctl is-active`. Никаких `ssh` connection tests, host probes, `modprobe`, systemd start/stop, firewall changes, restart и netcat.

| Проверка | Наблюдение |
| --- | --- |
| ОС ядра | Linux `6.8.0-146-generic`, `x86_64` |
| `/proc/modules` | `ksmbd` **не загружен** |
| `/sys/module/ksmbd` | каталог **отсутствует** |
| Локальные TCP listen сокеты на порту 445 | **0** |
| `hermes-agent.service` | `inactive` |
| `hermes-cloudflare-proxy.service` | `inactive` |

Это доказательство **состояния конкретного VPS на момент чтения**, а не аттестация загрузки при каждом reboot. Оно указывает, что проверенный host в этот момент **не имел загруженного `ksmbd`**, на котором основан kernel CVE `CVE-2026-43185`. Пакет `linux-libc-dev 6.12.111-1`, за который сообщил Trivy, поставляется **в Debian userspace образа** и содержит headers; он **не является текущим исполняемым kernel** проверенного Ubuntu host. Это подтверждает ошибочность непосредственного отождествления инвентаря headers с работающим kernel, но **не** означает полного снятия risk finding для иных хостов или будущих конфигураций. Vendor tracker: https://security-tracker.debian.org/tracker/CVE-2026-43185 .

## Что действительно доказано и что ещё блокирует

| Требование | Статус |
| --- | --- |
| Полный охват отслеживаемых Python файлов exact tag и AST прямых JWT calls | **LOCAL_SOURCE_CHECK** |
| Применимость уязвимости к работающему модулю `ksmbd` на данном host сейчас | **NO_LOADED_MODULE_OBSERVED**, не signed attestation |
| Вызов SSH / libxml2 в фактически разрешённых инструментах и native dependencies | **INCONCLUSIVE** |
| Исправленная версия PyJWT в новейшем удостоверенном immutable образе | **NOT_DONE** |
| Исправления/waivers CRITICAL/HIGH с подтверждением vendor и owner | **NOT_DONE** |
| Публикационная signed provenance, scanner/DB attestation, full SBOM/licence | **NOT_DONE** |
| Native tool permission enforcement, billable-provider hard stop, OS/network fail-closed, burn-in | **NOT_DONE** |
| Включение Hermes Agent или Cloudflare proxy | **НЕ ПРОИЗВОДИЛОСЬ** |

**P0 #199 — OPEN. P0 #33 — NO-GO.** Source-level audit не заменяет реальную проверку разрешённых вызовов, ядра в runtime, оценки vendor severity и повторную сборку с исправлениями.
