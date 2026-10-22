# H-15 #483 - безопасная проверка временной файловой системы Windows BRC

**Только для sandbox** `h15-win-05be75515428`. Этот документ не является разрешением пересоздать действующий Docker-контейнер, изменить Windows host или удалить чужие каталоги.

## Фактическая диагностика, 23.10.2026

Через живой Hermes MCP, команда только для чтения, устройство `H15 Windows permanent sandbox` (`linux/docker`):

| Контроль | Наблюдение |
| --- | --- |
| Процесс | `uid=65534(nobody)`, `gid=65534` |
| /tmp | tmpfs 16,777,216 bytes; **0 свободных, 100%** |
| Mount | `nosuid,nodev,noexec,size=16384k,mode=700,uid=65534,gid=65534` |
| cgroup v2 memory.max | 536,870,912 bytes (512 MiB) |
| cgroup v2 memory.current | 133,492,736 bytes при проверке |
| TMPDIR | не задан |
| /workspace | Windows C: bind mount; **не считать отдельной приватной временной ФС** |
| Статус | **BUG REPRODUCED** / Windows Docker host run config пока не получена |

Наблюдение сделано без удаления и записи файлов и не устанавливает, какие процессы сейчас владеют содержимым /tmp. Старые данные об именах временных каталогов могут устареть. Ни один чужой файл не удалять автоматически.

## Безопасный preflight

`scripts/h15_brc_tmp_preflight.py` - стандартная библиотека Python, только чтение `/proc/self/mountinfo`, `statvfs('/tmp')`, метаданных каталога и cgroup v2. Вызов в одобренном Linux/Docker sandbox:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -m scripts.h15_brc_tmp_preflight
```

Запускать из проверенного checkout Hermes с тем же git origin / HEAD / clean tree. **Не** делать `pip install`, `mktemp` или иные временные операции до проверки. Программа не исполняет команд, не управляет Docker, не очищает /tmp, не меняет переменные окружения. Возвращает JSON без env/секретов, код 2 при отказе.

Коды отказа: `TMP_SPACE_EXHAUSTED`, `TMP_INODES_EXHAUSTED`, `TMP_ACCESS_NOT_PRIVATE`, `TMP_ENV_NOT_PINNED`, `NOT_PINNED_TMPFS`, `MEMORY_LIMIT_UNVERIFIED`, `MEMORY_HEADROOM_LOW`, `OBSERVATION_UNAVAILABLE`. Фиксированный порог 8 MiB свободного /tmp, не менее 64 свободных inode и 64 MiB cgroup headroom.

`SPACE_OK_NOT_AUTHORIZED` означает **только** достаточные измеренные ресурсы на момент проверки. Между проверкой и записью возможна гонка (TOCTOU). Отдельно остаются обязательными ограничение не более трёх независимых тяжёлых задач, границы исходного устройства/каталогов, проверки real tool rights и owner approval. Скрипт этого не обеспечивает.

Для предсказуемого выбора /tmp в разрешённой **существующей** задаче оператор может до запуска команды выставить `TMPDIR=/tmp TMP=/tmp TEMP=/tmp`, затем заново вызвать preflight. Python `tempfile` кэширует директорию после первого обращения, поэтому переменные нужны **до** запуска интерпретатора; Node `os.tmpdir()` также выбирает `TMPDIR`. Это не решение переполнения! Запрещён автоматический fallback на общий `/workspace`.

## Исправление на стороне Windows Docker host - отдельный контролируемый шаг

1. На действительно авторизованном Windows host, а не в BRC sandbox, идентифицировать **текущий** контейнер и источник его запуска (Compose/Task Scheduler/команда). Проверить `docker inspect` только локально у владельца. Не копировать полный JSON, который может содержать env-секреты, в Issue/чат. Зафиксировать sanitized identity: container ID, image digest, mount/security/network/UID, memory and tmpfs, pairing/deviceId, volumes и команду запуска.
2. Сохранить восстановимую исходную конфигурацию и план отката **до** пересоздания. Приоритетная минимальная гипотеза - `tmpfs /tmp size=64m` при неизменном `memory.max=512MiB`, `uid/gid=65534`, mode 0700, `nosuid,nodev,noexec`, identity/volume/OAuth. Не внедрять этот параметр до проверки реальной конфигурации Windows host. TMPFS расходует память по мере фактической записи; для трёх параллельных заданий отдельно измерить пиковое потребление.
3. Только при owner-authorized change window и подтверждённом rollback - контролируемый recreate/reconnect. **Никакой Windows reboot и никакой очистки чужих /tmp**.
4. Повторить `df -B1 /tmp` и preflight, затем в специально созданном собственном приватном task-local каталоге проверять `mktemp`, Python `tempfile`, Node `os.tmpdir()`, запись/чтение и удаление **только своих файлов**. Контролировать free bytes после очистки, deviceId, OAuth, отрицательные FS/MCP tests и сохранение connect/reconnect.
5. Фиксировать старый/новый container identity, точную конфигурацию, процедуру отката и результаты. Без этих свидетельств #483 остаётся **OPEN / PRODUCTION_FIX_NOT_VERIFIED**.

## Тестирование

`python3 -B -m unittest tests.test_h15_brc_tmp_preflight -v` - синтетические проверки порогов, типов, владельца, mount, env, inode, памяти, безопасного JSON и запрещённого состояния. Они не подтверждают ремонт живого tmpfs, reboot или Docker-host setup.

Смежные работы: [#454](https://github.com/MikeMoore1337/hermes/issues/454), [#445](https://github.com/MikeMoore1337/hermes/issues/445). Никакого Codex CLI, платного API, нового права, сети или постоянно работающей службы.
