# H-01: пробный запуск на действующем Hermes VPS

**Дата**: 2026-10-11, UTC 13:32-13:47. **Scope**: владелец разрешил использовать тот же Hermes VPS и увеличить swap, если это помогает. Никаких новых VPS, моделей/аккаунтов, секретов и Telegram-подключений.

**Результат**: безопасный краткий CLI smoke **PASS**; полноценный автономный Hermes Agent / gateway **NOT DEPLOYED**. Не выдавать `hermes --version` за функциональную работу агента с LLM, расписаниями или инструментами.

## Подтверждённая конфигурация

| Параметр | До | После / факт |
|---|---|---|
| RAM total | 1967 MiB | без изменений |
| Swap total | 2047 MiB | 4095 MiB |
| Старый swap | `/swapfile1` 2 GiB, priority -2 | сохранён |
| Резервный swap | отсутствовал | `/swapfile-hermes-extra` 2 GiB, priority -3 |
| `vm.swappiness` | 20 | без изменений |
| Диск до образа | ~14.8 GiB available после swap | ~10.5 GiB после распаковки |
| Новости | active timer/anchor; last oneshot success | **unchanged**, проверены повторно |
| Reminder Bot / PostgreSQL / proxy | active | active, БД healthy по Docker |
| Автоматический новый Hermes Agent | отсутствовал | отсутствует |

Созданный дополнительный swapfile: права `0600`, `mkswap`, `swapon -p -3`, добавлена строка в `/etc/fstab`; перед изменением создан резервный файл `/etc/fstab.pre-hermes-extra-<UTC timestamp>`; выполнен `systemctl daemon-reload`. Дополнительный файл после проверки ещё не использовался (`0B`). **Это запас на случай пиков**, не увеличение физической памяти. Границы текущего новостного guard **не изменены**: min MemAvailable 768 MiB, max swap used 1024 MiB, load1 max 1.5, disk free min 5120 MiB.

## Закреплённый образ

- GitHub [upstream v0.21.6](https://github.com/NousResearch/hermes-agent/releases/tag/v0.21.6): 2026-10-08; annotated tag resolves to `818c13be1dc4fd28987e1e881a9408224afd4535`.
- Docker Hub `nousresearch/hermes-agent:v0.21.6` для `linux/amd64`: manifest digest `sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22`.
- Image local `RepoDigests` and platform verified; `docker image inspect` reported ~1,120,015,676 bytes.
- **Provenance caveat**: CLI выводит `Hermes Agent v0.21.6 (2026.9.24) · upstream a28a5d03`. GitHub commit `a28a5d03a9fa60418db5f44f3436fa2aa029c8f2` является предком tag commit на **39 коммитов**. Образ соответствует опубликованному Docker-тегу, но точное соответствие содержимого образа последнему коммиту тега **не доказано**. Для общего production gateway необходимо отдельно выяснить release provenance и security delta.
- Образ загружен лишь на Hermes VPS, без Compose и без перезапуска рабочих контейнеров.

## Smoke и post-check

На сервер в `/opt/hermes-agent-owner/` размещены **ровно две** проверенные копии из GitHub `main@24c2c43447a4cf38bab0fbb4751ecdeef3c21521`:
- `scripts/host_capacity.py` (git blob SHA `65703b090cd0a802b1e52e69c2511fc5d137c3a6`);
- `deploy/smoke.sh` (git blob SHA `571248d3a779408fe40ba6ffbc2d7a71b3587ea2`).

После pull, когда load1 ещё составлял 4.51, **news guard отклонил запуск** (`high_load`), а новый admission guard вернул `existing_news_load_pressure`. Это ожидаемое безопасное поведение. После снижения нагрузки до 1.2 admission разрешил проверку.

Вызов `bash /opt/hermes-agent-owner/deploy/smoke.sh` дал `SMOKE_EXIT_CODE:0`. Вывод:
```text
/opt/hermes/bin/hermes
Hermes Agent v0.21.6 (2026.9.24) · upstream a28a5d03
Install directory: /opt/hermes
Install method: docker
Python: 3.14.7
OpenAI SDK: 2.24.0
```

Среда одноразового контейнера: `--network none`, `--read-only`, `--user 10000:10000`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--pids-limit 64`, `--cpus 0.25`, `--memory 128m`, `--memory-swap 256m`, volatile tmpfs, `--rm`. Никаких bind mounts, root Docker socket, host network, новых credentials, runtime volumes, профилей или подписок. **Не выполнены** реальная модель, agent turn, plugins/MCP и browser.

После:
- news timer and network anchor: `active`;
- discovery/drain: `Result=success`, `ExecMainStatus=0`;
- YFC news resource guard: `status=ready`, available ~1068 MiB, swap used ~830 MiB, load1 ~0.41, disk free ~10496 MiB;
- Reminder Bot up, PostgreSQL healthy, Telegram proxy up;
- контейнер smoke удалён (`docker ps -a` не содержит image).

## Решение о дальнейшей эксплуатации на этом же VPS

Владелец **одобрил этот VPS как место H-01**, поэтому отдельный сервер не обязателен. Но не одобрено и не обосновано включение **постоянного** Hermes gateway:
- запас RAM относительно 768 MiB порога news guard только ~300 MiB после smoke, причём ресурсы меняются в течение суток;
- used swap ~830 MiB, запас до порога 1024 MiB только ~194 MiB, **несмотря на увеличение размера swap до 4 GiB**;
- даже одна распаковка подняла load1 выше 1.5; запуск дополнительных тяжёлых процессов может вызвать skip news;
- нет утверждённой модели, ключа/лимитов, отдельной Telegram identity или доказанных capability boundaries.

**Следующее допустимое действие**: измерение peak RAM/CPU реального изолированного runtime в рамках безопасного интервала, непрерывный мониторинг новостных порогов и создание on-demand профиля с полностью изолированными файлами. Не размещать постоянный автономный процесс без доказанного ресурсов/безопасности. Если не проходит, предложить *увеличить RAM у существующего VPS* с явным подтверждением возможной стоимости, а не пытаться компенсировать это swap.

**Статус H-01**: partial implementation; Issue #2 остаётся открытым. H-02/H-03 ещё не активированы.
