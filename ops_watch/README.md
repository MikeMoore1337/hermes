# Ops Watch: offline core (H-02)

Status (2026-10-14): the networkless health collector and SQLite outbox are active on Hermes VPS. Separately authorized one-event-per-tick Telegram sender and timer are now active (see [on-host audit](../docs/audits/H-02-autosender-vps-2026-10-14.md)). The owner manually verified a real Telegram transport receipt (message_id=4). Sender is NOT an AI agent, and no self-repair, unrestricted GitHub, YFC edits or publication permissions were added. The first automatic sender run observed an empty queue, not a real incident.

The component accepts a bounded normalized JSON snapshot:
- schema = hermes-ops-snapshot-v1
- observed_at = timezone-aware ISO timestamp (not older than 15 minutes)
- news = timer_enabled, timer_active, last_successful_discovery_at, consecutive_discovery_failures, consecutive_drain_failures, pending_jobs, oldest_pending_age_seconds, recent_provider_rate_limits
- optional yfc = backend, worker, bot_polling (healthy, unhealthy, unknown)
- optional actions = ci, deploy (success, failure, running, unknown)

Use a confirmed Telegram polling heartbeat, not merely a running container, before emitting bot_polling=unhealthy. If that signal is unavailable, report unknown. The recent_provider_rate_limits field must be measured in a known bounded recent window or last drain phase, NOT the historical cumulative provider_rate_limit_count.

No news articles with a healthy discovery timer is not a failure. An old snapshot results only in snapshot_stale. Missing optional sources are unknown, not proof of health.

Offline testing:
    python3 -m unittest discover -s tests -v

Offline evaluation (with a locally prepared, trusted normalized file):
    python3 -m ops_watch.cli --snapshot /path/to/snapshot.json

Changes between findings can be computed using ops_watch.changes or CLI --previous. There is no persistent deduplication or notification transport. Unexpected human-authored fields are never copied into findings; do not submit personal data or secrets in input.

Before production:
1. Finish H-01 with OS-level isolation and measured resource budget.
2. Add independently reviewed read-only collectors for YFC and GitHub, with authentication and exact minimal privileges.
3. End-to-end test missing signals, drift, restart/recovery, rate limits, dedup, resource ceilings and negative permissions.
4. Obtain explicit approval for any actual alert destination. No restart, merge, deploy, news publication or vault access.


## Local collector (approved Hermes host only)

The collector reads **only the health subsection** of the existing YFC-owned `/var/lib/hermes/state.json` (the full file is private and never logged). It reads only the state of `hermes-discovery.timer`; writes a sanitized list of incident codes in root-owned `/var/lib/hermes-agent/ops-watch/findings.json` and logs added/resolved fingerprints to the local system journal. The systemd timer may be enabled independently of a model provider, without affecting YFC's news processing.

Install **only after tested PR/CI** and confirm no pre-existing system monitor: `bash deploy/install-ops-watch.sh` on approved server with matching source. Check via `systemctl list-timers hermes-ops-watch.timer`, `journalctl -u hermes-ops-watch.service`. The service is sandboxed, network-less, has no write access to YFC state, and is not an alternative publication path. A user-facing Telegram channel is a later separate task with new credentials/approval.

Failure of reading health **fails closed**: no old success is claimed, and the systemd unit reports an error. Rate-limit anomaly is intentionally disabled until a source reports a real recent interval, not a cumulative counter. Optional remote connectors remain unknown until genuinely implemented.

### Least-privilege note (2026-10-14)

The original unit with no Linux capabilities cannot traverse the existing news service's 0700 private state directory (owned by another UID). The new unit needs exactly `CAP_DAC_READ_SEARCH` **for reading**, not `CAP_DAC_OVERRIDE` for writing, and keeps `ProtectSystem=strict`, `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, and a single `ReadWritePaths` output directory. This capability permits reading other filesystem paths if the process were compromised; its security boundary is the audited, tiny, read-only Python collector, no network, non-secret logging and systemd sandbox. Future migration to a dedicated scoped health API should eliminate the privileged filesystem read.


## Control of Hermes Agent network safety

The local 10-minute Ops Watch also reads **systemd metadata only** for `hermes-cloudflare-network-guard.service`. It reports stable, allowlisted incident codes when the guard is missing, disabled, or inactive, and preserves existing incident deduplication/recovery. It never reads AI credentials, model output or raw nft rules. A malformed systemd response is **UNKNOWN / collection failure**, never reported as a healthy guard. No automatic repairs or Telegram notifications are implied. This is an additional operational signal, not a proof that exact firewall rules stayed unchanged after the last startup check.

## Локальный предварительный текст инцидента (без отправки)

Каждый запуск сборщика формирует **фиксированные, проверенные** описания только
для новых и закрытых инцидентов и сохраняет их в локальном
`/var/lib/hermes-agent/ops-watch/incident-preview.json`. Текст никогда не
интерполирует сведения из новостей, ошибки модели, журналов CI, приватных
сервисов или URL. После прохода без изменений файл становится пустым массивом.
Это **снимок последнего прохода**, а не надёжная очередь доставки: внешнего
Telegram/почтового сообщения и подтверждения получения пока нет.
Разрешение и новый отдельный канал оповещений остаются обязательными.


## Надёжное локальное хранение событий мониторинга

Канонические состояния инцидентов и переходы `new/resolved` теперь
записываются **одной SQLite-транзакцией** в файл
`/var/lib/hermes-agent/ops-watch/incidents.sqlite3` (0600, системный владелец).
При первом запуске состояние однократно берётся из ранее существовавшего
`findings.json` для миграции. После миграции два JSON-файла остаются только
совместимыми проекциями и могут быть повторно созданы после сбоя, не генерируя
повторные события. Очередь ограничена 1000 событиями: при переполнении сборщик
отказывается терять сообщения и сигнализирует ошибку службы. Просмотр очереди
через `ops_watch.state_store.inspect` только локальный, без API и отправки.

**Важно:** это локальный журнал событий, не доставка и не подтверждённое получение.
В нём нет команды `ack`, Telegram, фонового соединения, приватных данных и
разрешения на публикацию. До подключения внешнего канала нужно отдельно
реализовать авторизованную отправку, подтверждение и архивирование событий.


## Локальный протокол доставки (ещё без отправителя)

`ops_watch.delivery_contract.claim_one` атомарно резервирует **старейшее** событие на
90 секунд. В один момент активна только одна доставка; неподтверждённое событие
не пропускается ради следующего. После реального подтверждения от внешнего
транспорта вызывается `confirm_one` с его числовым идентификатором сообщения
и секретом резервирования. Лишь тогда событие считается подтверждённым.

Если сервис принял сообщение, но ответ потерялся, возможен повтор. **Это
семантика at-least-once, не гарантия exactly-once**. После пяти неуспешных
резервирований событие блокирует очередь до ручного разбора, а не пропадает.
Действия и тексты восстанавливаются только по фиксированным проверенным кодам
(редактирование базы извне не позволяет вставить произвольную команду/URL).

На текущем этапе модуль **не отправляет сообщений**, не содержит получателя,
Telegram-токена, URL, автоматических таймеров или команд подтверждения из CLI.
Для последующего отправителя потребуется отдельное одобрение получателя,
токен нового независимого бота, проверка сетевого канала/ограничений и
сквозная проверка уведомления с подтверждением доставки.


## Отдельный Telegram-транспорт (код подготовлен, отправка НЕ включена)

`python3 -m ops_watch.telegram_sender` без `--execute` **никому не пишет** и
отображает только агрегированное состояние локального журнала. Команда
`--execute` без **отдельного** `HERMES_ALERT_BOT_TOKEN` и положительного
`HERMES_ALERT_PRIVATE_CHAT_ID` отказывается отправлять сообщения до
резервирования события. Не использовать редакционный токен YFC Hermes или
бота Second Brain. Бот должен быть заранее запущен самим получателем.

Модуль строго отправляет максимум **одну** запись одной команде через
Telegram Bot API `sendMessage`: один HTTPS POST с DNS/TLS проверкой точного
`api.telegram.org`, без редиректов, платных флагов, повторов и вставки
пользовательского текста. Успех фиксируется только по успешному ответу API,
положительному `message_id` и совпадающему `chat.id`. Это подтверждает
**принятие сообщения Telegram**, но не прочтение человеком. Потеря ответа
может привести к дубликату при следующей попытке; после 5 попыток запись
остаётся для ручного разбора.

Ни автозапуска, ни сетевого разрешения на VPS, ни рабочего токена/получателя
сейчас нет. Код не является разрешением на отправку сообщения. Введение
отдельного service/timer, проверка владельцем chat ID и реальная доставка -
следующий явно проверяемый этап задачи #3.

Официальная документация: https://core.telegram.org/bots/api#sendmessage.


## Проверка состояния без записи

Команда Telegram без `--execute` открывает SQLite строго для чтения: она
не создаёт таблиц и не резервирует событий. При пяти исчерпанных попытках
`--execute` выдаёт `telegram_delivery_exhausted` вместо ложного статуса
пустой очереди, сохраняя запись для ручной проверки.


## Однократная проверка отправки и записи подтверждения (только вручную)

Код: \`ops_watch.telegram_e2e\`; запуск только с явным \`--execute\`.
Без флага **нет обращения к сети и чтения токена**.
На одобренном хосте (после отдельной установки именно проверенной ревизии):

\`\`\`bash
sudo env PYTHONPATH=/opt/hermes-agent-owner \
    python3 -m ops_watch.telegram_e2e --execute
\`\`\`

До команды владелец должен подтвердить, что изолированный чат принадлежит ему и
\`/etc/hermes-agent/ops-watch.env\` содержит РОВНО два корректных ключа
\`HERMES_ALERT_BOT_TOKEN\` и \`HERMES_ALERT_PRIVATE_CHAT_ID\`.
Файл должен быть regular, root-owned 0600; ссылка на другой файл запрещена.
При успешном запуске в **отдельной временной БД, не в production** создаётся один
синтетический инцидент, отправляется ровно одно сообщение с явной приставкой
«ТЕСТ Hermes Ops Watch. Реального сбоя нет.», возвращённый Telegram \`message_id\`
записывается в \`delivery_receipts\`. Затем повторная отправка блокируется.
Скрипт проверяет наличие ACK и одной попытки, выводит только безопасные счётчики.
Он не запускает таймер, не меняет рабочую очередь, не делает автоматических повторов.

\`UNKNOWN_OR_FAILED\` - **не повторять команду автоматически**: если запрос принят
Telegram, а ответ потерян, второе выполнение может создать дубликат.
Проверить чат и журналы вручную. \`message_id\` означает приём сообщения API,
а не прочтение его человеком.

Важно: успешный unit test с заглушкой не подтверждает реальный HTTP.
Провести live-проверку только после отдельного сетевого допуска и установки
утверждённой ревизии; предыдущая попытка live-запуска через удалённый инструмент
была остановлена внешней защитой. **Не обходить этот запрет новым каналом.**

## Отдельная автоматическая доставка Ops Watch (H-02; разрешена владельцем)

После успешного ручного [сквозного теста](https://github.com/MikeMoore1337/hermes/pull/73) с реальным Telegram `message_id=4`, записью ACK и подтверждением получения владельцем подготовлена **отдельная** systemd-служба `hermes-ops-alerts.service` и таймер `hermes-ops-alerts.timer` (PR этапа H-02). Это не автозапуск Hermes AI Agent и не изменение существующего networkless `hermes-ops-watch.service`.

При запуске отправитель считывает только защищённый `/etc/hermes-agent/ops-watch.env` (root-owned `0600`) по защищённому file descriptor и берёт из рабочей SQLite **не более одного** сохранённого фиксированного инцидента. Telegram-транспорт проверяет HTTPS/TLS, `chat.type=private`, `chat.id` и положительный `message_id`. Лишь после ACK сообщение считается подтверждённым. Никакие новости, пользовательские данные, тексты CI, модели или сырые логи не передаются.

Таймер первый раз запускается приблизительно через 2 минуты после активации, затем не чаще одного сообщения на 10-минутный интервал; `Persistent=false`, автоматическая догоняющая отправка после простоя отсутствует. Максимум 5 попыток на один инцидент, 90 секунд резервирования, не пропускать неподтверждённое событие; неполученный ACK допускает дубликат после истечения аренды. Это **at-least-once**, не exactly-once. При истощении попыток потребуется ручное расследование. Никаких самовосстановлений, перезапусков новостного конвейера и GitHub write.

Отправитель запускается с отдельным sandbox systemd (CPU/RAM/timeout; без Linux capabilities и без доступа к `/var/lib/hermes`); root используется из-за уже существующего root-owned `0600` SQLite и токена. Владелец разрешил самостоятельное включение после CI и preflight 14.10.2026. Установка только сверенного с GitHub кода и юнитов:

```bash
sudo bash /opt/hermes-agent-owner/deploy/install-ops-alerts.sh
systemctl status hermes-ops-alerts.timer --no-pager
journalctl -u hermes-ops-alerts.service -n 20 --no-pager
```

Безопасное отключение отправки (сборщик и новости остаются работать):

```bash
sudo systemctl disable --now hermes-ops-alerts.timer
```

Остановка таймера не отменяет уже начатый запрос `sendMessage`: проверь отдельно службу `hermes-ops-alerts.service`. Не выводить файл с токеном в консоль, GitHub, journal или отчёты. Статусы `DRY_RUN_ONLY`/`EMPTY_OR_LEASED` не означают, что Telegram доступен: при пустой очереди сетевого запроса нет. Реальную проверку действующего таймера проводить на новых фактических инцидентах, без искусственного нарушения YFC.


### Ограничение каталогов при отправке

Родительский `/var/lib/hermes-agent` защищён `0700` и принадлежит системному пользователю `hermes-agent`. Служба без дополнительных Linux capabilities не может пройти через этот каталог. Вместо выдачи `CAP_DAC_READ_SEARCH` systemd монтирует только очередь `/var/lib/hermes-agent/ops-watch` в изолированный `/run/hermes-ops-alerts/outbox` с помощью `BindPaths`, закрывая доступ к исходному каталогу с помощью `InaccessiblePaths`. Read-only диагностика в transient sandbox на VPS показала, что очередь доступна через ограниченный путь. Это не открывает полный каталог Hermes, не меняет права production DB и не даёт sender доступ к YFC.


### Надёжная проверка восстановления

[Процедура и факт восстановления исходного systemd unit](../docs/operations/H-02-SAFE-INCIDENT-TEST.md): не отключать и не останавливать активные критичные службы ради теста. При связанном unit `systemctl disable` удаляет и системную ссылку; ошибка 15.10.2026 восстановлена по исходному backup symlink. Новый офлайн-регрессионный сценарий проверяет событие `new` -> `resolved`, резервирование, ACK и защиту от повторов, не изменяя production и не выдавая синтетический инцидент за естественный.


## Необязательный источник CI Hermes main (H-04)

Отдельная root-only read-only служба `hermes-qa-watch` может записывать только минимальный [CI signal](../docs/operations/H-04-READONLY-WATCH.md) после верифицированного GitHub Actions GET, без приватных логов и без токена Telegram. Сетево изолированный collector добавляет `ci_failed` только по свежему сигналу; при UNKNOWN, RUNNING или устаревшем сигнале прежний CI инцидент **сохраняется**, без ложного `resolved`. Служба новостей не модифицируется. Включение только после CI и отдельного проверенного rollout.


## Стойкость локального сборщика к аварии записи JSON (15.10.2026)

Снимки `findings.json` и `incident-preview.json` - **восстанавливаемые производные** от основной SQLite. Раньше запись использовала предсказуемое имя `findings.json.tmp` с `O_EXCL`: если процесс аварийно завершался после создания временного файла, следующая проверка падала при попытке создать этот же файл и могла надолго остановить сборщик инцидентов.

Исправление: для каждого снимка используется **новый уникальный** временный файл `0600` в защищённом каталоге, `fsync` файла, атомарный `os.replace`, `fsync` каталога и очистка временной записи после ошибки. Случайно оставшийся старый `*.tmp` больше не блокирует работу, а существующие символические ссылки не переписываются. Данные исходного новости/YFC и очередь Telegram не меняются по содержимому, сервисы не рестартуются. Офлайн регрессия воспроизводит сбойный остаток и последовательность `incident new -> resolved` через реальный collector + SQLite, без systemd и Telegram.


## Контроль доступности собственной доставки Telegram

Поскольку автоматический отправитель `hermes-ops-alerts.timer` является независимой службой, прежний Ops Watch мог оставаться «здоровым» при отключённом или неактивном отправителе. Новая строго read-only проверка `systemctl show` фиксирует `LoadState`, `ActiveState` и `UnitFileState` **только этого таймера**. Неизвестный формат ответа не означает успешное состояние.

В рабочем `collector.main` результат проверки добавляется в снимок как `alerts_timer`. Три фиксированных кода: `alert_sender_missing`, `alert_sender_disabled`, `alert_sender_inactive`. Возврат в рабочее состояние создаёт однократное `resolved` по обычной SQLite-схеме. Ни проверки вручную, ни аварийных отключений/включений реальных служб не производится: все негативные сценарии - через изолированные временные состояния в тестах.

**Ограничение:** если сам отправитель отключён, сообщение физически не сможет уйти в Telegram до восстановления таймера. Инцидент и восстановление останутся в защищённой SQLite-очереди для последующей отправки. Сборщик не пытается сам включать Telegram, ремонтировать систему или обходить эту зависимость. При недоступном systemd проба завершается ошибкой, а не ложным `healthy`.


### Проверка результата самой службы доставки (15.10.2026)

Даже при `hermes-ops-alerts.timer=active/enabled` отправитель `hermes-ops-alerts.service` может завершиться `start-limit-hit`, `exit-code`, `timeout` или `oom-kill`. Для исключения ложного «всё работает» добавлено второе независимое **только для чтения** наблюдение `systemctl show hermes-ops-alerts.service -p LoadState -p Result`. Успешно завершённая oneshot служба обычно `inactive` - **это не ошибка**; оценивается `Result`, а не `ActiveState`.

Когда `Result` не `success` либо служба не загружена, Ops Watch регистрирует критичный `alert_sender_failed`, сохраняет событие в SQLite и на последующем штатном успешном запуске создаёт ровно одно `resolved`. Журнал на VPS содержал прежний `start-limit-hit`, однако на момент разработки текущий `Result=success`, значит не создаём ложную тревогу из истории. Все отрицательные тесты выполняются с фиктивными ответами `systemctl` и временной SQLite. Не выводить ключ бота, не запускать восстановление systemd, не отправлять тестовое сообщение, не менять рабочую новостную службу. Наличие записи не гарантирует Telegram-доставку, пока неисправен сам отправитель.


## Исчерпание пяти попыток не должно блокировать последующие уведомления

Ранее после пятой неудачной попытки отправки самого старого события `claim_one()` всегда возвращал `None`, несмотря на следующие ожидающие события. Это могло **навсегда блокировать реальное восстановление и новые аварии**. Теперь после истечения последней 90-секундной аренды старый элемент остаётся в SQLite со статусом `leased, attempts=5` (история не удаляется), но следующий допустимый элемент получает собственную отдельную аренду и может быть доставлен. Активная аренда по-прежнему сохраняет FIFO, повтор пятого сообщения запрещён, проверка нетронутости всех событий остаётся обязательной.

Если новое сообщение удалось доставить и подтвердить, но в очереди сохраняется хотя бы один исчерпанный элемент, отправитель выдаёт `ACCEPTED_WITH_EXHAUSTED` **с кодом завершения 2**. Это не создаёт ложного `Result=success` у systemd, поэтому сам Ops Watch не объявит неустранённую проблему восстановленной. Сообщения содержат только заранее утверждённые названия инцидентов. Информацию об исчерпанных попытках должен разобрать оператор, без автоудаления и повторной отправки исчерпанного события. Все регрессионные тесты выполняются с временной SQLite и поддельным транспортом Telegram - без сетевой доставки и изменений рабочего VPS.


## Долговременное хранение подтверждённых уведомлений

Вместо ограничения `MAX_EVENTS=1000` на **все события за время существования системы** ограничение теперь применяется к **неподтверждённым** событиям (включая исчерпавшие попытки). Если, например, все 1100 прежних событий подтверждены Telegram, появление нового инцидента и получение аренды не блокируются: история и квитанции ACK остаются в SQLite, удалять или считать их несостоявшимися не нужно. При 1000 ещё ожидающих или исчерпанных событиях новое событие по-прежнему отвергается с `outbox_full`, без удаления очереди. Получатель обрабатывает только непогашенные записи, но сохраняет валидацию каждого отправляемого сообщения. Офлайн тесты проверяют сценарий 1100 старых ACK и сохранение лимита на неподтверждённые сообщения.

**Ограничение:** это исправление не архивирует историю и не ограничивает общий размер SQLite на диске. До реализации безопасной архивной политики нужен отдельный контроль свободного места и сохраняемых квитанций; нельзя запускать автоматическую очистку из предположения, что старые сообщения «не нужны».


## Исправление чтения SQLite в 2026-10-15

`read_current()` и `inspect()` используют percent-encoded SQLite URI (`Path.absolute().as_uri() + "?mode=ro"`), поэтому `?` и `#` в легальном пути не изменяют режим подключения и не приводят к чтению другой базы. Обе операции не изменяют файл; `inspect()` также отклоняет hardlinked DB, согласованно с основным транзакционным интерфейсом. Сценарии проверены только в временной SQLite фикстуре, production очередь не меняется. Это укрепление чтения, **не** доказательство естественной Telegram-доставки инцидента или восстановления.


## Ops Incident Advisor: только объяснение оператору

`docs/operations/H-02-OPS-INCIDENT-ADVISOR.md` описывает ограниченный первый
функциональный сценарий. `python3 -m scripts.ops_incident_advisor --all
--engine offline` проверяет 12 подготовленных случаев без модели. Для одного
локального Docker-прогона через настоящий CLI Hermes используйте, например,
`py -3.14 -m scripts.ops_incident_advisor --scenario provider_http_429
--engine docker`.

Advisor принимает только обезличенный allowlist-контекст, не запускает tools,
не имеет production credentials и возвращает только проверенный операторский
разбор. Mock provider нужен для воспроизводимости; его `MOCK_ONLY` не является
оценкой качества реальной LLM. Подключение к Cloudflare Workers AI заблокировано
до отдельного подтверждения Workers Free и владельческого пилота по #62.
