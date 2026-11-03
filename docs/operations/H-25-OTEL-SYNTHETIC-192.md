# Hermes #192 — OpenTelemetry candidate, isolated synthetic-only lane

**Status:** OFFLINE_ONLY / RUNTIME_NO_GO / NO_COLLECTOR. Этот документ описывает `eval_lane/offline_otel_projection.py` и не разрешает внедрение телеметрии в работающие сервисы.

## Gap analysis: переиспользование уже имеющегося

| Контур | Уже есть в Hermes | Наблюдаемый пробел | Решение этого этапа |
| --- | --- | --- | --- |
| Ops Watch | `ops_watch/collector.py`: read-only systemd/health signals; `state_store.py`: SQLite incident/outbox transaction; `retention_audit.py`: локальный лимит storage review | Нет безопасной корреляции отдельных агентных `turn/tool` с детальными latency/error | Только синтетический формат-прототип, **не второй Ops Watch** |
| H-23 benchmark | Offline synthetic scenarios; результат CI не доказывает живые вызовы | Нет независимого runtime turn trace/receipt | Не выдумывать provenance/usage |
| Control Center | Existing owner-only read-only incident/UI projections | Trace view или сборщик для live calls не согласованы | **Нет новых страниц/API/сервисов** |
| Future H-01 agent | Resident isolation и owner GO требуют отдельных задач #33/#350 | Нет подтверждённого bounded OS/egress runtime | До GO **нет SDK hooks и collector** |

Фактический live journal retention, CPU/RAM overhead и реальное качество traces **не замерялись**. Отсутствие source-visible OTEL exporter не доказывает отсутствие любой ручной телеметрии на VPS.

## Prototype contract: offline, non-network

`eval_lane/offline_otel_projection.py`, вход `hermes-h25-otel-synthetic-input-v1`, выход `hermes-h25-otel-synthetic-output-v1`.

Вызов только для synthetic fixture, читаемой через stdin (без runtime импортирования):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -m eval_lane.offline_otel_projection --stdin <<'JSON'
{"schema":"hermes-h25-otel-synthetic-input-v1","visibility":"PUBLIC_SYNTHETIC","source_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sample_stride":1,"events":[{"kind":"tool","tool":"ops_watch","duration_ms":13,"error_kind":"none","attempt_count":1,"retry_count":0,"budget_state":"within_limit","output_bytes_bounded":120,"trace_completeness":"complete"}]}
JSON
```

Экспортёр здесь **не отправляет** OTLP: возвращает внутренний `otlp_json_candidate` c `resourceSpans` и `resourceMetrics`, который нельзя передать одним OTLP/HTTP POST. Раздельные тела проверены независимыми protobuf-типами (ниже); реальный collector/exporter/network не проверялся. Поля `review` не входят в OTLP.

- Разрешённые `tool`: `ops_watch`, `qa_advisor`, `research_scout`, `other`. Для `kind=turn` tool только `null`.
- Лишь числовые длительности, число попыток/повторов, ограниченный размер вывода и строгие enum типов ошибок, budget/status, trace completeness. Не принимать произвольные имена tools, команды, пути, URL, стек исключения, payload, prompt/response, токены, идентификаторы пользователя и аргументы.
- `duration_ms=null`: отсутствует измерение, span/gauge не создаётся, ноль не подставляется. `unknown_duration_events` считает только sampled события, новый `unknown_duration_input_events` - все события. `duration_ms=0` - известный синтетический ноль.
- Для `error_kind=unknown` статус OTLP - `UNSET=0` (не успех); `none` - `OK=1`; `timeout/denied/execution_error` - `ERROR=2`. Ошибки `hermes.synthetic.errors` агрегируются по **всему** прошедшему проверку пакету до sampling, чтобы не терять ошибки в пропущенных событиях.
- `unknown_error_input_events` и `incomplete_trace_input_events` считаются по всем событиям, в том числе unsampled; `review.error_aggregate_scope=ALL_VALID_INPUT_EVENTS`. Длительности остаются sampled и не гарантируют репрезентативность распределения.
- Стоимость и токены здесь НЕ ИЗМЕРЯЮТСЯ: `cost_measurement_state`/`tokens_measurement_state=NOT_MEASURED`. Прежние флаги `unknown_cost` и `unknown_tokens` сохранены для совместимости. Причина `duration_ms=null` неизвестна (`UNKNOWN`). Некорректные входные значения - `INVALID` и полный отказ, а не числовое измерение.
- Trace/span IDs детерминированы из source SHA + индекса посредством hashlib; временная метка — фиксированная **синтетическая** epoch. Они не являются доказательством живой корреляции, измерения времени, провайдерского ответа или аутентификации.
- Error/status не принимает свободный текст. Дополнительные поля `metadata`, `resource_attributes`, `span_attributes`, `exception` и произвольные tool/error strings отклоняются. Даже вложенный/невалидный JSON возвращает фиксированный `REFUSED` без вывода исходного содержимого и traceback.
- Любое нарушение schema/types, повтор JSON-ключа, размерное превышение или неизвестный enum → полностью `REFUSED` (CLI exit code 2), без частичных traces.
- Не более **16 KiB** вход, **32 events** / batch, **64 KiB** выход, не более 600 секунд на фиктивный turn, не более 16 KiB фиктивного output size, 3 attempts, `sample_stride` 1..16.
- Sampling детерминированный по индексу фикстуры. Валидация и счётчики ошибок работают на ВСЁМ пакете до sampling. Drop-on-overflow = отказ всего пакета, а не частичный результат. Runtime instrumentation **не интегрирована**, её отказ не способен остановить работающий агент.
- Output формируется в памяти и пишется в stdout только при прямом запуске CLI. Собственных файлов/сети/таймеров нет; перенаправление stdout - ответственность вызывающего процесса. Offline retention - `MEMORY_ONLY`; runtime sampling/retention отсутствуют.

## Security/production gate

Нельзя импортировать этот fixture builder в Ops Watch/Research Scout/Control Center/H-01 без отдельной правки и preflight. Никаких `pip install opentelemetry-*`, collector, OTLP endpoint, network port, PID tracing, env-probing, автоматических прав ОС/CLI либо новых секретов.

До любой production-инструментации требуются: (#33) подтверждённый live runtime; owner approval exact resource/tool boundary; отдельный policy-sanitizer перед SDK; negative exfiltration tests на реальных gateway traces; bounded ingress/sampling/retention; CPU/RAM/disk overhead и drop counters; доказанный fail-open для telemetry только (не для guard/security); protected OTLP exporter; rollback и совместимость с Ops Watch/SQLite без второго источника истины.

## QA / Release

```sh
python3 -B -m unittest tests.test_h25_otel_offline -v
```

Проверяются schema, trace/metric, UNKNOWN!=0, privacy, sampling, limits, invalid JSON/duplicate keys, max batch и детерминированность. Дополнительный модуль `tests/test_h25_otel_regression.py` добавляет 11 проверок ошибок статуса, sampling, incomplete metadata, timeout, CLI, no-I/O и OTLP protobuf mapping (последняя проверка SKIP, если пакет `opentelemetry-proto` не установлен; runtime dependency не добавляется). Локально 03.11.2026: 27/27 PASS. GitHub CI на exact PR SHA обязателен; source-only merge не включает exporter. #192 остаётся OPEN до разрешённой эксплуатационной приёмки.

Related: [#192](https://github.com/MikeMoore1337/hermes/issues/192), [#33](https://github.com/MikeMoore1337/hermes/issues/33), [#470](https://github.com/MikeMoore1337/hermes/issues/470). Никакие BRC/Windows workstreams не затрагиваются.

## OTLP compatibility (независимый офлайн-аудит 03.11.2026)

Официальная спецификация: https://opentelemetry.io/docs/specs/otlp/ . Для OTLP/HTTP `/v1/traces` используется отдельное `ExportTraceServiceRequest` (`resourceSpans`), а для `/v1/metrics` - `ExportMetricsServiceRequest` (`resourceMetrics`). Поэтому существующий ОБЪЕДИНЁННЫЙ `otlp_json_candidate` - только внутренняя упаковка, не одно тело OTLP-запроса.

Через `google.protobuf.json_format.ParseDict(ignore_unknown_fields=False)` и официальные `opentelemetry.proto.collector.trace.v1.trace_service_pb2` / `metrics.v1.metrics_service_pb2` в изолированной среде подтверждено: `{"resourceSpans": candidate["resourceSpans"]}` - PASS, `{"resourceMetrics": candidate["resourceMetrics"]}` - PASS, полный candidate с обоими полями - EXPECTED REJECT для обоих типов. Hex `traceId/spanId`, числовые enum, decimal-string `*UnixNano` и `asInt/intValue` совместимы с JSON mapping. `source_revision`, trace IDs и фиксированный timestamp - синтетические, не живые.

Нет доказательств совместимости с настоящим Collector, транспортом OTLP/HTTP, retry/drop и темпоральной семантикой live метрик. Trace IDs генерируются из source SHA + index и могут повторяться в другом batch на той же ревизии - это **не** уникальные live trace IDs. Нельзя активировать exporter или переименовывать candidate в production OTLP по одному лишь protobuf parse.

## Отказоустойчивость, приватность и ресурсы

- Схема входа строго ограничена: 16 KiB stdin, не более 32 событий, 3 попытки, 600000 ms duration, 16384 bytes output field, 1..16 sample stride. Результат <=64 KiB. Недопустимые типы, extra keys, тайные строки, oversized packets и duplicate JSON keys дают фиксированный отказ exit code 2, без traceback и произвольного error string.
- Тесты используют только вымышленные marker strings, а не пользовательские промпты/ответы/секреты. `project()` не инициирует сети, чтения/записи файлов или запусков процессов. Вызов CLI выводит безопасный JSON в stdout.
- На Linux x86_64 Python 3.13.5, 300 вызовов `project()` для 32 синтетических событий с `tracemalloc`: median=3.200 ms, p95=3.938 ms, max=7.233 ms, Python allocation peak=342970 bytes, input=6422 bytes, output=26327 bytes. Эти замеры **не являются** результатами H-01, реальной CPUQuota, RSS или сетевого collector.
- Runtime wall-clock timeout при ожидании EOF на stdin и OS CPU/RAM cgroup для этого offline CLI здесь не обеспечиваются. Никаких дисковых очередей, persistent DB, exporter, SDK hooks и collector не существует. Runtime fail-open для телеметрии и fail-closed для security-guard можно подтвердить только в отдельно разрешённом интеграционном контуре.

## Read-only VPS observation (03.11.2026, не live tracing)

На основном VPS read-only: release SHA `3f9acc8e2760f2dc33f76ae0d397761b52b699e8` совпал с `/var/lib/hermes-main-deploy/last-success.sha` и release receipt. Offline OTEL source присутствует. H-01 one-shot и Ops Watch показали последний `Result=success`, их таймеры active/enabled; OTEL-named systemd units не найдены. H-01 имеет `CPUQuotaPerSecUSec=250ms`, `MemoryMax=201326592`. Это НЕ подтверждает #33 GO, живые turn/tool spans, отсутствие произвольной кастомной телеметрии или абсолютные лимиты будущего OTLP.

## Production preflight (сейчас NO_GO, только после отдельного owner approval)

1. Проверить фактическую эксплуатационную приёмку H-01 #33 и отдельное разрешение владельца на **конкретные** agent/tool hooks, категории метрик, получателя, пределы сети/ОС и конфиденциальность. Active timer или один exit0 не являются GO.
2. Закрепить exact main SHA + CI, границы данных и независимый sanitizer **до SDK**, запрет prompt/response, tool args, OAuth/JWT/API secrets, user IDs, paths, file content и exception stacks; провести отрицательные canary-exfiltration тесты на НЕПРИВАТНЫХ фикстурах.
3. В изолированном pre-production окружении проверить раздельные OTLP signal request bodies, безопасный collector с явным approval, а также таймауты, HTTP 413/429/500, переполнение, отключение сети, повторы и потерянные данные без зависимости бизнес-операций от telemetry.
4. Измерить реальные CPU/RAM/RSS/disk и p50/p95/p99 overhead, dropped-events, sampling coverage, ограничить очередь/retention и обеспечить безопасное удаление. Ненаблюдаемые значения - UNKNOWN/NOT_MEASURED, а не 0.
5. Убедиться, что Ops Watch/SQLite и Control Center остаются существующими источниками истины, новая OTEL event DB/UI/service не создаётся, а security permission/OS/egress guards по-прежнему fail-closed.
6. Подготовить rollback к точной исправной версии с `telemetry_enabled=false`, после разрешённого включения проверить снятие hooks/exporter, отсутствие новых endpoints/служб, сохранность H-01/Ops Watch и отсутствие секретов в отчётах. Только после отдельного GO допустим staged rollout.

**Статус:** source-only ready, runtime/collector/exporter NOT_RUN, #192 OPEN до обязательных эксплуатационных критериев.
