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

Экспортёр здесь **не отправляет** OTLP: он возвращает **`otlp_json_candidate`** с полями `resourceSpans`/`resourceMetrics`, пригодными для review структуры, но не протестированными с официальным OpenTelemetry collector/schema. Отдельные поля `review` не являются частью OTLP и явно фиксируют неизвестные cost/tokens/live authenticity и запрет runtime.

- Разрешённые `tool`: `ops_watch`, `qa_advisor`, `research_scout`, `other`. Для `kind=turn` tool только `null`.
- Лишь числовые длительности, число попыток/повторов, ограниченный размер вывода и строгие enum типов ошибок, budget/status, trace completeness. Не принимать произвольные имена tools, команды, пути, URL, стек исключения, payload, prompt/response, токены, идентификаторы пользователя и аргументы.
- `duration_ms=null` → нет gauge point/span и инкремент `unknown_duration_events`; **не** подставлять 0. `duration_ms=0` — допустимый фактически известный *синтетический* ноль. Cost/tokens всегда unknown, независимо от `budget_state`.
- Trace/span IDs детерминированы из source SHA + индекса посредством hashlib; временная метка — фиксированная **синтетическая** epoch. Они не являются доказательством живой корреляции, измерения времени, провайдерского ответа или аутентификации.
- Error/status не принимает свободный текст. Счётчики содержат только ограниченные категории; scope не включает private identifiers.
- Любое нарушение schema/types, повтор JSON-ключа, размерное превышение или неизвестный enum → полностью `REFUSED` (CLI exit code 2), без частичных traces.
- Не более **16 KiB** вход, **32 events** / batch, **64 KiB** выход, не более 600 секунд на фиктивный turn, не более 16 KiB фиктивного output size, 3 attempts, `sample_stride` 1..16.
- Sampling deterministic (по порядковому номеру фикстуры, не по пользователю), drop-on-overflow = отказ всего синтетического batch, а не выборочная усечённая выборка. Runtime instrumentation **не интегрирована**, поэтому ошибки этого инструмента не способны остановить существующую production задачу.
- Output формируется в памяти и печатается в stdout **только при прямом явном offline запуске**. Файлы не создаются, сетевых соединений нет, таймеры не добавляются, retention не настраивается. Future production sampling/retention/drop thresholds нуждаются в CPU/memory/disk замерах с отдельным GO.

## Security/production gate

Нельзя импортировать этот fixture builder в Ops Watch/Research Scout/Control Center/H-01 без отдельной правки и preflight. Никаких `pip install opentelemetry-*`, collector, OTLP endpoint, network port, PID tracing, env-probing, автоматических прав ОС/CLI либо новых секретов.

До любой production-инструментации требуются: (#33) подтверждённый live runtime; owner approval exact resource/tool boundary; отдельный policy-sanitizer перед SDK; negative exfiltration tests на реальных gateway traces; bounded ingress/sampling/retention; CPU/RAM/disk overhead и drop counters; доказанный fail-open для telemetry только (не для guard/security); protected OTLP exporter; rollback и совместимость с Ops Watch/SQLite без второго источника истины.

## QA / Release

```sh
python3 -B -m unittest tests.test_h25_otel_offline -v
```

Проверяются synthetic trace/metric success, unknown!=zero, redaction, sample stride, лимиты, неверные поля, injection, max batch, repeatable output. Github CI на exact PR SHA обязателен; при доставке в `main` это **source snapshot only**, без включённого exporter. При отсутствии отдельного owner GO #192 остаётся OPEN на real runtime и overhead testing.

Related: [#192](https://github.com/MikeMoore1337/hermes/issues/192), [#33](https://github.com/MikeMoore1337/hermes/issues/33), [#470](https://github.com/MikeMoore1337/hermes/issues/470). Никакие BRC/Windows workstreams не затрагиваются.
