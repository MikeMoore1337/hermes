# H-02: Ops Incident Advisor

**Статус на 15.10.2026: `MOCK_ONLY`, локальный прототип, production не менялся.**

Ops Incident Advisor получает уже подготовленное обезличенное событие Ops Watch и
объясняет его оператору. Он не собирает события, не отправляет уведомления, не
перезапускает службы, не делает deploy/rollback и не заменяет Ops Watch.

## Контур

```text
подготовленное событие Ops Watch
  -> allowlist и нормализация
  -> контекст без свободного текста и секретов
  -> Hermes Agent -z, toolsets=[]
  -> локальный OpenAI-compatible mock provider
  -> проверка JSON и происхождения evidence
  -> рекомендация оператору без автоматического действия
```

Входная схема `hermes-ops-incident-v1` содержит только тип, источник, время,
состояние службы, код ошибки, повторения, предыдущий аналогичный сигнал,
состояние восстановления и ограниченные технические метаданные. Неизвестные
поля, `operator_note`, логи, токены, ключи, персональные данные и данные
Second Brain отклоняются до вызова агента.

Выход обязан содержать `what_happened`, `impact`, `probable_cause` с
неопределённостью, `evidence`, `checks`, `recommendation`, `priority` и
`status`. `evidence` принимается только как подмножество каталога фактов
входного события. Выдуманные доказательства и заявления о выполненных
побочных действиях блокируются.

## Запуск

Один реальный локальный агентный прогон через Docker:

```powershell
py -3.14 -m scripts.ops_incident_advisor --scenario provider_http_429 --engine docker
```

Повторяемая матрица без Docker и без модели:

```bash
python3 -m scripts.ops_incident_advisor --all --engine offline --json
```

`offline` использует тот же контракт и детерминированный mock-ответ, но явно
помечает путь как `NOT_RUN: in-process mock only`. `docker` запускает настоящий
CLI Hermes из локального изолированного образа и принимает ровно один запрос к
локальному mock provider.

Пример входа:

```json
{
  "schema": "hermes-ops-incident-v1",
  "incident_type": "provider_rate_limited",
  "source": "provider",
  "detected_at": "2026-10-15T12:04:00Z",
  "service_state": "degraded",
  "error_code": "HTTP_429",
  "repeat_count": 5,
  "previous_similar": false,
  "recovery_state": "active",
  "technical_metadata": {
    "component": "workers-ai",
    "environment": "synthetic",
    "active_codes": ["provider_rate_limited"],
    "provider_status": 429
  }
}
```

Сокращённый пример результата:

```text
Что произошло: Ops Watch зафиксировал событие типа provider_rate_limited.
Вероятная причина: Получен HTTP 429; по событию нельзя различить квоту и временную ёмкость провайдера.
Что проверить: Проверить квоту и окно ограничений провайдера без нового запроса.
Рекомендация: ... автоматических действий не делать.
Приоритет: high
Статус инцидента: active
```

## Проверенные сценарии

| Сценарий | Ожидаемая интерпретация | Offline-контракт | Hermes Docker |
| --- | --- | --- | --- |
| Telegram sender не работает | активный критичный сбой отправителя | PASS | NOT_RUN |
| Таймер systemd завершился с ошибкой | активный критичный сбой запуска | PASS | NOT_RUN |
| Служба исправна, публикаций нет | доступность не нарушена | PASS | NOT_RUN |
| Очередь уведомлений остановилась | деградация, проверить drain/backlog | PASS | NOT_RUN |
| Провайдер HTTP 429 | активное ограничение провайдера, причина не различена | PASS | PASS |
| GitHub Actions завершился с ошибкой | деградация CI | PASS | NOT_RUN |
| Повторный одинаковый инцидент | повышенная срочность по повторениям | PASS | NOT_RUN |
| Восстановление после сбоя | восстановление подтверждено входным состоянием | PASS | NOT_RUN |
| Несколько одновременных проблем | критичный агрегированный сигнал | PASS | NOT_RUN |
| Недостаточно сведений | `insufficient_data`, без догадки о причине | PASS | NOT_RUN |
| Некорректные входные данные | отклонить до модели | REJECTED | NOT_RUN |
| Prompt injection во входе | отклонить свободное поле до модели | REJECTED | NOT_RUN |

Offline-проверка оценивает форму, полноту evidence, соответствие ожидаемому
status/priority, отсутствие неподтверждённых утверждений и повторяемость.
Для mock-провайдера `evidence_completeness=1.0`, `unsupported_evidence=[]`,
`llm_quality=NOT_RUN`: это не оценка качества настоящей LLM.

Фактический Docker-прогон 15.10.2026 для `provider_http_429` прошёл через
`/opt/hermes/.venv/bin/hermes -z`, без tools, с `model_calls=1`; один сэмпл
Docker Stats дал 35.62 с, пик 31.32% CPU и 371 MiB RAM. Это измерение одного
синтетического запуска, а не нагрузочный benchmark. Использован локальный
patched derivative `hermes-agent-v0221-native-tool-policy:20261015`, а не
утверждение о наличии патча в официальном upstream-образе.

## Ограничения контура

- input до 16 KiB, output до 32 KiB, wall-clock до 45 секунд;
- один запрос модели, `api_max_retries=1`, auto-recovery отключён, auto-title отключён;
- Docker: `--network none`, read-only root, non-root UID, все capabilities dropped,
  `no-new-privileges`, 96 процессов, 0.30 CPU, 640 MiB RAM и 896 MiB swap;
- `/tmp` и `/run` - отдельные ограниченные tmpfs; mount содержит только staged
  `ops_watch` и конфигурацию без credentials;
- mock provider не вызывает сеть и не имеет tools; ответ не является доказательством
  качества Cloudflare или другой реальной модели.

Статус Cloudflare Workers AI: `LIVE_BLOCKED`. Аккаунт владельца и фактический
Workers Free plan не подтверждены, токен не запрашивался, живой запрос и платный
fallback не выполнялись. Для #62 остаётся точное действие: владелец проверяет в
Cloudflare Dashboard Free plan, аккаунт, модель и отсутствие billing gateway;
до этого реальные запросы запрещены.

## Сравнение с Ops Watch

Ops Watch остаётся детерминированным источником фактов, кодов инцидентов и
уведомлений. Advisor добавляет только человекочитаемое объяснение, явную
неопределённость, безопасный список проверок и приоритет. Он не добавляет новый
сборщик или recovery-контроллер. Практическая добавленная ценность настоящей
модели пока `NOT_RUN`; текущий доказанный результат - воспроизводимый и
ограниченный агентный путь, а не доказательство, что LLM лучше правил.

## Приёмка и следующий шаг

Владельцу нужно отдельно проверить PR функциональности и разрешить его merge;
merge security PR #132-#135 также не выполнялся. Для live-модели нужен отдельный
owner-approved пилот после подтверждения #62 и сохранения нулевого бюджета.

Приоритет следующих функциональных задач:

1. Провести owner review/merge PR с read-only адаптером; этот документ не
   разрешает подключение production snapshot или отправку.
2. Выполнить один owner-approved `LIVE_FREE_VERIFIED` пилот Cloudflare с теми же
   лимитами и сравнением с правилами.
3. Добавить измерение реальных операторских решений по нескольким инцидентам;
   не считать синтетические сценарии real-user evidence.

Постоянный Hermes Agent и Issue #33 остаются `OPEN / NO-GO`.

## Read-only адаптер фактических Ops Watch событий

`ops_watch.advisor_adapter` читает только уже существующий локальный snapshot
`incidents.sqlite3` через `state_store.inspect`. Он не создаёт базу, не пишет
события, не ACK-ает очередь, не отправляет Telegram и не выбирает production
каталог автоматически. Каждая запись повторно проверяется по фиксированному
каталогу `INCIDENT_CODES`, заголовку, действию, фазе, severity и timestamp.

Проверка локальной read-only копии (без модели):

```bash
python3 -m scripts.ops_incident_advisor \
  --ops-watch-db ./local-ops-watch-snapshot \
  --provenance readonly_snapshot \
  --event-id 123 \
  --engine offline --json
```

Восстановленное событие получает `RULES_ONLY`; повторяющееся или контекстно
сложное событие получает `ADVISOR_CANDIDATE`. Недоступная, неизвестная или
подменённая запись получает безопасный отказ. `anonymized_copy` и `synthetic`
разрешены только как явные метки происхождения; они не становятся
production/real-user evidence.

## Базовые правила и bounded runtime

Для subprocess используется bounded helper из PR #132: stdout ограничен 64 KiB,
stderr 16 KiB, wall-clock 45 секунд, дерево процесса завершается при timeout,
а наружу выходит только санитизированный код ошибки. Финальный Advisor output
остаётся ограничен 32 KiB. Семантический валидатор дополнительно запрещает
несовместимый с событием status, завышенный priority, `low` uncertainty при
неподтверждённой причине, неподтверждённые claims о влиянии и диагностические
действия с restart/deploy/send/delete.

Эти проверки измеряют детерминированные инварианты и происхождение evidence,
но не качество настоящей модели: `expert_review=NOT_RUN` и
`llm_quality=NOT_RUN` сохраняются.

## Performance smoke, 15.10.2026

Измерялся внешний wall-clock команды для одного синтетического сценария
`provider_http_429`; внутренние этапы отдельно пока не инструментированы.

| Прогон | Результат | Время | Model calls |
| --- | --- | ---: | ---: |
| Offline matrix, 12 cases | PASS, 10 accepted + 2 rejected | 0.182 s | 0 |
| Docker cold | `child_timeout` | 45.393 s | unknown |
| Docker warm 1 | PASS | 35.304 s | 1 |
| Docker warm 2 | PASS | 34.141 s | 1 |
| Docker warm 3 | PASS | 34.801 s | 1 |

Успешная медиана трёх warm-прогонов — 34.801 с; cold timeout не является
успехом и не скрывается. Отдельные стадии `input preparation`, staging/temp
config, Hermes init, mock provider, response handling и cleanup имеют статус
`NOT_INSTRUMENTED`; замер Docker-команды включает их суммарно. По этим данным
ускорение относительно прежнего единичного сэмпла 35.62 с не доказано:
выборка мала, а cold запуск упёрся в лимит. Это не load test и не production
SLO.

## Сравнение с детерминированными правилами

```bash
python3 -m scripts.ops_incident_advisor --compare --engine offline --json
```

Команда сравнивает 10 валидных synthetic cases; invalid/prompt-injection
cases в сравнительную матрицу не включаются. При `offline` используется только
локальный mock path, поэтому строки помечаются `MOCK_ONLY`, а практическая
ценность AI — `NOT_PROVEN`; live provider и операторская оценка остаются
`NOT_RUN`.

## Уточнение после функционального ревью (15.10.2026)

Журнал SQLite `events` сохраняет только переходы `new` / `resolved`, а не
каждое наблюдение или попытку. Поэтому read-only адаптер **не вычисляет число
повторов по количеству одинаковых кодов среди последних 50 записей**:
этот способ смешивал восстановление с отдельными эпизодами. `repeat_count=1`
для перехода `new`, `repeat_count=0` для `resolved`, а
`previous_similar=false`, пока настоящий источник не передаст проверенные
счётчики повторных наблюдений. Порог повторов не включается на основании
истории переходов. Это намеренно консервативное поведение, а не потеря
достоверно известных повторов.

При единственном результате `RULES_ONLY` текстовый CLI показывает
`status`, `priority` и фактическую рекомендацию Ops Watch без фиктивной
ошибки `unknown`. Исполнение агента по-прежнему не требуется.

Исходные библиографические источники Research Scout и проверенный вручную
фрагмент полного текста различаются отдельно в
`research_scout/review_draft.py`; реальная научная экспертиза остаётся
`MANUAL_REVIEW`.
