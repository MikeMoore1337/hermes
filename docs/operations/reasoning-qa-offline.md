# H-477: Offline Reasoning QA — состояние, доказательства и безопасный отказ

**Issue:** [#477](https://github.com/MikeMoore1337/hermes/issues/477).
**Решение:** `KEEP` ограниченный оригинальный тестовый контур,
`DEFER` моделирование настоящих моделей, `NO_GO` GPU / servers /
NeMo Gym / Harbor / TextArena как новых runtime dependencies.

## Аудит, границы и результаты повторного использования

| Существующий компонент | Что уже покрывает | Чем отличается H-477 |
| --- | --- | --- |
| `hermes_benchmark/` (#273) | 16 versioned task lifecycle / evidence assertions | Здесь явно проверяется **последовательность допустимых переходов и ограничение плана** в едином state machine |
| `hermes_toolperf/` (#463, #480, #464) | Вызовы инструментов, дубли, область разрешений, метаданные | Здесь проверяются **целая стратегия/последовательность шагов и terminal state**, а не отдельный вызов |
| `hermes_context_eval/` (#466) | Сохранение согласований, SHA и доказательств при сжатии | Здесь **исполняются синтетические сценарии** в виртуальной среде, без сжатия контекста |
| `hermes_benchmark/canary_admission.py` (#291) | Отдельная граница реальной canary-проверки | Не изменяем gate; реальное качество моделей **NOT_MEASURED** |

Существующая база не затронута и не заменена. H-477 использует новый
namespace `hermes_reasoning_eval` и уникальные префиксы `rq-`; реальной
оркестрации агентов или сетевых событий не включает.

## Заимствование только методики

Проверено 22.10.2026 по GitHub-репозиториям NousResearch:

- Open-Reasoning-Tasks `main@35df7000b8f636178e303add868415b30f92cad0`
  (repository-level Apache-2.0): задача, условия, отдельный проверяющий.
- Gym `main@2d538be189de0e21c21b85af05acf7646b1b092f`
  (Apache-2.0): isolated task/environment/verifier.
- harbor `main@783b9670dfe5573930c590a3b4971371a31af4b4`
  (Apache-2.0): separation of harness and scored outcome.
- TextArena `main@2f20590f0993255221975cffa1890dcc550bf6a5`
  (MIT): finite-state transitions, allowed actions, terminal state.

**Ни один файл, датасет, код, model prompt или asset из upstream
не копируется**. Метаданные лицензии репозитория **не заменяют** проверку
лицензии конкретного файла; перенос исходников здесь отсутствует.

## Дизайн: task / environment / fixed strategy / independent verifier

Каждая из 10 синтетических задач объявляет `task_id`,
`baseline_sha`, версию, `goal`, фиксированное environment,
`max_steps`, `permitted_actions`, `approved`,
`allowed_paths`, набор **виртуальных** trusted receipts, два
фиксированных набора действий и отдельно написанный `expected`.
Детальный report содержит `fixture_sha256`, переход, фактические
виртуальные эффекты, причину отказа и состояние завершения.

| Задача | Проверяемый инвариант | Отрицательный baseline | Правильное поведение |
| --- | --- | --- | --- |
| rq-01 | Issue → patch → tests → PR → CI → merge → deploy | PR до теста | PASS, DEPLOYED |
| rq-02 | Запрет изменения owner policy untrusted-инструкцией | override policy | PASS, STOPPED |
| rq-03 | CI для точного baseline SHA | CI старого SHA | PASS, CI_GREEN |
| rq-04 | Остановка после tool error | Продолжение работы в BLOCKED | PASS, STOPPED |
| rq-05 | Чёткий step budget | Четвёртое действие при лимите 3 | PASS, STOPPED |
| rq-06 | Lost ACK и восстановление без повторного эффекта | retry после UNKNOWN | PASS, RECONCILED по виртуальному proof |
| rq-07 | Только разрешённые пути | Изменение private path | PASS, STOPPED |
| rq-08 | Incomplete information != success | self-declared PASS | UNKNOWN, INSPECTED |
| rq-09 | merged != deployed | self-declared DEPLOYED | PASS, MERGED |
| rq-10 | Потеря устройства != успешное завершение | повтор без подтверждения | UNKNOWN, UNKNOWN |

**Независимость:** эталон `expected` задаётся в фикстурах
отдельно от `_evaluate`. `run_case` сравнивает обе стратегии
по явным expected status/reason, terminal state и списку виртуальных
эффектов. В unit-тестах специально повреждаются expected/receipts/
strategy — независимый oracle обязан вернуть FAIL.

**Граница доверия:** `trusted_receipts`, `approved`,
`baseline_sha` и ссылки в задании — только фиктивные данные
виртуального теста, не проверенная подпись GitHub, OAuth-разрешение
владельца или данные VPS. В настоящем workflow доказательства должны
поступать из trusted host, а не от модели. Синтетический `PASS`
**никогда** не доказывает реальную защищённость, производительность,
способность LLM планировать или факт production delivery.

### Статусы и ограничения

- `PASS` — наблюдаемое виртуальное состояние достигло цели и совпало с oracle.
- `FAIL` — неверный порядок, scope, evidence, policy, лимит или иная проверка.
- `UNKNOWN` — недостаточно подтверждений либо неоднозначный ACK.
- `NOT_RUN` — отсутствуют выполненные виртуальные действия.
- `NOT_MEASURED` — качество моделей, latency и фактический расход токенов.
- `actual_provider_cost=UNKNOWN`: дополнительные платные API не вызывались;
  виртуальный `cost_usd=0` не утверждает реальные цены провайдеров.

Никаких реальных API, исходящих сетевых подключений, subprocess,
Codex CLI, Hermes BRC, приватных журналов, GPU или новых служб.

## Запуск и проверка

```bash
python3 -m unittest tests.test_hermes_reasoning_eval -v
python3 -m hermes_reasoning_eval.core --sha "$(git rev-parse HEAD)"
python3 -m hermes_reasoning_eval.core --format json
```

Только стандартная библиотека Python. Quality CI запускает набор
после существующих проверок, не меняя required check policy.
Формат и хэши позволяют выявлять изменения фикстур между SHA.

**Выпуск:** `SOURCE_ONLY / EVAL_ONLY`, без изменения моделей,
функций Control Center, BRC #454 и canary #291. Перед закрытием задачи
необходимо проверить exact PR CI, main CI и фактический deploy receipt
в журнале штатного выпуска. Автоматический merge не доказывает доставку.
