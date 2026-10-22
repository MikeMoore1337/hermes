# H-28 / #465 — Self-Evolution: проверяемая офлайн-регрессия одного описания

**Решение:** `KEEP` безопасный синтетический regression harness; `DEFER`
исполнение настоящих моделей/оптимизатора; `NO_GO` self-modification,
автоматический commit/PR/merge/deploy, расширение прав и платные API.

## Источники и существующие владельцы интерфейсов

Методический ориентир:
[NousResearch/hermes-agent-self-evolution](https://github.com/NousResearch/hermes-agent-self-evolution)
`main@0a929e3aa20e15cf04dc7c28492a7d41a5139125`,
`README.md@c59f9a6a57e36edbc2aae6b76aeee2e4878e63a8`.
README указывает MIT и что **реализована только Phase 1 (skills)**;
эволюция описаний инструментов, system prompts, tool code и continuous
evolution — планы. README сообщает о примерных **$2–10 за API-run**:
это несовместимо с действующим owner zero-extra-cost policy.

Никакие файлы, исходники, DSPy/GEPA, истории сеансов и prompt examples
из upstream не копировались и не исполнялись. MIT claim в README —
не основание для заимствования непроверенных отдельных файлов.
Весь корпус ниже создан для Hermes и **полностью вымышленный**.

| Существующее решение | Граница |
| --- | --- |
| [#349](https://github.com/MikeMoore1337/hermes/issues/349), `eval_lane/` | Реальные paired-model trials **запрещены** owner zero-cost gate; это не bypass |
| [#273](https://github.com/MikeMoore1337/hermes/issues/273), `hermes_benchmark/` | Существующий baseline для agent task lifecycle, не дублируется |
| [#432](https://github.com/MikeMoore1337/hermes/issues/432), `.agents/skills/` | Только development references; ни один файл не меняется |
| [AI Development Toolkit](https://github.com/MikeMoore1337/ai-development-toolkit) | `ai-engineering-qa`, `test-analysis-design`, `quality-gate-assessment`; Toolkit остаётся read-only |
| [#476](https://github.com/MikeMoore1337/hermes/issues/476), `hermes_decision_eval/` | Выбор между А/B/AB; здесь **измеряется одинаковое наблюдаемое поведение трёх версий** одного описания |

Новый `hermes_skill_delta/` — только namespace тестов. Он **не**
Skill Manager, registry, agent loader, deployment service или модельный judge.

## Эксперимент (фиксированные версии и входы)

Три **синтетические** версии описания единственной операции
`qa-evidence-summary` (никогда не подключённой к настоящим MCP/tool APIs):

- `baseline@v1` — читает receipt, owner gate, но ошибочно не проверяет,
  что SHA из CI/merge/deploy совпадает с нужным.
- `revised@v2` — сохраняет read-only scope, добавляет exact target SHA;
  отклоняет ложный CI/merge/deploy, сохраняет неоднозначность как UNKNOWN.
- `regressed@v3` — специально вредная **неактивируемая** фикстура:
  расширение полномочий `shell.exec`, новый dependency, write-effect,
  доверие self-claims и попытка убрать approval.

В `hermes_skill_delta/cases.py`: 12 синтетических задач на RU и EN,
включая подтверждённый CI PASS, CI FAIL, устаревший SHA, необоснованное
заявление успеха, недоверенный источник, несуществующий merge/deploy,
отсутствующее разрешение владельца и корректную полную цепочку receipt.
Каждый case содержит явный `expected`, написанный **независимо** от
тестируемого обработчика.

Верификация **наблюдаемого поведения**, не keyword matching:
входы — типизированные mock receipts (`issuer`, `kind`, `result`,
`sha`) и неподтверждённые `claims`; decision выводится
детерминированным read-only evaluator. RU/EN `request` сохраняется
как context, но не используется как доказательство. Тест специально
меняет формулировку на «CI PASS», «ДЕПЛОЙ СДЕЛАН» и убеждается,
что без receipt статус остаётся UNKNOWN. Строки
`github-actions`, `github`, `hermes-deployer` и `source_sha=f*40`
**являются только именами вымышленных объектов**, не проверенными
GitHub approvals, криптоподписями, правами владельца или реальным SHA.

`contract_gate` ДО эмуляции кандидата блокирует дополнительные
permissions, effects, dependencies, превышение 300 байт описания
и ослабление trust/owner boundary. Заблокированная версия имеет
`not_run=12` и **не выдаётся за 0/12 реальных ошибок**.

## Отчёт и критерий приемки

`hermes_skill_delta/core.py` сравнивает **один и тот же** набор SHA256
и одного и того же независимого oracle с baseline, revised, regressed:

| Variant | Контракт | Synthetic outcome |
| --- | --- | --- |
| baseline | Допущен как исходный read-only | 9/12 корректно, 3 ошибки stale SHA |
| revised | Допущен к **рассмотрению**, не активации | 12/12 корректно, `IMPROVED` (+3) |
| regressed | Запрещён ещё до эмуляции | `REGRESSED / BLOCKED / NOT_RUN` |
| baseline против самого себя | Сравнение без изменений | `NO_GAIN` |

Синтетические PASS не доказывают, что модель реально стала точнее,
что промпт стал лучше при живой генерации, что разрешение owner
подписано или что эффективность статистически значима.
`MODEL_EFFECTIVENESS=NOT_MEASURED`,
`MODEL_CALLS=0`, `PROVIDER_COST=UNKNOWN`.
Описание «revised» — только **кандидат для ручного анализа**,
не новый зарегистрированный Hermes skill.

Дополнительно: независимый verifier должен уличать специально
изменённый expected/receipt, ограничение текста, scope/cost,
ложные выводы о доставке и попытку скрытой записи. Отчёт хранит
`dataset_sha256`, отдельный `variant_sha256`, версию и фактическую
таблицу ошибок, без оригинальных private prompts/agent logs.
Показатели времени, реальные токены и live-effectiveness не замерялись.

```bash
python3 -m unittest tests.test_hermes_skill_delta -v
python3 -m hermes_skill_delta.core --sha "$(git rev-parse HEAD)"
python3 -m hermes_skill_delta.core --format json
```

В существующий `quality.yml` добавляется только офлайн-шаг.
Нет нового GitHub required check, секретов или runtime-трафика.
**Решение о любом действительном изменении skills или промптов
потребует нового человеческого review и отдельного PR** (Toolkit
меняется только в его репозитории). Production source deploy
означает доставку тестов, а не применение новых инструкций.
