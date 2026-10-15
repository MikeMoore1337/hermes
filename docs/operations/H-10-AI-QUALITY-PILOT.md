# H-10 — офлайн-пилот качества Hermes AI

**Текущий статус:** интерфейс и эталонные случаи подготовлены; реальная LLM — `NOT_RUN`; тариф конкретного Cloudflare аккаунта — `ACCOUNT_FREE_UNVERIFIED`.

## Локальный запуск

Команды не требуют токена и не выполняют сетевых запросов:

```text
python3 -m scripts.hermes_ai_pilot status
python3 -m scripts.hermes_ai_pilot cases
python3 -m scripts.hermes_ai_pilot compare --json
python3 -m scripts.hermes_ai_pilot prepare-live
python3 -m scripts.hermes_ai_pilot run --engine mock --case ops:provider_http_429 --case research:whey_gut_brain --json
```

`compare` запускает весь локальный набор и сохраняет sanitized результаты в `.artifacts/hermes-ai-pilot/results.json`, который не входит в Git. `run --engine mock` использует тот же контракт входа/выхода, но детерминированный ответ из Python. Это проверяет контур и валидаторы, **не качество AI**.

## Эталонный набор

Ops Incident Advisor: `telegram_sender_down`, `systemd_timer_failed`, `notification_queue_stopped`, `provider_http_429`, `github_actions_failed`, `recovery_after_failure`, `multiple_incidents`, `healthy_no_publications`, `insufficient_data`, `contradictory_state`, `unknown_error_code`, `prompt_injection`. Все входы synthetic и содержат только allowlisted факты. Существующие фикстуры `repeated_same_incident` и `invalid_input` сохранены для регрессии прежнего Advisor, но не являются частью этого 12-case пилота.

Research Scout: публичные библиографические записи для обзора растительных продуктов и восстановления, whey/gut-brain, IRONMAN с correction и massage/CRET. В prompt передаются только уже сохранённые metadata и публичная ссылка; ручной эталон хранится отдельно и не выдаётся модели как готовый ответ.

## Что измеряется

Каждый результат хранит provenance, статус, модельный режим, число вызовов и раздельные времена подготовки входа, Docker/Hermes (`NOT_RUN` для in-process интерфейса), ответа провайдера, JSON-валидации, формирования результата и всего процесса. Для наблюдаемого live-ответа дополнительно сохраняются только фактически возвращённые input/output tokens, Neurons, HTTP status и стоимость. Если стоимость не возвращена, она остаётся `COST_NOT_VERIFIED`/`None`, без оценки по прайсу.

Для Ops сравниваются существующие правила с валидированным Advisor-ответом: статус, приоритет, доказательства, безопасные проверки и полезность рекомендации. Для Research сравниваются идентификаторы, дисциплина `UNKNOWN`/`INSUFFICIENT_EVIDENCE`, тип/популяция/выборка/вмешательство/контроль/результаты/ограничения/correction и ручной эталон. На одних библиографических metadata научная точность и экспертное утверждение имеют статус `NOT_ASSESSABLE_FROM_BIBLIOGRAPHIC_METADATA` и `NOT_RUN`.

Итоговая таблица до live-запуска имеет вид:

| Задача | Правила или ручной эталон | Mock | Реальная LLM | Время | Качество |
| --- | --- | --- | --- | --- | --- |
| каждый Ops/Research case | READY | `MOCK_ONLY` | `NOT_RUN` | фактически измерено локально | mock не является доказательством качества |

## Финансовый и сетевой ограничитель

В `agent_budget/pilot.py` зафиксированы:

- основной model ID `@cf/openai/gpt-oss-20b`;
- по одному вызову на случай и не более трёх случаев за один live-запуск;
- максимум три live-вызова за сутки по локальному UTC-счётчику;
- ноль автоматических повторов и ноль model fallback;
- отсутствие фонового и параллельного выполнения;
- фиксированный HTTPS host/path Cloudflare, запрет redirect и proxy;
- вход до 16 KiB, выход до 32 KiB, `max_tokens=768`, timeout 45 секунд;
- обязательный `options.rejectIfBusy=true`;
- консервативный резерв 1 000 Neurons в account-status attestation;
- остановка на 401/402/403/429, timeout, недоступности, невалидном JSON, неизвестной схеме или неизвестной стоимости;
- отсутствие инструментов, публикации, Telegram, приватных данных и side effects.

Токен сам по себе не включает live-режим. Нужны одновременно `--owner-approved`, `HERMES_AI_LIVE_APPROVED=1`, внешний account-status JSON с `WORKERS_FREE`, fixed model, SHA-256 Account ID, остатком квоты и `ai_gateway_unified_billing=false`. Account JSON и секреты не коммитятся.

## Подготовка первого live-сценария

Команда подготовки ничего не вызывает:

```text
python3 -m scripts.hermes_ai_pilot prepare-live
```

После отдельного письменного разрешения владельца и независимой проверки Dashboard допускается только один явный case (не `--all`), например:

```text
python3 -m scripts.hermes_ai_pilot run --engine live --case ops:provider_http_429 --owner-approved --account-status <внешний-файл> --output .artifacts/hermes-ai-pilot/results.json
```

Перед этим секреты задаются владельцем в его защищённой среде, не через чат и не в Git. В текущем задании эта команда не выполнялась.

## Приёмка и остаток

Реализовано: единый offline/live-контракт, ограничитель вызовов, 12 Ops и 4 Research cases, сохранение sanitized результатов, сравнение с правилами/ручными reference и отрицательные тесты. Не доказано: качество настоящей LLM, фактические Neurons/стоимость, реальный Workers Free, Docker startup/инициализация Hermes для этого нового общего CLI, production readiness, PR/CI и обновление GitHub Issues.


## Research Scout: проверка на публичном реферате (16.10.2026)

Добавлены четыре научных сценария для проверки по подтверждённым фактам публичных рефератов (пятый-восьмой в Research наборе): plant_recovery_public_abstract, whey_gut_brain_public_abstract, ironman_correction_public_abstract, massage_cret_public_abstract.
Оригинальный plant_recovery остаётся строго metadata_only: вид исследования,
выборка и результаты не выводятся из названия.

Сценарий plant_recovery_public_abstract содержит 8 вручную сверенных кратких пересказов публичного
реферата PubMed PMID 42797032 (DOI 10.3390/nu18183049). Это не полный
текст и не экспертное научное заключение. Каждое научное поле с содержанием
требует field_evidence с допустимым идентификатором F1-F8.
Число исследований не превращается в количество участников:
sample_size=UNKNOWN; correction_status=UNKNOWN пока не проведена проверка.

Происхождение и допустимые идентификаторы проверяются детерминированно;
семантическая точность ответа остаётся NEEDS_EXPERT_REVIEW.
Публикации и изменения YFC/Second Brain запрещены.

Offline:
python3 -m scripts.hermes_ai_pilot run --engine mock --case research:plant_recovery_public_abstract --json
python3 -m unittest discover -s tests -p test_research_abstract_quality.py

Реальный запрос не выполняется до сброса дневного лимита UTC.


### Стоимость не возвращена в API - сохраняем результат, останавливаем вызовы

На Workers Free API может вернуть успешный валидированный ответ без
поля фактической стоимости. Такой ответ не должен теряться:
результат и оценка проверки сохраняются с status=BLOCKED,
validation_status=PASS, model_execution=LIVE_OBSERVED_COST_NOT_VERIFIED.
При этом запуск **немедленно прекращается**, второй case не выполняется.
Статус стоимости COST_NOT_VERIFIED, а не доказанные нулевые расходы.
Это позволяет изучить один ответ настоящей модели, не ослабляя ограничитель.


## Остальные три исследования, офлайн-проверка (16.10.2026)

Следующие записи находятся в ручном исходном каталоге Research Scout, а
не подгружаются тайным сетевым вызовом:

- whey_gut_brain_public_abstract: PubMed PMID 42840492,
  DOI 10.3389/fcimb.2026.1918695. Обзор механистических и клинических
  сведений, НЕ новое совместное клиническое исследование. Доказательств
  улучшения когнитивных функций от одновременных сывороточного белка и
  силовых тренировок пока недостаточно.
- ironman_correction_public_abstract: PubMed PMID 42771055,
  DOI 10.1007/s00520-026-11251-3. Наблюдательный регистр с 2485 людьми
  и отдельным опубликованным исправлением DOI 10.1007/s00520-026-11294-6:
  умеренная физическая активность в описательном показателе исправлена
  с 50 на 150 минут в неделю. По заявлению издателя анализ и выводы
  не изменились. Исправление нельзя скрывать или подменять итоговым
  порогом рекомендаций >=150 минут, который измеряет другое.
- massage_cret_public_abstract: PubMed PMID 42733310,
  DOI 10.1002/ejsc.70246. Рандомизированное crossover исследование с
  25 спортсменами. Биомаркеры и УЗ-показатели изменялись, но
  убедительного улучшения восстановления силы/производительности нет.

Для каждого кейса сохраняются только публичные краткие пересказы
проверенных рефератов (F1-F8 в зависимости от сценария), DOI/PMID,
оригинальная публичная ссылка, отдельно DOI/url исправления, если
оно известно. Источник -- PubMed и открытый документ издателя
по IRONMAN: https://link.springer.com/article/10.1007/s00520-026-11294-6.
Точные ID фактов обязательны. Для установленного количества участников
требуется F2, для исправления IRONMAN -- F6, F7, F8. Отсутствие
фактов исправления в остальных статьях означает UNKNOWN, не 'нет'.

Всего эталонных случаев: **12 Ops + 8 Research = 20**.
Корректные ответы локального mock провайдера не доказывают качества LLM;
окончательная научная оценка остаётся HUMAN_REVIEW_REQUIRED.

Офлайн проверки:
python3 -m scripts.hermes_ai_pilot compare --json
python3 -m unittest discover -s tests -p test_research_abstract_quality.py

Никакой публикации, новых live Cloudflare запросов или смены
провайдера/тарифа в этом PR не выполнялось.
