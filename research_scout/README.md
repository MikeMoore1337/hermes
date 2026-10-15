# Hermes Research Scout - offline evidence gate

Status 15.10.2026: **daily public metadata research collector active on VPS**; offline evidence gate also operates. No AI model calls, no external reporting, no automatic publication or YFC/Second Brain writes. Partial progress for [Issue #4](https://github.com/MikeMoore1337/hermes/issues/4).

This deliberately does not copy code from VIBE-SERCH or other repositories
with unclear licences. Uses Python standard library.

Input consists of untrusted source metadata in a strict schema:
`url`, `title`, `published_at`, `claim_id`, `polarity`,
`summary`. Unknown keys, credentials, redirect targets or opaque data are
rejected. URL allowlist is exact HTTPS host-based and does **not** authorize
fetching: redirects/DNS and effective egress would require a separate hardened
connector with SSRF proof.

What this stage actually does:
- mark secondary vs primary domain (never proof of publication authenticity);
- quarantine stale/future items, suspicious instruction-like content and
  contradictory claim metadata;
- reject duplicate URLs and require independent primary **domains** before
  a claim can reach human review (domain independence is only a heuristic);
- emit bounded link/title/provenance metadata, not source summaries or secrets;
- return `NO_DATA`, `HOLD` or `READY_FOR_REVIEW`, never `verified=true`.

This stage does **not** verify the truth or factual independence of studies.
Even `READY_FOR_REVIEW` is NOT permission to publish to Telegram/YFC,
change a fitness recommendation, send a message or store in Second Brain.

Follow-up gate: independent manual assessment of original study methods, DOI/PMID/license, evidence citations and human-approved research delivery. Fixed public source clients, timeout/size limits and 20+ negative cases exist; keep #4 OPEN until scientific review and outgoing channel are separately authorized.


## Матрица негативных случаев (14.10.2026)

[Набор сквозных синтетических проверок](../tests/test_research_safety_matrix.py) покрывает 29 отдельно названных отклонений URL/SSRF, схемы, контрольных символов, дат, правдивости заявлений и внедрённых команд. Дополнительно проверяются многоязычные инструкции, приоритет причины при stale+injection, ложная независимость доменов и противоречия.

CI подтверждает только офлайн-защиту. Актуальность реальных исследований, NCBI registration, общая квота IP и live API остаются в статусе OPEN в [#4](https://github.com/MikeMoore1337/hermes/issues/4). `READY_FOR_REVIEW` и `MANUAL_REVIEW` не означают доказанный научный вывод и не дают разрешения публиковать материалы.


## Альтернатива NCBI без регистрации

[Europe PMC: один защищённый запрос и актуальные тесты](EUROPE_PMC.md) - первичный публичный научный поиск без API-ключа/карты, проверенный на VPS 15.10.2026. Результаты сохраняют `MANUAL_REVIEW`/`HOLD`, никакой автоматической публикации. Старый NCBI pipeline не отключает новости YFC и не является обязательным условием для Europe PMC.


## Ежедневный автономный сбор открытых научных метаданных

[Протокол безопасности, установка и остановка](../docs/operations/H-03-DAILY-RESEARCH.md): отдельный ограниченный публичный сборщик, не более 3 фиксированных Europe PMC GET + 1 Crossref DOI lookup, 1 защищённый локальный JSON отчёт, без платных API, LLM, YFC/Second Brain, Telegram-рассылки или публикации. Scientific claims всегда `verified=false`; материалы `MANUAL_REVIEW` требуют проверки оригинала и согласования редактора. Никаких duplicate-source доказательств.


## Фактическая ежедневная работа на VPS

[Акт установки 15.10.2026](../docs/audits/H-03-research-digest-vps-2026-10-15.md): `hermes-research-scout.timer` включён, отдельная root-only служба в проверенном sandbox, 3 темы и максимум 4 публичных GET в сутки. Первый ограниченный отчёт содержит 4 кандидата, 1 зарегистрированный DOI Crossref, 0 ошибок; [правила отчёта и отката](../docs/operations/H-03-DAILY-RESEARCH.md). Это не означает доказанные рекомендации для тренировок и не даёт разрешения публиковать.


## Проверка содержания первых четырёх записей (15.10.2026)

[Ручной обзор с официальными ссылками и ограничениями](../docs/audits/H-03-first-science-candidates-2026-10-15.md): найдена официальная correction к исследованию IRONMAN (значение 50 -> 150 мин/нед), отсутствие DOI в Europe PMC при наличии DOI в PubMed для обзора whey, одна низкорелевантная общему продукту клиническая работа, отсутствие доказанного функционального преимущества CRET, неоднородность обзора 36 вмешательств. **Ни одна публикация не получила разрешение на автоматическое внедрение в YFC или Telegram.**


## Проверка исправлений и отзывов статей по официальным метаданным

[Одноразовая процедура](../docs/operations/H-03-ARTICLE-INTEGRITY.md) - один ограниченный `Europe PMC /article/MED|PMC/id?format=json&resultType=core`. Подтверждена форма ответа `commentCorrectionList` для IRONMAN; если есть исправление или отзыв, статус `HOLD`, а отсутствие поля **не означает**, что статья гарантированно не исправлялась. Статья `PMC13639859` осталась без DOI в данной PMCID записи, хотя DOI опубликован в PubMed: `HOLD` до корректного связывания идентификаторов. Прямые изменения YFC/новостей/существующего ежедневного Research Scout отсутствуют.


### Приёмка дополнительной проверки в ежедневном отчёте

Research Scout безопасно анализирует `commentCorrectionList` максимум у **одного** кандидата за цикл (тот же, чей DOI проверяется через Crossref). Автоматически выявленное исправление, отзыв или неизвестный тип - `HOLD`; остальные публикации **не считаются проверенными** (`NOT_CHECKED`). Ограничение теперь до 5 публичных запросов на запуск; публикаций, платных API и моделей нет. [Правила](../docs/operations/H-03-DAILY-RESEARCH.md).
