# Hermes Research Scout - offline evidence gate

Status 18.10.2026: **Research Scout v1 — owner-only read-only bibliographic collection and Control Center reporting, technically accepted**. No AI model calls, no automatic publication, no YFC/Second Brain writes. [Issue #4](https://github.com/MikeMoore1337/hermes/issues/4) is the **v1 technical delivery contract**; claim-level independent scientific verification is tracked separately in [Issue #317](https://github.com/MikeMoore1337/hermes/issues/317). [Final v1 technical acceptance](../docs/audits/H-03-RESEARCH-SCOUT-V1-ACCEPTANCE-2026-10-18.md).

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

Follow-up gate for **scientific claims**, not v1 metadata delivery: independent manual assessment of original study methods, DOI/PMID/license, effect sizes/CI, evidence citations and owner-approved external research delivery is [Issue #317](https://github.com/MikeMoore1337/hermes/issues/317). Fixed public source clients, timeout/size limits and 20+ negative cases exist; closing technical #4 does not approve scientific conclusions or any outward channel.


## Матрица негативных случаев (14.10.2026)

[Набор сквозных синтетических проверок](../tests/test_research_safety_matrix.py) покрывает 29 отдельно названных отклонений URL/SSRF, схемы, контрольных символов, дат, правдивости заявлений и внедрённых команд. Дополнительно проверяются многоязычные инструкции, приоритет причины при stale+injection, ложная независимость доменов и противоречия.

CI подтверждает только офлайн-защиту. Актуальность и доказательность отдельных исследований и permission на научную публикацию остаются в [#317](https://github.com/MikeMoore1337/hermes/issues/317); регистрация NCBI не требуется для уже разрешённого Europe PMC/Crossref v1. Реальные ограниченные API проверки выполнены, но не подтверждают беспрерывную доступность внешних каталогов. `READY_FOR_REVIEW` и `MANUAL_REVIEW` не означают доказанный научный вывод и не дают разрешения публиковать материалы.


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


### Дополнительный обратный поиск Crossref updates по DOI (ручной режим)

[Фиксированный reverse-update GET, коды и ограничения](CROSSREF_UPDATES.md) проверяет связанные DOI уведомлений **в обратную сторону** с помощью официального фильтра `updates`. Это устраняет покрытие, которое не обеспечивается одним `Crossref /works/{doi}`, и позволяет получить DOI коррекции/ретракции (если зарегистрирован у Crossref). Требует явного `--execute`, **не** подключён к ежедневному таймеру и не увеличивает лимит 5 GET; отрицательный результат не означает глобального отсутствия исправлений.

### Приёмка дополнительной проверки в ежедневном отчёте

Research Scout безопасно анализирует `commentCorrectionList` максимум у **одного** кандидата за цикл (тот же, чей DOI проверяется через Crossref). Автоматически выявленное исправление, отзыв или неизвестный тип - `HOLD`; остальные публикации **не считаются проверенными** (`NOT_CHECKED`). Ограничение теперь до 5 публичных запросов на запуск; публикаций, платных API и моделей нет. [Правила](../docs/operations/H-03-DAILY-RESEARCH.md).


## Structured scientific review draft (offline)

`research_scout.review_draft` готовит bounded черновик из уже полученных
публичных metadata для ручного экспертного обзора. Он не скачивает статью, не
выводит метод или эффект из заголовка, не вызывает модель, не пишет в YFC или
Second Brain и не публикует результат:

```bash
python3 -m research_scout.review_draft --review-stdin < candidate.json
python3 -m research_scout.review_draft --compare-stdin < drafts.json
```

Черновик сохраняет source URL, source kind, DOI/PMID/record id и происхождение
полей, явно предоставленных оператором. **PubMed, Europe PMC и DOI-resolver —
библиографические указатели, а не проверенный полный текст исследования.**
Ссылка на сайт издателя сама по себе также не доказывает доступ к полному тексту.
`primary_source_link` остаётся `UNKNOWN`, пока оператор не предоставит
`confirmed` с явным `review_basis=operator_reviewed_full_text`, ссылкой на
страницу издателя и `supporting_excerpt` для каждого поля. Это только
операторское свидетельство, не независимая автоматическая проверка первоисточника.
`primary_source_access` сообщает степень проверки. Подлинность фрагмента
этот офлайн-модуль не подтверждает; `MANUAL_REVIEW` обязателен.
Неподтверждённые `research_question`, `study_type`, `population`,
`sample_size`, `methods`, `main_results`, `limitations` и `effect_size`
остаются `UNKNOWN`; secondary source не становится primary source. Состояния — `MANUAL_REVIEW`/`HOLD`, `scientific_claims_verified`
всегда `false`, `automatic_publication` всегда `false`.

Сравнение нескольких drafts показывает только явно одинаковый research question
и оставляет методологические различия, противоречия, общие выводы и
meta-analysis на `MANUAL_REVIEW_REQUIRED`/`NOT_ASSESSED_WITHOUT_EXPERT_REVIEW`.
Офлайн-фикстуры проверяют documented/incomplete/secondary/correction/unknown
effect/missing sample, попытку сильного claim и comparison без автоматического
вывода consensus.

## От ежедневного публичного кандидата к офлайн-черновику (15.10.2026)

Выбранный элемент массива `items[]` из проверяемого отчёта
`latest-citations.json` можно передать напрямую, без ручного преобразования
ключей и без чтения защищённого каталога самим инструментом:

```bash
python3 -m research_scout.review_draft --daily-item-stdin < selected-public-item.json
```

Модуль проверяет ровно известные поля сборщика и сохраняет состояние
`article_notice_state`. Значение `NOT_CHECKED` не интерпретируется как
«исправлений нет»; `REVIEW_REQUIRED`/`UNAVAILABLE` требуют `HOLD`.
`scientific_claims_verified=false` и `automatic_publication=false` сохраняются.
Научные результаты, методы и размер выборки остаются `UNKNOWN` до
отдельной проверки полного текста. Никаких запросов модели, сети или
публикации не происходит.

[Предметный черновик по фактической публикации о растительном питании
и восстановлении](../docs/audits/H-03-plant-recovery-review-2026-10-15.md)
отделяет машинный библиографический кандидат от аналитического обзора
с указанием источников и неопределённости. Обзор требует экспертного
утверждения; изменений YFC, Second Brain и Telegram нет.


## Проверка методологии четырёх опубликованных работ (18.10.2026)

[Методологический аудит с первоисточниками](reviews/2026-10-18-publisher-methodology-risks.md) раскрывает ограничения, которые нельзя получить из одного DOI: наблюдательный дизайн и **смещение выборки 2485/4538** в IRONMAN, косвенный подсчёт силовых сессий по **15 минутам**, непрямую механистическую базу whey, авторскую RoB-оценку 36 исследований plant-food и отсутствие доказанной функциональной пользы CRET.

В `report_view.field_evidence.limits` для IRONMAN теперь есть строго ограниченные факты из конкретных разделов издателя. `source_doi` у evidence исправления указывает на **DOI отдельной correction**, а `doi` сохраняет исходный DOI статьи для совместимости. Выводы остаются `NEEDS_EXPERT_REVIEW`: обзор выбранных разделов первоисточника не равен полному статистическому аудиту или экспертному разрешению публикации.


## Передача на независимую научную экспертизу (18.10.2026)

[Пакет из 19 незавершённых проверок для рецензента](reviews/2026-10-18-expert-handoff.md) создан для четырёх зафиксированных PMID/DOI. Отдельный модуль `science_handoff` выводит JSON со ссылками на проверяемые источники, неосмотренные таблицы и протоколы, неопределённые effect size/CI и статус **`NOT_INDEPENDENTLY_REVIEWED`**. Важная оставшаяся проверка для CRET — официальный ClinicalTrials.gov NCT06906146 (по вторичным зеркалам плановая выборка 50, в публикации N=25; без оригинального protocol/version audit это **не доказанное** отклонение).

```bash
python3 -m unittest -q tests.test_research_science_handoff
python3 -m research_scout.science_handoff
```

Инструмент работает без сети, модели, прав на публикацию или чтения приватных данных; не может принять экспертное решение и не повышает `scientific_claims_verified`. Ни один из 19 пунктов не закрыт человеческой экспертизой — **Issue #4 остаётся OPEN/PARTIAL**.


## Контракт Research Scout v1 после приёмки 18.10.2026

**[Акт финальной технической приёмки](../docs/audits/H-03-RESEARCH-SCOUT-V1-ACCEPTANCE-2026-10-18.md)** отделяет доставленный read-only библиографический продукт от полноценной научной экспертизы. Владелец получает данные и предварительные научно-аналитические оговорки через защищённый Control Center; это **разрешённый внутренний канал выдачи** в рамках v1. Внешняя публикация не входит в v1.

- **#4** — реализация ежедневного bounded сбора Europe PMC/Crossref (не более 5 GET за run), защищённого локального snapshot, provenance, `HOLD/NO_DATA/MANUAL_REVIEW`, проверки DOI/коррекций и owner Control Center. Никаких новых прав и платных API.
- **[#317 Scientific Evidence Review](https://github.com/MikeMoore1337/hermes/issues/317)** — 19 уже подготовленных человеческих review gates, полноценные первоисточники, риск систематической ошибки, эффекты/95% CI, проверка publisher notices и claim-level редакционное решение. Не prerequisite для технического закрытия #4.
- Любые внешние советы, рекомендации YFC, Telegram/Second Brain publication, изменения fitness/nutrition алгоритмов требуют самостоятельного owner GO и применимой научной экспертизы. `scientific_claims_verified=false` и `automatic_publication=false` не меняются.
