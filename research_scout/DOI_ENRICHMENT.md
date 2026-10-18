# H-03 - обогащение отсутствующего DOI без ложного научного подтверждения

Проблема [#4](https://github.com/MikeMoore1337/hermes/issues/4): публичный Europe PMC `lite` может не содержать DOI, даже если официальная `core`-запись связывает PMCID, PMID и DOI (реальный пример `PMC13639859`). Это **не** разрешает угадывать DOI или публиковать выводы исследования.

Модуль `research_scout.doi_enrichment.review_missing_doi` - **только явный библиотечный вызов** при ручной обработке проверенного кандидата `EUROPE_PMC` со статусом `MANUAL_REVIEW`, причиной `metadata_only` и отсутствующим DOI. Ручной операторский модуль остаётся самостоятельным; начиная с реализации Issue #4 18.10.2026, ежедневный `daily_digest` также использует **свой прежний единственный Europe PMC core-слот** для одного DOI-less кандидата, **только когда обычный кандидат с DOI для Crossref не найден**. Это не вызывает `review_missing_doi()` как отдельные +2 запроса и не подключает нового поставщика. Максимум 5 GET за весь daily запуск сохраняется. Никаких изменений YFC или systemd-таймера.

Процедура строго ограничена: сначала проверка идентификатора и точного URL (без HTTP); затем **не более одного** запроса через существующий официальный Europe PMC Core по проверенному `MED/id` или `PMC/id`. Если корректная core-запись обнаружена, нет признаков correction/retraction и DOI допустим, делается **не более одного** Crossref GET для точного DOI. Никаких произвольных адресов, вторых попыток, новых провайдеров или моделей. Публикации и передача данных в YFC/Second Brain отсутствуют.

`MANUAL_REVIEW` означает лишь найденную и зарегистрированную библиографическую связь DOI/PMID/PMCID, **не** рецензированность, эффект или пригодность рекомендаций. Даже отсутствие correction/retraction в метаданных не доказывает отсутствие проблем у издателя. Если есть исправление/ретракция, ошибка/несовпадение, неизвестные метаданные или недоступный провайдер - **HOLD**, Crossref не вызывается там, где он бесполезен. `scientific_claims_verified=false`, `automatic_publication=false` всегда.

### Проверка без сети и без реальных статей

```sh
python3 -m unittest -q tests.test_research_doi_enrichment
```

Тестовые fixtures моделируют DOI-less PMCID, найденный DOI/PMID, негативные ответы, ссылочную подмену, correction/retraction, несовпадающий Crossref и разрыв соединения. Полный offline Linux suite после реализации: **591/591 PASS**. Не считать это production-доставкой или полноценной научной экспертизой. Для отдельного production включения/массового обогащения нужны своя заявка, квоты, проверка нагрузки и разрешение владельца.


## Дополнение — однократное автоматическое обогащение внутри бюджета daily

Когда три фиксированных Europe PMC lite-запроса не содержат ни одного безопасного DOI-bearing кандидата, но есть `HOLD/doi_missing`, daily может потратить **четвёртый запрос** на `core` строго для *того же source/id*. Ответ должен подтвердить PMCID или PMID, статус, отсутствие зарегистрированных notices, валидный DOI и запрет публикации. Если DOI восстановлен **и core не сообщил об исправлении/ретракции**, один **пятый запрос** проверяет регистрацию в Crossref. При выявленной correction/retraction **пятый запрос не нужен**: запись остаётся HOLD. Дополнительного Crossref reverse-update lookup и новой нагрузки сверх 5 GET нет.

Итоговая запись при успешном обогащении **всё равно HOLD** с причиной `doi_enriched_review_required` (даже при `MATCHED_METADATA_ONLY`): DOI проверяет библиографическое соответствие, не первичную научную доказательность или publisher clearance. Обнаруженная коррекция остаётся `integrity_hold`, ошибка проверки — `integrity_unknown`, а по-прежнему отсутствующий DOI — `doi_missing`. За один daily запуск рассматривается не более одной DOI-less статьи, без догоняющей пагинации и повторных попыток.

Если `PMC13639859` по-прежнему не содержит DOI в своей core-записи, Hermes **не** склеивает произвольно соседние PMID и PMCID. Ручной fixed-source оригинал PubMed `42840492` может содержать DOI, но независимая привязка двух идентификаторов требуется отдельно.

Проверка:
```sh
python3 -m unittest -q tests.test_research_daily_doi_recovery tests.test_research_daily_integrity
```
Предел запросов, точная source identity, correction HOLD, отсутствие платных API/публикации и отказ сохранения поддельного повышения статуса проверяются offline тестами; их успешность не означает живой production-run DOI enrichment на реальной DOI-less записи.


## Live smoke test 18.10.2026 — 08:52 UTC

[GitHub Actions #39113134401](https://github.com/MikeMoore1337/hermes/actions/runs/39113134401), одноразовый ограниченный workflow на SHA `8ceffdf6a15d23eda486263a169bd17b9e217c58` (ветка `audit/h03-live-daily-doi-recovery-once-20261018`) проверил **реальную** цепочку recovery: три тематических lite-ответа были **синтетическими и без сети**, DOI-less candidate `MED/42840492` с публикацией 22.09.2026 был фиксирован, а `article_integrity.inspect` сделал **ровно один официальный Europe PMC MED core GET** и `review_candidate` **один Crossref DOI GET**. Дополнительных retries или иных реальных источников не было, токены и секреты не использовались. Стандартный отчёт `prepare` указывает 5 *логических* вызовов, в том числе три mocked lite, но реальных HTTP максимум 2.

**Действительный ответ:** `doi=10.3389/fcimb.2026.1918695`, `crossref_state=MATCHED_METADATA_ONLY`, `integrity_state=NOT_REPORTED_IN_THIS_METADATA`, `errors=[]`, `reason=doi_enriched_review_required`, `status=HOLD`, `scientific_claims_verified=false`, `automatic_publication=false`. Workflow SUCCESS; точная запись `H03_LIVE_DOI_RECOVERY` содержится в GitHub Actions logs. Одноразовый workflow после проверки **удалён из изолированной ветки**, не был включён в `main`.

Это доказывает реальный bounded network + parser + Crossref happy path на зафиксированном PMID, **не** натуральный scheduled-daily сбор, полноту PMID↔PMCID для любых статей или отсутствие publisher corrections.
