# H-23 - OpenAlex: офлайн-проверка применимости к Research Scout

[Issue #190](https://github.com/MikeMoore1337/hermes/issues/190) поддерживает научный сбор [#4](https://github.com/MikeMoore1337/hermes/issues/4). Этот этап выполняется **без API-запросов, ключей, денег, веб-поиска из sandbox, LLM, релиза на VPS и автоматических публикаций**.

## Изменившиеся условия OpenAlex на октябрь 2026

- [Официальное объявление OpenAlex от 24.02.2026](https://blog.openalex.org/openalex-api-new-features-and-usage-based-pricing/) говорит, что API-ключ необходим для производственного использования. Без ключа разрешены лишь демонстрационные запросы, не для фонового сервиса.
- Запросы теперь тарифицируются по типу. На дату проверки в [официальном справочнике](https://help.openalex.org/api/authentication/) бесплатный подтверждённый ключ даёт дневной бюджет, но **наличие free tier не доказывает технический hard stop без платных списаний**.
- Работающие Europe PMC/Crossref в Hermes не требуют такого перехода на API-ключ. Не регистрировать OpenAlex account, не запрашивать email/ключ, не вызывать API и не включать новые задачи systemd без отдельного решения владельца и оплаты/лимитов.
- [Официальный словарь полей Works](https://help.openalex.org/data/works/attributes/) включает `id`, `doi`, `ids`, `is_retracted`, `type`, `publication_date`, `updated_date`. Флаг `is_retracted=false` означает только отсутствие известной записи в базе Retraction Watch; не означает отсутствие corrections, expression of concern или научных ошибок. `doi` хранит один предпочтительный идентификатор, хотя у работы может быть несколько DOI.

## Реализация

`research_scout/openalex_offline.py` обрабатывает **только заранее переданный** OpenAlex-shaped `{"results":[...]}` JSON, без сети. Контур строго ограничен 64 КиБ (65 536 байт) и 20 работами. Он проверяет OpenAlex work ID, DOI по существующему Crossref-контракту, согласованность `ids.doi`, UTC время и дату публикации, retraction и paratext; дедуплицирует DOI без учёта регистра относительно Europe PMC/Crossref и текущей страницы.

Статусы:

| Статус | Значение |
| --- | --- |
| `MANUAL_REVIEW` | Новый корректно оформленный кандидат, **научно не проверен** |
| `DUPLICATE` | DOI уже присутствует в существующих источниках или в этой порции |
| `HOLD` | Есть retraction, невалидный/отсутствующий DOI, конфликт идентификаторов, неполная дата/флаг или paratext |
| `OFFLINE_ONLY` | Уровень итогового отчёта; нельзя интерпретировать как разрешение API/runtime |

Результат содержит только проверенные `openalex_id`, нормализованный DOI, source URL, предоставленный вызывающей стороной `retrieved_at` и консервативные флаги. Title, abstract, arbitrary remote text и другие неразрешённые поля отбрасываются; источник timestamp не аттестован самим парсером. Поля `scientific_claims_verified=false`, `publisher_notices_cleared=false`, `automatic_publication=false`, `resident_agent_allowed=false` обязательны.

Проверка из корня Hermes:

```bash
python3 -m unittest discover -s tests -p 'test_research_openalex_offline.py' -v
```

На Windows доступен `py -3.14` вместо `python3`. В тестах только синтетические DOI/Work ID. Проверены повторный DOI, уже известный DOI, retraction, пропущенный retraction status, paratext, даты, противоречащие идентификаторы, зловредный title, дубликаты JSON-ключей и превышение размера.

## Польза относительно Europe PMC / Crossref

- Возможный плюс: дополнительные записи вне PubMed, альтернативный библиографический граф и источник сигнала Retraction Watch. Без живого сопоставления это **гипотеза, не доказанный прирост**.
- Недостатки: платный по потреблению API с ключом; отсутствие гарантии достоверности медицинских выводов; несколько DOI на одну работу; возможные дубли с Europe PMC/Crossref.
- Итог: **NO_GO для live интеграции**, разрешено только offline-преобразование. Для сравнения прироста сначала нужны отдельный owner approval, явный бюджет/жёсткий нулевой paid fallback, подтверждённый лимит, allowlist IP/egress, тестовые реальные выборки при разрешении и независимая проверка исправлений/отзывов статьи. Никаких изменений YFC и Telegram.