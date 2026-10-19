# H-24 / Hermes #191 - Google Search Console: read-only evidence

Дата проверки: **19.10.2026**. Scope: GSC property
`sc-domain:your-fitness-coach.ru` (Your Fitness Coach).
Issue: https://github.com/MikeMoore1337/hermes/issues/191

## Решение: KEEP_WINDSOR + offline handoff, не новый OAuth

1. В разрешённой сессии ChatGPT обнаружен существующий подключённый
   Windsor.ai connector `searchconsole` с указанной property. Реальное
   чтение данных **выполнено 19.10.2026**. Через Windsor доступны
   Search Analytics и Sitemaps; URL Inspection в списке полей нет.
2. Это **доступ ChatGPT connector**, не credential для VPS. Никакого
   Google refresh token, нового клиента, доступа к аккаунту, ключей,
   платежей, network egress и systemd timer не добавлено.
3. `marketing.gsc_analytics` нормализует отдельно предоставленный
   снимок в памяти без IO. Не подключает Hermes runtime к Windsor/Google.
   Такой файл может быть получен оператором через существующий источник
   или проверенный ручной экспорт. Наличие `transport=windsor_ai`
   в самостоятельно переданном JSON само по себе НЕ доказывает
   аутентичность; `provider_attested=false`.
4. Самостоятельное регулярное извлечение **из Hermes production**:
   `RUNTIME_SOURCE_NOT_CONFIGURED`. Если понадобится, отдельное
   owner-решение о безопасном разрешённом канале данных и правах.
   Новая OAuth интеграция для текущего read-only исследования не нужна.
   Для живого URL Inspection отдельное решение `HYBRID` возможно,
   но только после обоснования и owner GO.

## Актуальное подтверждённое чтение (не тестовые данные)

Источник: текущая разрешённая Windsor.ai/Google Search Console property,
операторский ChatGPT session, 19.10.2026. Search type в переданных
данных отдельно не маркирован - использовались стандартные
Search Analytics поля. Выбранное окно **03-16.10.2026 включительно**;
17 октября Windsor показал нулевую строку без доказательства, что
сутки полностью финализированы, поэтому не включён в baseline.

| Отчёт | Наблюдение |
|---|---|
| Site total | 16 показов, 0 кликов, CTR 0, средняя позиция 22.1875 |
| Pages | 6 URL, сумма по строкам 18 показов - НЕ site total |
| Queries | 5 доступных строк, 5 показов; неполнота из-за privacy/top rows |
| Devices | DESKTOP: 10; MOBILE: 6; TABLET: нет строки, НЕ доказанный ноль |
| Countries | Russia: 8; Ukraine: 2; United States: 2; Germany, Spain, Kazakhstan, Latvia: по 1 |
| Sitemap | https://your-fitness-coach.ru/sitemap.xml, submitted=29, errors=0, warnings=0 |
| Sitemap downloaded | 2026-10-16T00:32:20.695Z |
| Sitemap submitted | 2026-09-13T18:22:36.946Z |
| URL Inspection | Недоступен в текущем Windsor поле/инструменте |
| Фактическая freshness | Полнота последних суток 17-18.10 не подтверждена |

Pages: `/` 2 показа (поз. 2), `/calculators/1rm` 10
(21.1), `/nutrition` 3 (15.6667), `/training` 1 (7),
`/for-trainers` 1 (8), `/exercises/bench-press` 1 (82).
Запросы: `1 пм`, `5пм`, `жим штанги лёжа техника`,
`калькулятор на раз`, `рассчитать 1пм`: каждый по одному
показу и без кликов. Это агрегированные SEO-данные, не PII.

Исторический baseline YFC #320 (03-14.10.2026): **12 показов,
0 кликов, позиция 23.25**. Сравнивать окна 03-14 и 03-16
как независимые периоды некорректно. Рекомендация Stage 2 остаётся
`INSUFFICIENT_EVIDENCE / DEFER`; не обещать рост по 16 показам.
Контрольное наблюдение намечено примерно на 31.10.2026.

В Windsor.ai было использовано восемь ограниченных read-only отчётов
(общий, ежедневный, страницы, запросы, sitemap, страны, устройства,
отдельная проверка 17-18 октября). Не выполнялись mutating actions.

## Контракт данных

Функции:
- `normalize_analytics(snapshot)`: один отчёт Search Analytics
  (site, page, query, country, device, date или явно указанные
  совместимые измерения). Каждый результат имеет `schema_version`,
  `search_engine`, `source`, `provider`, `source_kind`,
  `property`, `observed_at`, `period_start`, `period_end`,
  `data_latest_date`, `search_type`, `dimensions`,
  `evidence_sha256`, `quality_status`, `completeness`,
  `limitations`, `rows`.
  Строки несут только доступные метрики
  `clicks/impressions/ctr/average_position`; необязательные
  размерности не заполняются фиктивными значениями.
- `normalize_sitemaps(snapshot)`: `sitemap_url`,
  `submitted_url_count`, `errors`, `warnings`,
  `last_submitted`, `last_downloaded`, если доступны.
  `indexed` **умышленно выбрасывается**: deprecated.
- `to_h12_observations(report, query, intent, as_of)`:
  мост к существующему Hermes #64. Принимает только query-level GSC,
  требует явно выбранный запрос и intent, выдаёт существующий
  `google_search_console / owner_export` контракт. Указывает
  `owner_attested=false` и `OWNER_EXPORT_UNVERIFIED`, пока
  отдельной ручной проверки владельцем не было. Это никогда не
  становится live-verification через Hermes или командой на публикацию.

Пример входного **синтетического** отчёта:

```json
{
  "property": "sc-domain:your-fitness-coach.ru",
  "transport": "windsor_ai",
  "period_start": "2026-10-03",
  "period_end": "2026-10-16",
  "observed_at": "2026-10-19",
  "data_latest_date": "2026-10-16",
  "search_type": "web",
  "dimensions": ["query"],
  "ctr_unit": "fraction",
  "rows": [{"query": "synthetic query", "clicks": 0, "impressions": 2,
            "ctr": 0, "position": 15}]
}
```

Отчёт - только вход в отдельную функцию, **не OAuth и не
настройка автоматического сбора**. `ctr_unit` обязателен:
`fraction` (0..1) либо `percent` (0..100);
смешивать масштабы нельзя. Отрицательные значения, NaN, несовпадение
property, невалидные page URL, дубликаты, лишние поля (в том числе
псевдо-`indexed`), несоответствие даты и метрик отклоняются
с безопасным кодом ошибки без значения строки.

Пределы: 1000 строк, 256 KiB JSON, 370 дней. Код не осуществляет
сетевых запросов, чтения токенов, записи файлов, публикации,
фоновых задач или вызовов моделей. Digest SHA-256 идентифицирует
байты переданного JSON, **не удостоверяет Google/Windsor**.

### Статусы качества

`AVAILABLE`: есть данные и дата latest достигает конца окна.
`PARTIAL`: latest ранее конца окна.
`STALE`: latest старше 10 суток от observed_at (локальное
операторское правило, не порог Google).
`LATEST_DATE_UNKNOWN`: дата latest не предоставлена.
`NO_DATA`: нет строк, что НЕ эквивалентно подтверждённому
нулю показов. Для отдельной строки возможны `NO_IMPRESSIONS`,
`PARTIAL_METRICS` и `OBSERVED`. Нулевые дни от провайдера
нельзя автоматически считать доказанной полнотой Google.

Отчёты сайта и страниц могут различаться: property и canonical-page
агрегирование считают показы по-разному. Query rows не исчерпывают
все показы из-за анонимизации и ограничений строк.
Позиция 0 в нулевой дневной строке Windsor удаляется как
неизвестная, не сохраняется как реальный SERP rank.
CTR и position **не складываются**; нельзя выводить site total
из page/query/country/device слоёв.

## Индексация: остающийся отдельный пробел

Search Analytics сообщает поисковую видимость, не покрытие индекса.
Sitemaps `submitted=29` и `errors=0` подтверждают только
диагностику sitemap, не 29 проиндексированных страниц.
URL Inspection indexStatusResult отдельно может содержать
`verdict`, `coverageState`, `robotsTxtState`, `indexingState`,
`lastCrawlTime`, `pageFetchState`, `userCanonical`,
`googleCanonical`, `sitemap[]`. Текущий Windsor этого не
предоставляет. Старые owner UI-проверки в YFC #502 не обновляются
автоматически на новую дату. Никакого массового URL инспектора,
нового Google OAuth, индексирующих запросов или нового crawler нет.

Если отдельно одобрен официальный GSC API, minimum OAuth scope
`https://www.googleapis.com/auth/webmasters.readonly`,
отдельный credentials store и property permissions; bounded calls,
timeouts, pagination 1..25000 на page, date window caps,
429/5xx backoff с конечным бюджетом и отсутствие секретов в логах.
HTTP 400/401/403/404/429/5xx, timeout и JSON errors должны
оставаться source error, а не `0 traffic`.
Такая реализация сейчас **не активирована и не необходима для
текущего read-only research**.

## Зависимости и reproducible tests

```bash
python -m unittest tests.test_marketing_gsc_analytics tests.test_marketing_seo_research -v
```

Новые тесты - синтетические, без сети/credentials. Покрыты уровни
site/page/query/device/country/date, неполные метрики, query privacy
и несуммируемость слоёв, stale/no-data, percent/fraction,
sitemap deprecated, URL scope, property mismatch, ошибки/дубликаты,
попытки передать indexed и отсутствие publication capability.
Путь `GSC snapshot → normalized → #64 observations` сохраняет
низкое качество неподтверждённого operator snapshot. Для отдельного
H-12 SEO packet editorial decision остаётся fail-closed:
без owner-attested source нельзя получить verified opportunity.

Яндекс Вебмастер и Wordstat: исключительно Hermes #397 и #64,
здесь не смешиваются с Google. Оценка конверсий - YFC #320,
публикация и owner READY - YFC #322. Ни YFC, ни Cloudflare,
ни H-01 #33 этим изменением не затронуты.

Официальные первоисточники:
- https://developers.google.com/webmaster-tools/v1/searchanalytics/query
- https://developers.google.com/webmaster-tools/v1/how-tos/all-your-data
- https://developers.google.com/webmaster-tools/v1/sitemaps
- https://developers.google.com/webmaster-tools/v1/urlInspection.index/UrlInspectionResult
- https://support.google.com/webmasters/answer/17011364?hl=en
- https://developers.google.com/search/blog/2022/10/performance-data-deep-dive
