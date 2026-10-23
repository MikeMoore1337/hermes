# H-24 #397 — Яндекс Вебмастер: read-only API shape, owner-export и SEO packet

Статус 23.10.2026: **OFFLINE_IMPLEMENTED / LIVE_AUTH_BLOCKED / NO_PUBLISH / NO_COST**. Исходные данные YFC: права на сайт уже настраивались владельцем в Вебмастере (YFC #264 и #502), historical Wordstat export 15.08–15.09.2026 имеется. Повторная проверка регистрации сайта и создание аккаунта не нужны. Но **доступ Hermes к реальному API, OAuth, актуальный primary mirror и октябрьские Яндекс-показы не подтверждены**. Не подменять собственника UI тестовым ответом.

## Официальные API v4 (проверено по документации 23.10.2026)

- [Авторизация](https://yandex.ru/dev/webmaster/doc/ru/tasks/how-to-get-oauth) — Яндекс OAuth, read-only в Hermes должен использовать ровно `webmaster:hostinfo`; `webmaster:verify` и иные возможности изменения хоста не запрашиваем, пока не доказана необходимость. **Ни токенов, ни нового OAuth приложения сейчас нет.**
- [Реестр ресурсов v4](https://yandex.ru/dev/webmaster/doc/en/concepts/getting-started) — отдельно GET user, hosts, search queries, sitemap и indexing. POST/DELETE/recrawl запрещены.
- [Popular queries](https://www.yandex.ru/dev/webmaster/doc/ru/reference/host-search-queries-popular) — ограниченный TOP, mandatory `order_by`, не более 500 за запрос; текущий план берёт **не более 50**. Отдаёт `query_id/query_text`, `TOTAL_SHOWS/TOTAL_CLICKS/AVG_SHOW_POSITION/AVG_CLICK_POSITION`, `count`, `date_from/date_to`. Ограничение списка и privacy/порог выдачи **не равно нулевому спросу**, запросные показатели **без URL или региона**.
- [All-query history](https://www.yandex.ru/dev/webmaster/doc/ru/reference/host-search-queries-history-all) — динамика показателей **по всему сайту**, без query/page. Нельзя превратить её в метрику выбранного ключа.
- [Indexing history](https://www.yandex.ru/dev/webmaster/doc/ru/reference/hosts-indexing-history) — наблюдаемые HTTP 2xx/3xx/4xx/5xx/OTHER по обходу и индексированию; это **не сертификат, что URL находится в поисковой выдаче**.
- [Sitemaps](https://yandex.ru/dev/webmaster/doc/ru/reference/host-sitemaps-get) — GET discovered sitemaps/errors/counts; не создавать и не удалять Sitemap. Robots, canonical, зеркала и page-level errors требуют своих независимых источников/GET; этот этап их не заявляет.

## Что реализовано

`marketing/yandex_webmaster.py` (без дополнительных библиотек):

- `read_plan(user_id, host_id, start, end, device)` возвращает **только список** шести фиксированных HTTPS GET: user, hosts, popular (50), all history, indexing history, sitemaps (20). Нет сетевого клиента и OAuth-токенов; для другого хоста/невалидных дат отказ. У всех запросов 0 ретраев, 0 фактических вызовов.
- `normalize_export(payload, as_of)` принимает только `PUBLIC_SYNTHETIC`-форму `source_type=synthetic_fixture` или `owner_export` с заранее полученным официально-подобным JSON. Источник может быть предоставлен владельцем **после удаления секретов**; это не импорт приватной статистики из аккаунта.
- Строгие schema/dates, до **64 KiB** входного JSON, 50 ключевых строк, по 32 дня на series, 20 sitemap. Повторные query_id/dates, некорректные счётчики, отрицательные/NaN/Infinity, чужие URL, malformed/неизвестные поля → fail-closed. Digest SHA-256 — только целостность предоставленного содержимого, **не поставщик/аутентификация**.
- Отдельные `site_history`, `indexing_http_status_history`, `sitemaps`. Все отсутствующие поля остаются отсутствующими/`null` — **NO_DATA != 0**. CTR вычисляется лишь при наличии обоих реальных счётчиков и положительном знаменателе; отсутствие CTR не означает 0.
- **Единственная интеграция** — выдача `seo_research_observations` уже существующего Hermes #64 `marketing.seo_research.normalize_observations`. Только конкретные популярные запросы. Глобальные site counts, indexing, sitemap не конвертируются в «спрос на ключ» и не суммируются с Google или Wordstat. Пользователь вручную задаёт `search_intent`, он не выводится из provider metrics.
- `source_type=owner_export` с явной `owner_attested=true` даёт только `OWNER_ATTESTED_NOT_PROVIDER_VERIFIED`. Ни один путь не выдаёт VERIFIED/Google данные, не разрешает YFC-публикацию и не создаёт SEO Growth Operator.

**Симуляция:** `python3 -B -m unittest tests.test_marketing_yandex_webmaster -v`. У синтетических примеров нет реальных Яндекс-показов/URL и не могут служить доказательством индексации.

## Live GO / эксплуатационный остаток

1. Использовать уже подтверждённый owner доступ Вебмастера к **YFC**; проверить свежий primary mirror и разрешённый путь к данным. Подтверждённый **санитизированный owner-export** может пройти offline normalizer без новой авторизации. Никаких просьб переслать токены/ключи в чат/GitHub.
2. **Только после отдельного owner approval**: конкретный OAuth scope `webmaster:hostinfo`, отдельный малопривилегированный secret store и egress allowlist `api.webmaster.yandex.net`, token expiry/revocation, fixed GET budget, 401/403/429/5xx bounded non-retry, источник свежести/лимиты Yandex, masked logs. Отдельные privacy tests реального адаптера.
3. Сверить один фактический read / user-host identity, один recent query/index/sitemap ответ, сопоставить export с API без утечек, затем интегрировать в существующий #64 packet и проектный отчёт YFC #320 по собственным правилам. Ошибка OAuth → BLOCKED, не 0, не synthetic PASS.
4. **Не включать Wordstat Search API v2** и не превращать исторические Yandex Wordstat broad/quoted volume в Google demand. YFC #322 сохраняет редакционные/публикационные права. Для page-level canonical/robots/URL нужно отдельное подтверждение официальных источников.

Изменения только в Hermes offline Python/tests/docs. **Не** устанавливались библиотеки, credential providers, scheduled collectors, UI компоненты, команды на VPS или BRC, платные API. При merge main доставляется исходный код/документация без runtime consumer.
