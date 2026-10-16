# H-12 / #64 — HTML → SEO metadata: bounded read-only candidate

Аудит 16.10.2026. **Не включён в production execution.**
Этот этап соединяет уже существующий `network_boundary.fetch_public_html`
с детерминированным парсером и **ручным офлайн-хэнд-оффом** в
`statejnik_integration.offline_gap`. Его задача — получить из
**публичной HTML-страницы** название и единственный `h1` для
последующего анализа покрытия, не выдумывая проверку источника,
Wordstat-частоту или медицинскую достоверность.

## Что реализовано

`statejnik_integration.html_review` — отдельный Hermes-owned модуль.
Исходные 62 файла подаренного `statejnik` не изменены.

1. `candidate_fetch_one(url, allowed_hosts=..., network_authorized=False)`
   всегда возвращает `network_not_enabled` **до DNS и HTTP**.
   При **явном** `network_authorized=True` вызывает **только**
   `network_boundary.fetch_public_html` с тем же exact HTTPS-host
   allowlist и pinned DNS/TLS. Код не зарегистрирован в
   `statejnik_integration.runner`, расписаниях, Control Center,
   YFC или общем агенте. Это проверяемый разработческий кандидат,
   **не** новый публичный read-only crawler и не допуск в сеть.
2. `parse_public_html(url, bytes, allowed_hosts)` не открывает сеть.
   Только UTF-8 HTML до 256 KiB, не более 6000 тегов,
   один `<title>` и один `<h1>`. Скрытые `script/style/template`
   исключаются. Строки нормализуются, удаляются HTML/Markdown
   спецсимволы, которые могут стать инъекцией в `plan.md`;
   тело статьи, JS, ссылки на другие домены и cookies не копируются.
3. Ответ содержит только `requested_url`, title, h1, размер и
   SHA256 загруженных байтов, плюс:
   `status=MANUAL_REVIEW_REQUIRED`,
   `source_authenticity_verified=false`,
   `final_redirect_url_verified=false`,
   `wordstat_volume=null`,
   `search_demand_verified=false`,
   `publication_allowed=false`, `yfc_write_allowed=false`.
   Хеш доказывает лишь совпадение байтов, **не подлинность страницы**.
4. `to_offline_gap_site(review, allowed_hosts,
   operator_classified_article=False)` формирует **строго
   локальный** `site.json`, совместимый с прошлым
   [site-gap офлайн-аудитом](H-12-STATEJNIK-OFFLINE-SITE-GAP.md).
   Пока оператор отдельно не классифицирует страницу как статью,
   `article_urls=[]`: статья **не объявляется покрывающей тему**
   автоматически. Даже с `operator_classified_article=True`
   это лишь ручная классификация, не фактчекинг.

## Доказательства / ограничения

Синтетический набор тестов подменяет HTTPS/TLS и DNS: полный отказ
сети по умолчанию, запрет metadata/loopback/неразрешённых доменов,
строгая UTF-8 обработка, огромные и невалидные HTML, несколько H1,
скрипты, HTML/Markdown инъекции, неверные переданные provenance
flags и совместимость с `offline_gap._site`. **Ни один
живой домен или DNS не опрашивался**, модель не вызывалась.

Важно: будущая эксплуатация требует отдельного owner/security GO
на ограниченный OS egress, server allowlist, живые негативные
TLS/redirect/slow-response пробы, документирование `robots`,
тарификацию провайдера (если затрагивается) и управляемую регистрацию
сборщика. В текущем `network_boundary` **нет доказанного общего
wall-time бюджета для медленно читаемого тела** — этот gate
остаётся открытым. До его закрытия не давать разрешение на реальную
сеть и не поднимать таймер сканирования.

Режим: `HTML_REVIEW_CANDIDATE_OFFLINE_VERIFIED`,
`NETWORK_RUNTIME_NO_GO`, `CMS_PUBLISH_NO_GO`,
`RESIDENT_HERMES_NO_GO`.
