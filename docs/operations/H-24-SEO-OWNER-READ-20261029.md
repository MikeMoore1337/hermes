# H-24 / #191 / #397 - поисковые данные YFC и граница самостоятельного исполнения

**Дата чтения:** 29.10.2026. **Период отчётов Google:** 01.10.2026-26.10.2026 включительно. **Режим:** operator-connected, read-only; `NOT_HERMES_AUTONOMOUS`, `NO_PUBLISH`, `NO_PAID_API`.

## Источники и реальный доступ

- Google Search Console: существующее разрешённое соединение **Windsor.ai `searchconsole`**, имущество `sc-domain:your-fitness-coach.ru`, подтверждённый тариф **Free**. Вызваны только read-only Search Analytics с группировками **day** и **page**, `force_refresh=false`; новых Google OAuth-доступов и сохранения учётных данных в Hermes **не было**.
- **Сайт / ежедневно:** 42 показа / 1 клик / CTR ~2,38% / средняя позиция ~26,86 (за указанный период). Позиция вычислена как `sum(day_impressions * day_position) / 42` только для дней с показами; нулевые строки с `position=0` не считаются реальной позицией. Единственный клик в прочитанном ряду - 26.10.
- **Страницы:** `/` - 3 показа / 1 клик / поз. 1,6667; `/calculators/1rm` - 25 / 0 / 25,48; `/nutrition` - 8 / 0 / 34,125; `/exercises/bench-press` - 4 / 0 / 46; `/for-trainers` - 3 / 0 / 8,6667; `/training` - 1 / 0 / 7.
- Сумма шести **page rows = 44 показа**, не `site total=42`. Разные размерности не обязаны агрегироваться в одну величину (каноникализация и правила Search Analytics); не исправлять разницу вычитанием и не суммировать page/query/site. **Query-level rows для этого среза отдельно не опрашивались**: `NO_DATA`, а не нулевые показы.
- Это минимальный объём: `SEO_IMPROVEMENT_CAUSALITY=NOT_VERIFIED`. CTR 2,38% не означает статистически устойчивую конверсию. Исторический 03-16.10 baseline содержит 16 показов/0 кликов, но **окна перекрываются** и не являются независимым before/after тестом.

**Яндекс**: живых Webmaster query/indexing/site данных за октябрь нет в прочитанном операторском пакете. У владельца уже есть сайт в Яндекс Вебмастере, но последний подтверждённый независимый маршрут к `api.webmaster.yandex.net:443` с VPS/Windows/роутера/мобильного интернета оканчивался `TCP/HTTPS TIMEOUT` (Issue #397 23.10). Текущий `NETWORK_UNAVAILABLE` нельзя выдавать за сбой OAuth, отсутствие индексации или глобальную аварию сервиса. Новых сетевых попыток в рамках этого этапа **не делали**. Старый Wordstat owner-export (15.08-15.09.2026, Россия) остаётся отдельной исторической оценкой **Яндекс-спроса**, не Google CTR/rank.

## Что реализовано в Hermes и что остаётся отдельно

| Канал | Исходники и синтетические тесты | Реальный provider/host runtime |
| --- | --- | --- |
| Google | `marketing/gsc_analytics.py`, `marketing/gsc_direct.py`, `tests/test_marketing_gsc_analytics.py`, `tests/test_marketing_gsc_direct.py`; `webmasters.readonly`, 6 Analytics + 1 Sitemaps ограниченных запросов на план | **NOT_VERIFIED**: отдельный service-account credential в VPS runtime, реальный OAuth/GSC GET, приватный журнал, активный systemd tick и owner-operational GO отсутствуют в текущем доказательстве. Windsor.ai ChatGPT read нельзя превращать в сервисный Hermes OAuth. |
| Яндекс | `marketing/yandex_webmaster.py`, `marketing/yandex_webmaster_direct.py`; 6 фиксированных GET, bounded response/egress, synthetic error coverage | **LIVE_API_NETWORK_BLOCKED**: реальный OAuth/host mirror и провайдерский `GET /v4/user` успешно не подтверждены. Нет сервисного таймера, записи или оплаты Wordstat API. |
| Общий SEO packet | `marketing/seo_research.py` и контракт Hermes #64 сохраняют google/yandex/wordstat раздельно, `NO_DATA != 0`, owner/source provenance, `publication_allowed=false`. | YFC publication/edit/personalized advice не осуществлялись. |

### Редакционная политика после закрытия Hermes #317

Отдельная квалифицированная внешняя научная экспертиза **отменена владельцем как недоступная**, #317 закрыта `not_planned`, но это не `SCIENTIFIC_VERIFIED`. SEO-пакет не должен требовать недостижимого экспертного заключения для **market research**. При подключении первичного исследования нужно самостоятельно проверить источники/тезисы, provenance и ограничения и честно отмечать `NOT_ATTESTED` / `SCIENTIFIC_HOLD`; медицинские рекомендации не допускаются по одному авторскому abstract. Единственный маршрут публикации образовательных статей - добровольное решение YFC Root по конкретной редакции в #601. Закрытие #317 **не** включает scientific claim handoff и не снимает его программный `HOLD`.

## Следующие проверяемые внешние условия (не BRC)

1. **#191:** на самостоятельном разрешённом Hermes VPS окружении проверить уже предоставленные Google credentials без их вывода/передачи, минимальный egress и один bounded live GET; после отдельного операционного разрешения - собственный таймер и proof его одного реального запуска. Не создавать новый сервис и не включать таймер в рамках только source PR.
2. **#397:** объективно подтвердить HTTPS/TLS/HTTP-доступность API Яндекса прежде чем расходовать OAuth GET бюджет, затем единичный `/v4/user` из прежнего изолированного окружения. Не переустанавливать OAuth, не менять Xray, не запрашивать ключи, не обращаться к платному Wordstat.
3. **#320/#322 YFC:** при достаточной независимой выборке отдельно оценить страницы/индексацию и одобрить конкретные изменения через YFC PR; не запускать SEO-автопубликацию.

**Интерпретация:** доставленные source modules и успешная операторская аналитика не равны автономному VPS producer. Нельзя закрывать #191 и #397 по offline CI или данным только Google. Следить за состояниями `NOT_VERIFIED` / `NETWORK_BLOCKED` без ложных `0`.
