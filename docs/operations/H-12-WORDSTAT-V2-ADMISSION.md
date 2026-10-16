# H-12 / #64 — Wordstat: актуальный API-контракт и NO-BILLING-GO

Дата проверки официальных источников: **16.10.2026**.
Режим: **OFFLINE_ONLY / PAID_REQUESTS_NO_GO**.

## Не запускать legacy Wordstat-клиент из vendor

Полная копия `statejnik` v1.2.0 сохранена без изменений. Однако в
`third_party/statejnik/skills/statejnik/scripts/keywords.py`
переменная `WORDSTAT_URL` использует
`https://api.wordstat.yandex.net/v1/topRequests`, а токен
`WORDSTAT_TOKEN` и `_net.request` используют старый контракт.
Это не означает, что официальный legacy endpoint обязательно отключён,
но **он не соответствует первичному текущему русскоязычному руководству**.

Официальная [русскоязычная справка Wordstat API](https://yandex.ru/support2/wordstat/ru/content/api-wordstat)
сообщает, что API доступен как часть Yandex Search API.
[Актуальная документация Yandex AI Studio](https://aistudio.yandex.ru/ru/docs/search-api/concepts/wordstat)
перечисляет методы `GetTop`, `GetDynamics`,
`GetRegionsDistribution` и `GetRegionsTree`.
Для выполнения запросов требуется IAM-роль
`search-api.webSearch.user`; API-ключ с областью
`yc.search-api.execute` либо разрешённый IAM-токен.
[Руководство GetTop](https://aistudio.yandex.ru/ru/docs/search-api/operations/wordstat-gettop)
указывает REST `POST https://searchapi.api.cloud.yandex.net/v2/wordstat/topRequests`
с JSON и `folderId` сервисного аккаунта.

Другие REST пути в `/v2/wordstat`: `/dynamics`,
`/regions` и `/getRegionsTree`. Наличие методов по документации
**не** означает, что у Hermes есть доступ к сервису.

## Официальные ценовые ориентиры — не платёжные лимиты

По [официальному прайсу Yandex Search API](https://aistudio.yandex.ru/ru/docs/search-api/pricing)
на дату проверки (цены в рублях с НДС):

| Wordstat method | Справочная цена за 1000 запросов |
|---|---:|
| GetTop | 20 ₽ |
| GetDynamics | 20 ₽ |
| GetRegionsDistribution | 50 ₽ |
| GetRegionsTree | Не тарифицируется |

**Даже нетарифицируемая операция НЕ разрешена без доступа владельца**
и отдельного API GO. Все цифры могут измениться; округление, квоты,
скидки, фактический биллинг и достижимость аккаунта = **NO_DATA**.

`statejnik_integration.wordstat_v2` реализует только статическую
спецификацию и `reference_estimate(method,calls)`, возвращающую
справочную арифметику. Прямого HTTP клиента, токенов, среды, OAuth,
billing/paid fallback или вызова `POST` нет. По умолчанию
`provider_access_verified=false`,
`billing_hard_limit_verified=false`,
`daily_spend_cap_rub=0`, `any_request_executed=false`.

## Что ещё нужно для настоящего GO

1. Подтвердить нужный **личный** Yandex Cloud account, сервисный
   аккаунт / IAM роль, явный доступ к Wordstat, folder ID и метод
   авторизации **без передачи секрета в GitHub/ChatGPT/логи**.
2. Owner approved максимальную месячную и дневную стоимость,
   независимый server-side billing hard stop, квоты и политику
   превышения — без автоматических ретраев и paid fallback.
3. Отдельный review read-only **POST** транспорта с DNS-pin/TLS,
   outbound egress firewall и запретом redirect/SSRF. Нельзя напрямую
   разрешать `_net.request` и обходить установленный runner.
4. Полностью синтетические тесты платёжных отказов, квот 429/503,
   отсутствие утечек Bearer/IAM и replay. Реальное E2E — только
   по отдельному owner GO и с фактическими показателями.

**Диспозиция:** весь upstream код перенесён,
новый контракт/стоимость изучены,
`WORDSTAT_REAL_CALLS_BLOCKED`, `SEO_DATA_NO_DATA`,
`NO_PAID_API`, `NO_PUBLICATION`.
