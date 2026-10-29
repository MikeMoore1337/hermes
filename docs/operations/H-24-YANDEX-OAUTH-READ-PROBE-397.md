# H-24 / #397 — реальное чтение Яндекс Вебмастера (без автономной активации)

**Владелец 23.10.2026:** разрешил подключать данные и **управлять всем SEO-процессом** YFC: Google/Яндекс evidence → opportunity → proposal → YFC PR → проверка публикации → измерение. Это разрешение распространяется на разработку и корректирующие SEO-PR, а не на платные операции, массовый автопостинг, публикацию непроверенных медицинских материалов, создание произвольных privileged runtime-сервисов или раскрытие токенов. Уже существующие обязательные gates: [Hermes #397](https://github.com/MikeMoore1337/hermes/issues/397), [YFC #320](https://github.com/MikeMoore1337/your-fitness-coach/issues/320), [YFC #322](https://github.com/MikeMoore1337/your-fitness-coach/issues/322).

## Реализованный минимальный GET executor

`marketing/yandex_webmaster_direct.py`:
- Стандартная библиотека Python; **не** дополнительный SEO-сервис или scheduler. **По умолчанию выполнение отключено**, `--date` без `--execute-read` печатает `NOT_EXECUTED`.
- Только операторский **однократный** запуск с `--execute-read --token-file ...`. Не запускать из CI или бессрочного timer.
- OAuth token читается **только из приватного локального файла** на Linux VPS с правами владельца, mode 0600, no symlinks. Никогда не передавать токен через CLI параметр, чат, GitHub Issue/CI, stdout или лог.
- `Authorization: OAuth ...` и `Accept: application/json`. Система доверенных HTTPS CA, строго `api.webmaster.yandex.net`, без перенаправлений, без системного proxy; `GET`-only, таймаут 8 сек, не более 6 запросов, **0 retries**, не более 64 KiB на ответ / 256 KiB суммарно.
- Сначала `GET /v4/user`, затем `GET /v4/user/{id}/hosts`, проверка единственного exact `https:your-fitness-coach.ru:443`, verified=true и совпадающего `main_mirror.host_id` (если указан). При 401, 403, 404, 429, 5xx, mismatch, unknown и malformed JSON — фиксированная ошибка, без продолжения.
- Только затем четыре оставшихся GET `/search-queries/popular`, `/search-queries/all/history`, `/indexing/history`, `/sitemaps` из уже проверенного bounded `read_plan()` (28 суток до позавчера; 50 популярных запросов). Внедрённый тестовый transport помечается `SYNTHETIC_TRANSPORT_CHECK`, не `PROVIDER_VERIFIED`.
- На выходе по умолчанию **только безопасный summary receipt**: статус, домен, период, количество запросов и Sitemap, наличие индексной истории. Ни строк поисковых запросов, ни агрегатов посещений, ни token/UID/response payload. Собранные наблюдения остаются в памяти; `normalize_export` помечает `OWNER_EXPORT_UNVERIFIED`. Верификация provider origin/аккаунта через независимый источник и защищённое хранилище истории **NOT_DONE**.

Документированные сценарии отказа и тесты: `tests/test_marketing_yandex_webmaster_direct.py`, только синтетический транспорт/фикстуры. Никаких вызовов к настоящему Яндексу в GitHub CI.

## Однозапросная диагностика OAuth без повторной загрузки статистики

Если штатный `--execute-read` возвращает только `AUTH_OR_RESPONSE_NOT_VERIFIED`, не повторять полный шестизапросный сбор и не перевыпускать токен без доказательств. После проверки правильного production release SHA, владельца и режима 0600 приватного token-файла, оператор может **однократно** выполнить:

```sh
cd "/opt/hermes-agent-owner/releases/main-$(cat /var/lib/hermes-main-deploy/last-success.sha)"
runuser -u hermes-seo -- env -i HOME=/var/lib/hermes-seo PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 -B -m marketing.yandex_webmaster_direct \
  --date "$(date -u +%F)" --execute-read --probe-user \
  --token-file /var/lib/hermes-seo/private/yandex-oauth-token
```

Новый `--probe-user` запускает только **один HTTPS GET** `https://api.webmaster.yandex.net/v4/user` (8 секунд, без proxy/redirect/retry) и никогда не обращается к `hosts`, поисковым запросам, индексации или sitemap. Положительный результат `LIVE_USER_ENDPOINT_ONLY` подтверждает только валидный `/user` ответ при локально переданном OAuth-токене, **не** наличие YFC в аккаунте или пригодность данных. Отказ выдаёт только заранее разрешённый код: `TOKEN_INVALID`, `AUTH_REQUIRED`, `ACCESS_DENIED`, `NETWORK_UNAVAILABLE`, `USER_ID_INVALID`, `RESPONSE_JSON_INVALID` и прочие фиксированные состояния; неизвестное исключение никогда не выводится наружу. Никакие token/UID/provider response не печатаются. Обычный полный `--execute-read` сохраняет прежний обобщённый отказ. Все проверочные тесты синтетические; необходимость живого smoke сохраняется.

## Реальный запуск на авторизованном Linux VPS после установки OAuth

1. У владельца **уже был** подтверждён сайт YFC в UI Webmaster. Не создавать снова verification-файлы или другой сайт. Официальный [OAuth guide](https://yandex.ru/dev/webmaster/doc/ru/tasks/how-to-get-oauth): отдельное приложение, redirect `https://oauth.yandex.ru/verification_code`, scope `webmaster:hostinfo` для только чтения. Если для **явно согласованного управления** позднее потребуется `webmaster:verify`, предоставить её отдельному специально ограниченному клиенту и проверить операции/квоты, не переводить read-collector на все permissions по умолчанию.
2. После регистрации/предоставления OAuth владелец должен **локально** поместить токен в root/owner-privileged Linux file, например `/var/lib/hermes-seo/private/yandex-oauth-token`, с владельцем соответствующего отдельного `hermes-seo` OS пользователя и `chmod 0600`. **Не** вводить OAuth token в чат, GitHub, открытые переменные CI, командную строку или BRC sandbox. Проверить OS identity, file ACL и ограниченный исходящий маршрут.
3. На проверенном Hermes checkout с зафиксированным commit SHA и установленным Python запуск **без GET**:
   
   ```sh
   python3 -B -m marketing.yandex_webmaster_direct --date 2026-10-23
   ```

   Должен вернуть `NOT_EXECUTED`. Для первого **разрешённого живого чтения** из *авторизованной host-level* учётной записи:
   
   ```sh
   python3 -B -m marketing.yandex_webmaster_direct --date 2026-10-23 --execute-read --token-file /var/lib/hermes-seo/private/yandex-oauth-token
   ```

   Дата примера не должна использоваться для последующих запусков без обновления. **Это инструкция, не свидетельство того, что команда уже запущена.** CLI не пишет файлы/таймеры.
4. Проверить `LIVE_GET_RESPONSE_UNATTESTED` и частный receipt. Если OAuth получен от другого аккаунта, сайт `NOT_VERIFIED`, primary mirror отличается, возвращён неизвестный контракт — **остановить**, не дополнять данные предположениями.
5. Для полноценного SEO management после verified evidence: открыть Issue/PR в **YFC**, сохранить canonical/robots/privacy/structured-data/editorial guardrails, сравнить Google/Яндекс отдельно, вносить ограниченные исправления с CI и monitoring. Для YFC #322 **owner READY перед публикацией остаётся обязательным**. SEO write API Яндекса (например priority Sitemap recrawl) — **НЕ реализован** этим read probe; отдельный API executor может получить `webmaster:verify` только после конкретного security/impact/quotas review. [Sitemap recrawl ограничен 10 запросами в месяц](https://yandex.ru/dev/webmaster/doc/ru/reference/host-priority-re-crawl-sitemap), не использовать автоматически ради «продвижения» или после каждого deploy. Wordstat Search API v2 не включать — может потребовать отдельной оплаты.

## Границы достоверности

Эта реализация тестирует форму + приватность + доступную цепочку GET, **не проверяет** валидность реального OAuth, owner host connection, реальную индексацию/запросный спрос, billing, полноту официальной выгрузки и фактическую применимость `main_mirror` к YFC. Отсутствие query rows != 0 показов. PR/CI/исходный код на VPS не включают ни OAuth, ни timer. Локальные YFC PR или production-изменения не создаются без наблюдаемой причины. Source code shipment ≠ live SEO-automation.
