# H-24 / #191 - самостоятельное read-only получение GSC Hermes

Статус: **код подготовлен; реальный Google OAuth / Hermes VPS timer не активированы**.
Эта инструкция дополняет [H-24 historical Windsor evidence](H-24-GSC-READONLY-EVIDENCE.md).

## Почему прямой источник, а не Windsor.ai

19.10.2026 официальный клиент Windsor.ai в ChatGPT подтверждён для
`sc-domain:your-fitness-coach.ru`. Но текущий Windsor.ai account
`TRIAL`, scheduled destination tasks отсутствуют, доступные назначения
требуют новой настройки и не поддерживают создание из чата.
Подключённые Remote Desktop Commander устройства были OFFLINE.
Ни существующий коннектор ChatGPT, ни сессия владельца не могут
использоваться как учётные данные Hermes на VPS.

**Решение:** отдельная сервисная учётная запись Google с единственным
OAuth scope `https://www.googleapis.com/auth/webmasters.readonly`
и доступом только к GSC property. Google-auth используется лишь для
получения OAuth2 access token; все действия API строго read-only.
Не выдавать сервисной учётной записи роль администратора Google Cloud
и не добавлять OAuth write scopes; минимальная GSC permission
`Restricted user` там, где она позволяет необходимые чтения.
Если Google требует более широкую роль, не расширять автоматически;
сначала сверить и согласовать права.

**Важное разграничение:** одобрение разработки не создаёт саму
Google Cloud service account, не даёт согласия на расходы, не
создаёт key-файл и не является проверкой доступа к property.
Это выполняется отдельно владельцем в официальном интерфейсе Google;
не пересылать ключ в ChatGPT, GitHub, Issues или CI.

## Что реализовано

- `marketing/gsc_direct.py`: последовательный one-shot клиент, строго
  **7 HTTP-вызовов за один запуск**:
  `POST searchAnalytics.query` site / date / page / query / country /
  device (6 отчётов) и `GET sitemaps` (1 отчёт). Никаких
  `PUT/DELETE`, inspection, indexing, запросов к другим хостам,
  массовой пагинации, retries или внешних AI.
- Дата отчётности: `America/Los_Angeles`. Окно 28 дней до вчера
  по этой зоне, `dataState=final`. Данные последних суток могут
  отсутствовать; это не ноль. Реальный последний наблюдаемый день
  устанавливается по доступным date-rows, **не доказывает полноту**.
- Жёсткие ограничения: максимум 250 top rows на отдельный отчёт,
  один проход без пагинации, 50 sitemap, 384 KiB на ответ,
  8 секунд на один API-вызов, 100 секунд на unit.
  Конечный лимит, никакого retry storm. HTTP 400/401/403/404/429/5xx,
  timeout и невалидный JSON приводят к отказу без записи частичного
  результата. Утечки из ошибок provider исключены.
- `google-auth` запрашивает **только** `webmasters.readonly`.
  Файл сервиса должен быть обычным файлом, без symlink,
  с приватными POSIX permissions (например, 0400 или 0600),
  не больше 32 KiB, `type=service_account` и точным token endpoint.
  Хранится **вне git**. OAuth refresh и Google API выполняются
  через outbound TLS (после отдельного допуска).
- Только после **реального** OAuth2 и семи успешных API ответов
  результат помечается `provider_verified=true` и
  `live_api_used_by_hermes=true`, в отличие от offline fixtures.
  Снимок атомарно сохраняется `0600` в private storage;
  промежуточный результат никогда не публикуется.
- `scripts/hermes_gsc_collect.py`: `--dry-run` без credentials и сети,
  обычный запуск с обязательными путями.
- `deploy/hermes-gsc-readonly.{service,timer}`:
  **только неактивные шаблоны**, не включаются автоматически
  в main deploy. Таймер рассчитан на один запуск в день около 09:40 UTC
  с bounded jitter. Первоначальную активацию и ограничения egress
  проводить отдельно. Не переносить содержимое Google key в env
  или unit, не раскрывать в `journalctl`.
- `deploy/requirements-gsc-readonly.txt`: зависимости отдельного
  ограниченного venv, не добавляются в Hermes Agent/YFC.
  Перед установкой подтвердить актуальность пакетов, pin и отсутствие
  неразрешённых платных сетевых вызовов. Установка в runtime не
  производится при GitHub merge.

## Что оператору предстоит сделать (owner activation gate)

1. В Google Cloud Console создать (или выделить существующую)
   сервисную учётную запись с **Google Search Console API enabled**.
   Проверить стоимость / billing policy. Для GSC API не нужен платный
   провайдер рекламы или Windsor.ai. Не создавать новый Cloud project,
   если уже есть безопасно подходящий.
2. В Search Console → `sc-domain:your-fitness-coach.ru` →
   Settings → Users and permissions добавить адрес сервисной учётной
   записи как пользователя с минимальной читательской ролью, проверить
   доступ. Не менять DNS, канонические URL, robots или sitemap.
3. Создать отдельный service-account key **через официальный Google UI**
   только если невозможно безопаснее получить credentials через
   Workload Identity. Хранить в root/private provisioning-процедуре,
   затем установить на VPS в `/etc/hermes-gsc/service-account.json`,
   без GitHub/Gmail/ChatGPT. Не публиковать key/refresh/access token.
4. Отдельный операторский preflight для VPS:
   выделить `hermes-gsc` identity, storage `/var/lib/hermes-gsc`,
   `/opt/hermes-gsc/venv` с pinned google-auth/requests,
   проверить доступ только к `oauth2.googleapis.com:443`
   и `www.googleapis.com:443`. ОС policy должна обеспечивать
   egress ограничения (не просто декларации в unit).
   **Не менять H-01 #33/Cloudflare/YFC active units.**
5. Сначала `--dry-run`. Затем **один разрешённый live smoke**
   с output `/var/lib/hermes-gsc/latest.json`, под sandbox user
   и с установленным бюджетом, например:
   ```bash
   /opt/hermes-gsc/venv/bin/python -m scripts.hermes_gsc_collect --dry-run
   /opt/hermes-gsc/venv/bin/python -m scripts.hermes_gsc_collect \
     --credentials /etc/hermes-gsc/service-account.json \
     --output /var/lib/hermes-gsc/latest.json
   ```
   Проверить `status=LIVE_GSC_SNAPSHOT_SAVED`, 7 запросов,
   `source_kind=gsc_api_live`, корректную property и
   freshness/NO_DATA, permission deny-tests, отсутствие секретов
   в логах. Историческое показов 16 на 03-16.10 - не эталон
   для другой даты/окна.
6. Лишь при успешном реальном запуске и проверенном egress policy
   установить и включить `hermes-gsc-readonly.timer`.
   Проверить один фактический systemd tick, exit 0, созданный
   файл, свежесть, отсутствие вмешательства в другие Hermes/YFC таймеры.
   Rollback: `systemctl disable --now hermes-gsc-readonly.timer`,
   `systemctl stop hermes-gsc-readonly.service` без удаления
   исторического evidence или изоляционных настроек.

**Не запускать unit и не изменять production даже с готовым файлом,
если не завершены owner credentials, budget, egress и live smoke.**
Владелец уже подтвердил Wordstat/YFC/GSC исторические данные;
повторно эти evidence не запрашивать.

## Статусы исполнения и измерений

Отдельно учитывать:
- `OFFLINE_ONLY`: модуль и тесты доставлены, но credentials отсутствуют.
- `CREDENTIALS_READY`: secret установлен с безопасными правами,
  но живой доступ не доказан.
- `LIVE_VERIFIED`: service account получила access token и реальные
  данные 7 GSC вызовов, результат записан.
- `AUTONOMOUS_ACTIVE`: отдельный systemd timer подтверждён,
  произошёл хотя бы один успешный **автоматический** вызов.
- `BLOCKED`: любая ошибка credentials, прав, квоты, таймаута,
  missing final data или запретов сети. Ошибка не становится нулём
  трафика или утверждением «индексации нет».

Отчёты query/top rows частичны. Сумма показов на страницах может
отличаться от site total. CTR и средняя позиция не складываются;
частоты Wordstat, показы Яндекс Вебмастера и GSC изолированы.
Состояние индексации может быть получено только отдельным
URL Inspection API и **не реализуется автоматически #191**.
У YFC #320 evidence gate остаётся `DEFER` до содержательных
наблюдений, публикация YFC #322 требует owner READY.

## Воспроизведение тестов

```bash
python3 -m unittest tests.test_marketing_gsc_direct tests.test_marketing_gsc_analytics -v
python3 -m scripts.hermes_gsc_collect --dry-run
```

В CI нет сетевых запросов, реальных Google credentials и VPS прав.

Официальные источники:
- https://developers.google.com/webmaster-tools/v1/prereqs
- https://developers.google.com/webmaster-tools/v1/how-tos/authorizing
- https://developers.google.com/webmaster-tools/v1/searchanalytics/query
- https://developers.google.com/webmaster-tools/limits
- https://developers.google.com/webmaster-tools/v1/sitemaps/list
- https://googleapis.dev/python/google-auth/latest/reference/google.oauth2.service_account.html
