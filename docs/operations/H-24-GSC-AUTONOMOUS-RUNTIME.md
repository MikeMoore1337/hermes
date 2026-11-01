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
- URL-строки нормализуются в рамках доменного ресурса
  `sc-domain:your-fitness-coach.ru`: HTTP(S), основной домен и его
  поддомены. Чужие и похожие домены, логин/пароль в URL и нестандартные
  порты отвергаются. Нормализация не выполняет сетевых запросов.
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

## Preactivation - подготовка без OAuth и таймера

После независимого dry-run используем reviewed
[операторский установщик](../../deploy/h191-gsc-runtime-prepare.sh),
который запускается **только из доставленного release** на
Hermes VPS vps1777112993 через ранее разрешённый прямой SSH.
Не использовать BRC, Commander или GitHub deploy-ключ как shell.

Команды от root в разрешённом SSH-терминале (никаких секретов в аргументах):

    set -euo pipefail
    sha="$(cat /var/lib/hermes-main-deploy/last-success.sha)"
    script="/opt/hermes-agent-owner/releases/main-$sha/deploy/h191-gsc-runtime-prepare.sh"
    bash "$script" --plan
    bash "$script" --prepare

Установщик сначала проверяет совпадение release SHA/receipt, root ownership,
отсутствие изменённых исходников и активных GSC units. Затем:

- Создаёт только системного пользователя hermes-gsc, без интерактивного входа
  и дополнительных групп, и каталоги /etc/hermes-gsc (root:hermes-gsc 0750),
  /var/lib/hermes-gsc (hermes-gsc:hermes-gsc 0700),
  /opt/hermes-gsc (root:root 0755).
- Создаёт отдельный root-owned Python venv; устанавливает только binary
  wheels из официального PyPI для google-auth==2.62.0 и requests==2.32.5
  вместе с зависимостями; проверяет версии и pip check. Не запускает apt
  и не изменяет Python других сервисов. Нужен установленный Python 3.10+
  с venv; при отсутствии fail-closed.
- Выполняет CLI dry-run от hermes-gsc без credentials, сети и записи snapshot.
- Только после этого размещает выключенные systemd service/timer,
  проверяет шаблоны и выполняет daemon-reload без start/enable/restart.
  Существующие чужие конфигурации, symlink, небезопасные права и
  непроверенные credentials отклоняются.

Важная граница: **network policy пока DENY_ALL**, а не Google allowlist.
Новый шаблон включает PrivateNetwork=yes, IPAddressDeny=any и
RestrictAddressFamilies=AF_UNIX; никакой OAuth не работает и не должен
работать до отдельного approved egress cutover. systemd IPAddressAllow
не умеет ограничивать исходящие подключения по DNS-именам. Для допуска
только oauth2.googleapis.com:443 и www.googleapis.com:443 необходима
отдельная reviewed OS/transport policy и проверка её реального применения.
Нельзя просто отключать сетевые ограничения для успешного live smoke.

Credentials не создаются и не копируются установщиком. Для последующего
ключа нужен отдельный защищённый канал и разрешение. Файл должен быть
обычным (не symlink), принадлежать hermes-gsc, иметь права 0400/0600
и соответствовать требованиям клиента; его содержимое не помещать в
GitHub, shell history, CI, логи или ChatGPT.

Прямые версии зависимостей закреплены. Транзитивный lock и wheel
SHA256 пока не зафиксированы независимо: перед первым live-запуском
следует провести проверку поставленных зависимостей.

Результат H191_PREPARE=PASS подтверждает только OS identity, каталоги,
venv, отключённые units и dry-run. Это не LIVE_GSC_SNAPSHOT_SAVED и
не AUTONOMOUS_ACTIVE: фактический OAuth, 7 API-вызовов и автоматический tick
требуют отдельных подтверждений и owner gates.

## Закрытая передача существующего Google service-account JSON

**Отдельный owner gate. Не выполнять без разрешения на provisioning secret.**
Учётная запись Google существует по прежним свидетельствам владельца,
но key-файл по штатному пути VPS отсутствует. Не создавать новую Google
учётную запись, секрет или DNS без доказанной необходимости и согласования.
Workload Identity Federation обычно безопаснее постоянного JSON-ключа,
но текущий H-24 клиент рассчитан именно на service-account JSON.

Подготовлены два отдельно запускаемых средства:
- scripts/h191_gsc_key_send.py - локальный Python-отправитель, совместимый
  с Windows и прямым SSH, без PowerShell text pipeline;
- scripts/h191_gsc_credential_provision.py - принимающий скрипт на VPS
  из точно доставленного root-owned Hermes release, в изолированном venv.

До передачи отправитель запрашивает metadata-only статус без секрета.
Разрешены только проверенный SSH host key (StrictHostKeyChecking=yes),
авторизация SSH-ключом (BatchMode=yes), строго заданный root@host и SHA;
ProxyJump/ProxyCommand и пересылка SSH agent отключены. Если ключ уже
существует или preflight не пройден, secret-файл не отправляется.

Пример PowerShell на Windows из доверенного checkout проекта, только
после разрешения владельца на secret transfer и проверки known_hosts:

    py -3 scripts/h191_gsc_key_send.py --key-file "C:\SECURE\existing-service-account.json" --ssh-target "root@YOUR-APPROVED-SSH-HOST" --release-sha "EXACT_40_CHARACTER_DEPLOYED_SHA" --confirm-owner-key-transfer

Пути и SSH-host выбирает и проверяет сам владелец. Не использовать
GitHub Actions deploy-ключ как shell, BRC, Commander, email, чат,
GitHub Issues, общественные файлообменники, env или shell arguments для
содержимого ключа. Скрипт передаёт исходные байты исключительно как stdin
зашифрованного SSH-канала. Флаг подтверждения обязателен.

Приёмник на правильном VPS сверяет hostname, SHA, release receipt, UID/GID,
права /etc/hermes-gsc и уже существующие files. Он проверяет размер,
формат JSON, запрещает повторяющиеся имена полей и чужие token_uri,
валидирует offline private key форматом google-auth из отдельного venv.
Никаких Google network requests. Создаёт
/etc/hermes-gsc/service-account.json строго однократно, mode 0400,
владельцем hermes-gsc, атомарно и без перезаписи существующего файла
или symlink. Секреты не выводятся. Ротация - отдельно согласуемое действие.

Ожидаемое сообщение локального отправителя:

    H191_KEY_TRANSFER=PASS
    H191_GOOGLE_OAUTH=NOT_RUN
    H191_TIMER=NOT_ENABLED

Этот статус означает только credential file metadata READY, не
подтверждение OAuth или доступности GSC property. После получения
реального ключа сохраняется NO_GO на OAuth и systemd timer до review
реально действующего сетевого ограничения.

**Google-only egress ещё не реализован.** В активируемом шаблоне
PrivateNetwork=yes, RestrictAddressFamilies=AF_UNIX и IPAddressDeny=any.
systemd IPAddressAllow принимает IP/CIDR, но не hostname или порт 443.
Для перехода нужен самостоятельный проверенный механизм DNS/IP,
ограничения 443, TLS hostname, negative network tests и отдельный owner GO;
не снимать deny-all ради успешного smoke. Также остаётся независимая
проверка фактически установленных транзитивных wheel dependencies.

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
