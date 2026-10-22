# Hermes: автоматическая доставка green main на VPS (#238)

## Договорённость

GitHub Actions `.github/workflows/production-deploy.yml` принимает события завершения успешных `Hermes repository checks` **и** `Hermes Control Center UI` (только `push` в `main`). Если UI-проверка необходима, но ещё выполняется, запуск автоматически откладывает доставку без ошибок и без запуска SSH; завершение UI повторно инициирует проверку того же SHA. Это устраняет ложный пятиминутный отказ при долгой загрузке браузера в CI. При ручном `workflow_dispatch` применяется тот же контроль CI. Доставка разрешается только для **актуального** SHA `main`; для UI-изменений требуется также успешный `Hermes Control Center UI` того же SHA. Все события сериализуются одним `concurrency` group.

Рабочий компьютер владельца для автоматической доставки не нужен. Первоначальная установка серверной команды и ограниченного SSH-доступа выполняется отдельно оператором.

## Границы

- Доставляются только уже существующие разрешённые активные Hermes Ops Watch, QA Advisor, Research Scout, Control Center и офлайн-модули.
- Не включать resident AI, Cloudflare proxy, OAuth broker, новые интеграции, публикации или платные запросы. Изменения служб/systemd/Caddy также требуют отдельного решения.
- Сервер получает архив по стандартному вводу SSH, сверяет SHA-256 и embedded git commit SHA, отвергает нестандартные tar entries и попытки перехода из каталога.
- Все Python-проверки свежеполученного архива выполняются через временный systemd unit с `DynamicUser=yes`, `PrivateNetwork=yes`, `ProtectSystem=strict`, `NoNewPrivileges=yes`, бюджетом памяти и времени. **Не выполнять код архива от root.**
- Только после зелёного полного unittest серверная доверенная команда обновляет разрешённые каталоги, сохраняет резервные копии и атомарно переключает Control Center. Ошибки до фиксации релиза вызывают rollback.
- Не полагаться на содержимое PR или зелёный GitHub CI как на доказательство deployed; успех - строка `PRODUCTION_DEPLOYED=<sha>`, receipt, проверка localhost `/healthz` и активности таймеров.

## Первый запуск на уже утверждённом VPS

Оператор из **проверенного checkout точного PR HEAD** переносит обе подписанные своим ревью процедуры на VPS, затем в привилегированном SSH-сеансе выполняет команду начальной установки с обязательным независимым SHA-256: `bash deploy/provision-main-deploy.sh --initial-setup <reviewed-handler-sha256> < /path/to/restricted-deploy-key.pub`. Одноразовый установщик создаёт пользователя `hermes-deploy`, устанавливает root-owned `/usr/local/sbin/hermes-main-deploy` (`0750`), ограниченное `sudoers` и SSH-ключ с `restrict,command="..."`; проверяет отказ для чужой команды. Нельзя выполнять установщик из недоверенного архива или передавать закрытый ключ на сервер. GitHub Actions Secrets и проверка реального входа отдельным ключом требуются после установки.

На GitHub в Repository Settings → Secrets and variables → Actions создаются четыре закрытых секрета:

| Имя | Содержимое |
| --- | --- |
| `HERMES_DEPLOY_KEY` | Закрытый ED25519 ключ исключительно для ограниченной доставки |
| `HERMES_DEPLOY_TARGET` | Отдельный SSH user@host для delivery |
| `HERMES_DEPLOY_PORT` | SSH-порт этого хоста |
| `HERMES_DEPLOY_KNOWN_HOSTS` | Точное `known_hosts` соответствие подлинному ключу сервера, сверенному независимо от сети |

Секреты не копируются в репозиторий, pull request, отчёт, stdout CI или лог сервера. При утечке ключа: удалить соответствующую запись на сервере, отозвать GitHub Secret и создать новые credentials.

Для ограниченного аккаунта `hermes-deploy` использовать строго `sudoers` на единственную root-owned команду; поддерживать `SSH_ORIGINAL_COMMAND` исключительно для разбора формата `deploy <40-hex-sha> <64-hex-sha256>` и не передавать её в shell как произвольную команду.

## Приёмка и отказ

1. Проверить `bash -n`, CI PR и реальный sandbox non-root test на VPS.
2. Установить принудительный SSH-обработчик, проверить, что произвольная команда отвергается.
3. Объединить PR после зелёного CI. По факту срабатывания проверить Actions run, deployed SHA, receipt и работающие таймеры.
4. Повторить через `workflow_dispatch`: ожидается `ALREADY_DEPLOYED=<sha>`, без повторного развёртывания.
5. При красном workflow: не включать bypass и не запускать агента, проверить журналы и вернуть последний рабочий релиз.

Внимание: `main` в приватном репозитории исторически не был защищён GitHub branch protection (настройка зависела от тарифных прав). Автодеплой не заменяет ревью и CI при merge и не должен скрывать статус этой защиты.


## Issue #250: readiness и версия привилегированного обработчика

После перезапуска Control Center обработчик ожидает успешный /healthz в течение максимум 20 секунд по монотонным часам Linux (включая сетевые таймауты и паузы). Успех - HTTP 200, непустое тело ответа и активный systemd unit до и после запроса. Transport errors, 401/403/500, остановка сервиса или исчерпание общего бюджета завершаются отказом и прежним rollback. Успешный SHA записывается только после всех проверок и формирования receipt.

### Операторская установка - отдельно от CD

Обычный GitHub Actions deploy и restricted forced-command SSH НЕ могут обновить root-owned /usr/local/sbin/hermes-main-deploy. Привилегированная установка выполняется владельцем после утверждения source SHA, CI и получения независимо проверенного SHA-256 именно файла deploy/hermes-main-deploy.sh. Хеш из неизвестного содержимого VPS **не** является подтверждением проверки.

1. Сверить точный merge SHA, источник и checks. Проверить успешную доставку полного архива текущим работающим обработчиком, exact-SHA receipt и CI run. Новый обработчик в архиве сам себя не устанавливает.
2. В утверждённой папке /opt/hermes-agent-owner/releases/main-APPROVED_MAIN_SHA, проверив происхождение обоих shell-файлов, оператор выполняет:

   ~~~bash
   cd "/opt/hermes-agent-owner/releases/main-APPROVED_MAIN_SHA"
   bash -n deploy/hermes-main-deploy.sh deploy/provision-main-deploy.sh
   sha256sum deploy/hermes-main-deploy.sh
   sudo bash deploy/provision-main-deploy.sh --install-handler "INDEPENDENTLY_REVIEWED_64HEX_SHA256"
   sudo sha256sum /usr/local/sbin/hermes-main-deploy
   sudo stat -c '%U:%G %a' /usr/local/sbin/hermes-main-deploy
   ~~~

   Установленный digest обязан совпасть с заранее зафиксированным независимо от сервера. Владелец и режим: root:root 750. Повторная установка того же SHA ничего не изменяет. Прежний проверенный handler сохраняется root-only в /usr/local/lib/hermes-main-deploy-versions/OLD_HANDLER_SHA256 (каталог 0700), старый экстренный backup не удаляется.
3. Отрицательная проверка restricted SSH должна отвергать любую чужую команду. Локальная проверка forwarding sudo:

   ~~~bash
   sudo runuser -u hermes-deploy -- env SSH_ORIGINAL_COMMAND='not-an-approved-deploy' sudo -n /usr/local/sbin/hermes-main-deploy
   ~~~

   Ожидается exit code != 0 и HERMES_DEPLOY_FAILED: invalid command. Дополнительно проверить фактическую попытку по выделенному ключу. Не передавать произвольные shell-команды.
4. После установки выполнить повторную идемпотентную доставку актуального SHA через workflow_dispatch, проверить ALREADY_DEPLOYED, точный receipt, /healthz, таймеры, что resident Agent и proxy НЕ запущены, внешний Control Center, Second Brain и реальную browser-сессию GitHub OAuth владельца. Проверки без browser-сессии не доказывают OAuth.

### Откат обработчика

Владелец вызывает отдельную root-only процедуру из проверенного checkout. Предварительно независимо подтвердить SHA обоих файлов (текущего и root-only backup):

~~~bash
sudo bash deploy/provision-main-deploy.sh --rollback-handler \
  "CURRENT_HANDLER_SHA256" "PREVIOUS_HANDLER_SHA256"
sudo sha256sum /usr/local/sbin/hermes-main-deploy
~~~

Скрипт отклоняет неправильный текущий digest, повреждённый backup или symlink; устанавливает предыдущую версию атомарно. Не меняет SSH ключи, sudoers, Caddy, Cloudflare, OAuth credentials, systemd, Ops Watch или Second Brain. После rollback повторяются syntax, forced-command refusal, health и receipt проверки. Не использовать непроверенный репозиторий, CI или входящий deploy архив для самообновления handler. Если нет root доступа или SHA ревью - операторский этап BLOCKED до выполнения этих условий.
