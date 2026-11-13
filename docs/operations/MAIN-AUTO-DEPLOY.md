# Hermes: ручная доставка утверждённого main SHA на VPS (#238)

## Договорённость

Merge в `main` и завершение CI не запускают production. Владелец отдельно утверждает полный cumulative release и его текущий SHA `main`; изменения могут ожидать выпуска в `main`. Оператор вручную запускает `.github/workflows/production-deploy.yml` через `workflow_dispatch`, выбирает `main` и передаёт утверждённый 40-символьный `release_sha`. Workflow отвергает несовпадение выбранной ревизии, утверждённого SHA или текущего `main`, а также отсутствие успешных `Hermes repository checks` и `Hermes Control Center UI` для этого SHA. Успешный CI не заменяет разрешение владельца. Запуски сериализуются одним `concurrency` group.

Проверки SHA не блокируют параллельные merge атомарно: на время разрешённого выпуска оператор должен исключить изменение `main` и при его изменении получить новое утверждение. Первоначальная установка серверной команды и ограниченного SSH-доступа выполняется отдельно оператором.

## Границы

- Доставляются только уже существующие разрешённые активные Hermes Ops Watch, QA Advisor, Research Scout, Control Center и офлайн-модули.
- Не включать resident AI, Cloudflare proxy, OAuth broker, новые интеграции, публикации или платные запросы. Изменения служб/systemd/Caddy также требуют отдельного решения.
- Сервер получает архив по стандартному вводу SSH, сверяет SHA-256 и embedded git commit SHA, отвергает нестандартные tar entries и попытки перехода из каталога.
- Все Python-проверки свежеполученного архива выполняются через временные непривилегированные systemd-юниты с `PrivateNetwork=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `NoNewPrivileges=yes`, ограничениями памяти и времени. Быстрые предварительные проверки используют `DynamicUser=yes`; **полный** набор Python-тестов с реальными проверками ядра `openat2` использует статические UID/GID `65534:65534` (nobody), `CapabilityBoundingSet=` и `RestrictSUIDSGID=no`: systemd при `DynamicUser=yes` принудительно включает seccomp-правило `RestrictSUIDSGID=yes`, которое возвращает `ENOSYS` для `openat2`. Никакого отключения тестов или выполнения кода архива от root.
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
3. Объединить PR после зелёного CI; deploy при этом не запускается. После отдельного разрешения владельца на текущий cumulative SHA выполнить ручной `workflow_dispatch` с `release_sha`, затем проверить Actions run, deployed SHA, receipt и работающие таймеры.
4. Только после отдельного разрешения повторить через `workflow_dispatch`: ожидается `ALREADY_DEPLOYED=<sha>`, без повторного развёртывания.
5. При красном workflow: не включать bypass и не запускать агента, проверить журналы и вернуть последний рабочий релиз.

Внимание: `main` в приватном репозитории исторически не был защищён GitHub branch protection (настройка зависела от тарифных прав). Проверять фактическую защиту отдельно; ручной выпуск не заменяет ревью и CI при merge.


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
4. После отдельного разрешения владельца на актуальный cumulative SHA выполнить повторную идемпотентную доставку через workflow_dispatch с `release_sha`, проверить ALREADY_DEPLOYED, точный receipt, /healthz, таймеры, что resident Agent и proxy НЕ запущены, внешний Control Center, Second Brain и реальную browser-сессию GitHub OAuth владельца. Эти live-проверки и доступ к приватным системам требуют соответствующих разрешений; проверки без browser-сессии не доказывают OAuth.

### Откат обработчика

Владелец вызывает отдельную root-only процедуру из проверенного checkout. Предварительно независимо подтвердить SHA обоих файлов (текущего и root-only backup):

~~~bash
sudo bash deploy/provision-main-deploy.sh --rollback-handler \
  "CURRENT_HANDLER_SHA256" "PREVIOUS_HANDLER_SHA256"
sudo sha256sum /usr/local/sbin/hermes-main-deploy
~~~

Скрипт отклоняет неправильный текущий digest, повреждённый backup или symlink; устанавливает предыдущую версию атомарно. Не меняет SSH ключи, sudoers, Caddy, Cloudflare, OAuth credentials, systemd, Ops Watch или Second Brain. После rollback повторяются syntax, forced-command refusal, health и receipt проверки. Не использовать непроверенный репозиторий, CI или входящий deploy архив для самообновления handler. Если нет root доступа или SHA ревью - операторский этап BLOCKED до выполнения этих условий.

## 2026-11-06: серверный тестовый бюджет после отказа выпуска #454

При выпуске утверждённого `4bed76151d0486da2d2a87464e2d7905d010ccc0`
через [GitHub Actions #42272349433](https://github.com/MikeMoore1337/hermes/actions/runs/42272349433)
доверенный обработчик прошёл проверки SHA, архива, структуры, политики и Markdown,
но изолированная группа unit-тестов остановилась ровно через 360 секунд с
`OFFLINE_UNIT_SUITE_FAILED_OR_TIMED_OUT`. Локальный журнал тестов очищен
обработчиком; причина отдельных тестов не установлена. Исходный релиз
НЕ БЫЛ установлен: `last-success.sha` и Control Center остались на
`7cc4237721107434425c0e7638606aeb6296e253`, `/healthz` вернул 200,
шесть утверждённых таймеров остались активны.

Исправление повышает **только** `RuntimeMaxSec` полной обязательной группы
с 360 до **540 секунд**. Это ограниченный бюджет в пределах неизменного
20-минутного workflow; лимит 240 секунд для быстрых проверок сохраняется.
`DynamicUser`, `PrivateNetwork`, `ProtectSystem`, `NoNewPrivileges`,
`MemoryMax`, `TasksMax`, проверка полного `OK` и откат не изменяются.
Новый лимит не гарантирует завершения: при повторном отказе нельзя
продлевать его снова без анализа тестов и нагрузки.

**Особенность эксплуатации:** `/usr/local/sbin/hermes-main-deploy` является
отдельно установленным root-owned обработчиком, не обновляемым GitHub
source deploy. Слияние PR само по себе **не** меняет лимит на VPS.
Установка новой версии требует независимого SHA-256 кандидата, отдельного
разрешения владельца, штатной команды
`deploy/provision-main-deploy.sh --install-handler <reviewed-sha256>`,
сохранения прежней версии в `/usr/local/lib/hermes-main-deploy-versions`
и проверки установленного хеша/доступного отката. Для отката предусмотрен
`--rollback-handler <current-sha256> <previous-sha256>` с теми же
проверками. Не выполнять root-установку через обычный GitHub deploy;
новый source SHA также требует отдельного утверждения.

## 2026-11-12: H454 openat2 в изолированном production-тесте

На оригинальном Hermes VPS при проверке релиза `14779540c69d6e1fad8b37046577b985dae6f44c` полный набор тестов завершился `FAILED (failures=19, errors=37, skipped=4)`; исходники не установлены, фактический `last-success.sha` остался `94d888acb3ac2a29ca248614bfc63669e77402ca`. Независимое воспроизведение в том же `systemd-run` подтвердило: `PATH_SYSCALL=ENOSYS`, `READ_SYSCALL=ENOSYS`, `STAT=DENIED`, `LIST_ENTRIES=0`. Это не достаточное основание отключать `openat2`: именно он обеспечивает `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV` без TOCTOU.

Причина: `DynamicUser=yes` неотключаемо включает `RestrictSUIDSGID=yes`; для `openat2` системная политика seccomp отвергает системный вызов целиком. Источник: [systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) (раздел `RestrictSUIDSGID`), [systemd #38711](https://github.com/systemd/systemd/issues/38711).

Доверенный серверный обработчик `deploy/hermes-main-deploy.sh` теперь выбирает:
- `DynamicUser=yes` для трёх быстрых проверок архива.
- Статический непривилегированный `User=65534`, `Group=65534`, `DynamicUser=no`, `RestrictSUIDSGID=no` только для полной группы unit-тестов, **с неизменёнными** `PrivateNetwork=yes`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `MemoryMax=1G`, `TasksMax=128` и `RuntimeMaxSec=540`. Дополнительно `CapabilityBoundingSet=` удаляет все Linux capabilities, а проверка `id nobody` требует точные UID/GID `65534:65534`.
- Если оригинальная система не поддерживает `openat2` и без этого фильтра, проверки по-прежнему **FAIL CLOSED**; нет подмены `openat2` на `openat`, `skip`, отключения unittest или искусственного PASS.

**Порядок выпуска:** source-only PR/merge/CI сами по себе не устанавливают новый обработчик `/usr/local/sbin/hermes-main-deploy`. Старый обработчик работает отдельно от исходного релиза и при очередном обычном workflow снова вызовет `DynamicUser=yes`. Поэтому требуется отдельный точный SHA-256 файла `deploy/hermes-main-deploy.sh`, целевое разрешение владельца на **привилегированную установку обработчика**, штатное `deploy/provision-main-deploy.sh --install-handler ...` с сохранением предыдущей версии и проверкой отката. Источник обработчика может быть взят только из независимо сверенного Git checkout точного approved source SHA, не из последнего НЕ установленного release. Только после реального теста в изоляции с `User=65534`, проверки нового обработчика и нового **одобренного** SHA релиза допустим повторный production-deploy workflow.

Исходные BRC/WSS, native agent и сохранённый маркер предыдущего переключения не меняются.


### 2026-11-13: предотвращение ошибок фикстур после устранения openat2

После применения исправленного обработчика полный набор unit-тестов VPS больше не
отказывает на просмотре и поиске файлов, однако новая попытка
[Actions #43318869651](https://github.com/MikeMoore1337/hermes/actions/runs/43318869651)
остановлена на `FAILED (failures=2, errors=18, skipped=4)`. Ошибки относятся
преимущественно к синтетическим Linux runtime и Windows worker тестам.
Оригинальный выпуск не был подтверждён как установленный.

При `User=65534` у системного пользователя `nobody` домашний каталог
`/nonexistent`; тесты приватного Linux manifest создают файлы
`TemporaryDirectory(dir=Path.home())`. Только для полного unit-набора
`systemd-run` теперь создаёт отдельный частный каталог
`RuntimeDirectory=hermes-main-deploy-tests`, `RuntimeDirectoryMode=0700`
и выставляет `HOME=/run/hermes-main-deploy-tests`. Каталог создаётся до
запуска Python с тем же UID/GID и удаляется systemd после временной службы.
`ProtectHome=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`,
`PrivateNetwork=yes`, `CapabilityBoundingSet=`, `NoNewPrivileges=yes`,
лимиты и запреты доступа к реальным проектам не ослабляются. При невозможности
создать каталог все проверки по-прежнему отклоняют выпуск.

В `tests/test_h454_native_win32_worker.py` время `NOW` ранее вычислялось
однократно при импорте модуля; срок тестового bearer был только +200 секунд,
а полный набор на VPS выполняется около шести минут. Фикстура теперь
вычисляет время при `setUp` каждого теста, не меняя TTL, формат, проверку
срока действия или код production-авторизации. Добавлена регрессия на
свежесть синтетического bearer.

Изменение доверенного серверного обработчика остаётся отдельной привилегированной
операцией: обновление в Git/CI само по себе не изменяет
`/usr/local/sbin/hermes-main-deploy`. Нужны независимый SHA-256, проверка
временной изоляции на оригинальном VPS, отдельное разрешение владельца,
сохранение предыдущей версии и новый exact-SHA выпуск. Никаких BRC/WSS,
OAuth, реальных токенов или нативных служб это не активирует.

### 2026-11-13: исправление тестового HOME после повторной диагностики

Повторная оригинальная VPS-проверка подтвердила `HOME_ENV_MATCH=True`,
`PATH_HOME_MATCH=True`, `RUNTIME_DIR_MATCH=True`, `HOME_OWNER_MATCH=True`,
`HOME_MODE=0o700`, `HOME_TEMP_WRITE=PASS`, однако два позитивных Linux native
runtime-теста завершились `RuntimeDenied(native_linux_runtime_denied)`.
Проблема была не в правах. Фикстура ставит `roots` равным вложенному пути
`Path.home()`, а `device_fabric/native_install_preview._linux_root` правильно
запрещает весь префикс `/run` через `BLOCKED_LINUX_ANCESTORS`.

Запрет `/run` НЕ снимается. Для полной непривилегированной группы тестов
`systemd-run` теперь создаёт только пустую служебную директорию
`CacheDirectory=hermes-main-deploy-tests` (режим `0700`) в
`/var/cache` и монтирует поверх неё ограниченную частную `tmpfs`:
`TemporaryFileSystem=/var/cache/hermes-main-deploy-tests:rw,nosuid,nodev,size=64M,mode=0700,uid=65534,gid=65534`.
При запуске выставляется `HOME=/var/cache/hermes-main-deploy-tests`.
`/var/cache` не входит в заблокированные root-префиксы; вложенные тестовые
папки обеспечивают атомарные проверки прав и реальный kernel `openat2`.
Содержимое HOME не записывается на постоянный диск, монтирование завершается
вместе с transient unit; на диске остаётся только пустая служебная директория
режима `0700`. `PrivateNetwork`, `ProtectHome`, `PrivateTmp`,
`ProtectSystem=strict`, `NoNewPrivileges`, `CapabilityBoundingSet=`,
лимиты и запрет обхода тестов остаются.

**Важное условие:** прежде чем устанавливать обновлённый root-owned handler,
проверить реальные `CacheDirectory` + `TemporaryFileSystem` на исходном VPS
в отдельной временной systemd-службе с теми же ограничениями. Установка
обработчика - отдельная авторизуемая операция с SHA-256 и штатным откатом.
Новый source-only релиз - отдельное разрешение, CI и приёмка. Изменение
не даёт прав на BRC/WSS cutover, сопряжение или активацию Linux/Windows agents.
