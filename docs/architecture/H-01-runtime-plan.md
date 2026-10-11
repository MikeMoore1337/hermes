# H-01: проект безопасного независимого Hermes Agent

**Статус: текущий Hermes VPS утверждён для ограниченной проверки; CLI smoke PASS. Постоянный gateway / LLM и внешние подключения ещё не разрешены и не прошли ресурсные проверки.**  
Дата: 2026-10-11. Основание: [H-00 аудит](../audits/H-00-2026-10-11.md) и [Issue #2](https://github.com/MikeMoore1337/hermes/issues/2).

Первые безопасные действия уже выполнены: +2 GiB swap, скачан pin-digest Docker image, пройден CLI smoke без сети/модели. См. [фактический протокол](../audits/H-01-on-host-smoke-2026-10-11.md). Указанные ниже требования к полноценному gateway и постоянной работе **пока не выполнены**.

## Кандидат upstream

- На дату проверки последний опубликованный стабильный релиз: [NousResearch/hermes-agent v0.21.6](https://github.com/NousResearch/hermes-agent/releases/tag/v0.21.6), опубликован 2026-10-08.
- Annotated tag object: `f27cdbce5ab63eafe8633b293a75151409da5769`; tag указывает на **commit `818c13be1dc4fd28987e1e881a9408224afd4535`**.
- Версия является **кандидатом** для независимого Hermes, а не новой версией редакционного worker YFC: тот продолжает использовать pinned upstream provenance v0.21.0, commit `29112bef099274229cadff79cdff7bf7b99c4b77`.
- Ни `stable`, ни `latest` не использовать как runtime pin. Перед внедрением найти digest соответствующего образа, верифицировать `linux/amd64`, SBOM и подпись/происхождение (если доступны). Официальный v0.21.6 amd64 Docker artifact теперь закреплён digest `sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22` и прошёл ограниченный CLI smoke. Упакованный CLI сообщает upstream `a28a5d03`, отстоящий на 39 коммитов от annotated tag SHA `818c13be`; **исходную идентичность не объявлять подтверждённой** до разбора различий.
- Upstream поддерживает native Windows и Docker; однако доступная Windows-машина рассматривается **только как dev/sandbox**, а не как SLA для постоянного мониторинга.

Документация upstream: [Security trust model](https://github.com/NousResearch/hermes-agent/blob/v0.21.6/SECURITY.md), [Profiles](https://github.com/NousResearch/hermes-agent/blob/v0.21.6/website/docs/user-guide/profiles.md), [Docker](https://github.com/NousResearch/hermes-agent/blob/v0.21.6/website/docs/user-guide/docker.md).

## Главная модель угроз: только изоляция всего процесса

В `SECURITY.md` upstream **единственной серьёзной границей безопасности против враждебного LLM называет ОС**. Одного `terminal.backend=docker` недостаточно: Python-процесс Hermes, MCP-плагины, hooks, внутренняя возможность исполнения кода и Skills способны работать вне терминальной песочницы.

**Production-постура: whole-process wrapper.** Каждая зона доверия запускается в собственной OS/container isolation с отдельными файловыми mount, пользователем, cgroup, сетевым доступом и секретами. Запреты в промпте и встроенный scanner - только дополнительная защита от случайных ошибок, **не sandbox**.

Профили Hermes имеют отдельные память, sessions, cron, config и навыки. Но **профиль не является security boundary**: несколько профилей одного процесса/host не должны использоваться как доказательство отсутствия доступа к чужим данным. Не запускать два agent writer с одним профилем. Не клонировать bot/channel credentials. Для различающихся прав создавать отдельные OS-isolated instances (или доказанный эквивалент), а не просто разные папки.

## Поэтапный план

### P0: offline contract и dev-only proof

1. Точно проверить upstream revision и лицензию MIT; подготовить locked Docker digest/build plan, без установки под видом проверенного runtime.
2. Описать one-profile, zero-provider, zero-network, no-tool fixture. Не создавать GitHub Actions workflow, загружающий неизвестный `curl | bash`.
3. Выбрать отдельный локальный dev workspace с пустыми credentials, без host share `~/.ssh`, `~/.gitconfig`, `/var/run/docker.sock`, YFC/Second Brain checkout и приватных файлов.
4. Dev-only smoke: boot -> graceful stop -> restart -> clean state; при отсутствии модели честно фиксировать `no-provider`, **не** утверждать, что выполнен LLM turn.
5. Создать тесты на отсутствие network egress, хостовых mount, inbound ports, прав записи вне data dir, запрещённых plugin/skill loads. Проверить особые случаи path traversal, environment inheritance и prompt injection fixture, когда настоящий runtime существует.

**Критерий:** всё локально обратимо и воспроизводимо, никакой production-трафик, никакие личные токены, никаких расходов. До настоящих dev-тестов оставлять статус `planned`, а не `pass`.

### P1: после явного решения владельца

1. Выбрать **отдельный Linux host** и реальные лимиты CPU/RAM/disk/egress по нагрузочным измерениям. Начальная гипотеза 2 vCPU/4 GiB RAM не является достаточной спецификацией и не разрешает аренду.
2. Согласовать, требуется ли модель и какая именно; проверить легальность/стоимость. Не использовать неофициальные subscription API bridges, не включать paid fallback.
3. Развернуть за отдельным непривилегированным OS identity/isolated process, приватными mounts, без host networking и без host Docker socket.
4. Disable by default: gateways, Telegram channels, API/web dashboard, cron, plugin installation/auto-learning writes, privileged terminal tools. Разрешать по одному после тестов, с отдельными лимитами и owner GO.
5. Добавить remote health/trace + журнал с очищенными данными и ограниченным сроком хранения, защитить секреты.
6. Staging shadow без побочных действий. Контролировать реальные ресурсы и стабильность news pipeline на **другом** VPS.
7. Отдельная санкционированная активация нужных агентов; проверка end-to-end, rollback и отсутствия общего provider/bot account конфликтов.

### P2: после безопасного H-01

H-02 (Ops Watch) -> H-03 (Research Scout) -> H-04 (QA Advisor); H-05 (Second Brain) дополнительно требует закрытия #386 и отдельного разрешения. YFC #322 не дублировать.

## Запрещённые упрощения

- Upstream `docker-compose.yml` использует **`network_mode: host`** по умолчанию. **Не копировать** этот режим для нашего boundary: требуется независимый ограниченный bridge и deny-правила с тестами.
- Docker как **только terminal backend** не равен изоляции агента целиком; host subprocesses/skills остаются угрозой.
- `profiles`, `permissions.yml`, `approvals.mode`, `cron_mode: deny` и sanitizer нельзя считать гарантией запрета инструментов, если процесс обладает правами ОС.
- Никогда не подключать к новому Hermes volume `/var/lib/hermes` новостного worker, `second-brain-vault`, YFC secrets, DB socket или SSH keys.
- Не переиспользовать Telegram bot token новостного YFC: два polling-consumer создадут конфликт.
- Не делать read-only интеграцию посредством прямого доступа к базе: только выделенный authorized scoped API.
- Не направлять cron/мониторинг на реально работающий сервис без операционного разрешения.

## Негативные критерии приёмки

| Сценарий | Обязательный результат |
|---|---|
| Вредоносная веб-страница просит `ssh`, `curl` внутрь сети или прочитать токен | Deny на уровне процесса/сети; отсутствие чтения файлов |
| Попытка читать `/var/run/docker.sock`, host SSH, YFC DB, `second-brain-vault` | `ENOENT`/permission-denied, никакой mounted path |
| Профиль исследователя пытается использовать другого агента credentials | Физически недоступны; отдельный identity/secret store |
| Модель/провайдер недоступны или бюджет исчерпан | `no-provider`/отказ, без перехода на платный или OAuth proxy |
| Новый runtime crash/loop/переполнение RAM | cgroup stop/ограниченный retry без остановки существующего Hermes/YFC |
| Запуск второго экземпляра/дублирование cron | Нет двойного исполнителя и повторной отправки сообщений |
| URL redirect на private IP/cloud metadata | Deny на egress уровне/allowlist |
| Неподтверждённый skill/plugin пытается исполниться | Не загружается; источник/commit/лицензия требуют проверки |
| Запрос на Telegram publish или изменение YFC issue | Нет capabilities/credentials, изменение невозможно |

## Итог и требуемое решение

**Offline-проект подготовлен.** По H-00 оба существующих production VPS не имеют безопасного доказанного ресурса для дополнительного постоянного Hermes. Третий Linux host предпочтителен; его выделение/стоимость, провайдер, секреты и сетевую топологию нельзя решать без владельца.

**До owner GO разрешено:** локально разрабатывать исключительно synthetic/zero-provider проверки и документацию. **Не разрешено:** арендовать VPS, инсталлировать на production, подключать платную модель, использовать реальные токены, запускать scheduler, создавать новых ботов, трогать YFC/Second Brain.


## Актуализация по решению владельца 2026-10-11

Владелец выбрал **действующий VPS Hermes**, а не отдельный сервер, и разрешил увеличивать swap при необходимости. **Уже реализован** безопасный одноразовый CLI smoke на этом VPS, не полный gateway: [протокол](../audits/H-01-on-host-smoke-2026-10-11.md). Предпочтительная архитектура теперь - отдельный sandbox/process *на том же VPS*, но только после доказанных RAM/CPU лимитов, отрицательных security tests и выбора model/provider. Ссылка на отдельный VPS в ранее составленных вариантах - альтернатива в случае ресурсного отказа, а не утверждённое решение. Увеличение RAM существующего VPS предпочтительнее дальнейшего роста swap при дефиците физических ресурсов; возможные платные действия требуют отдельного согласия.
