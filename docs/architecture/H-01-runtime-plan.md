# H-01: проект безопасного независимого Hermes Agent

## Текущая приёмка H-01 на 17.10.2026 (после PR #266)

**Состояние на момент read-only проверки VPS 17.10.2026 ~20:53 MSK**, canonical deployment SHA
`6b8365704b625a427e575c3ee2b1be8b72e52a4e`. Это отдельный снимок
фактического состояния, а не обещание, что оно останется неизменным.

- Активен **ограниченный event-driven Ops AI**, не unrestricted gateway.
  `hermes-h01-ops-agent.timer` enabled/active, `hermes-cloudflare-proxy.service`
  enabled/active, network guard active; `hermes-agent-sandbox.service` disabled/inactive.
  One-shot service в норме становится `inactive` после успешного завершения.
- Точная базовая версия: NousResearch v0.22.2 AMD64
  `sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05`;
  локальная производная с исправлением native dispatch и без разрешения на
  unrestricted agent. Это **не** upstream-attested derivative.
- Модель - только Workers Free `@cf/openai/gpt-oss-20b` с подтверждённым
  владельцем Free account, cost `NOT_MEASURED`. Только проверенный
  `ADVISOR_CANDIDATE`, максимум один записанный до вызова AI-call в UTC-сутки;
  ноль автоматических retries, tools/MCP/shell/browser, публикаций и paid fallback.
  Обычный порог нагрузки `load1 <= 1.30` не повышен.
- CLI zero-native-tool real Workers AI response `OK`, exit 0, 140.97s:
  [#33, акт 17.10](../audits/H-01-limited-resident-v0222-2026-10-17.md).
  Первые production one-shot cycles: `NO_ADVISOR_CANDIDATE`, 0 model calls.
  Полезный реальный анализ инцидента не наблюдался: `NOT_VERIFIED`.
- **Новый фактический дефект:** журнал systemd за 17.10 фиксирует успешный
  precheck в 19:43, успешный `NO_ADVISOR_CANDIDATE` в 20:00 и отказ таймера
  в 20:33:47 MSK с `Result=start-limit-hit`. Старые
  `OnActiveSec=15min` / `OnUnitInactiveSec=30min` допускали третью
  попытку внутри `StartLimitBurst=2` за `StartLimitIntervalSec=3600`.
  Source timer исправлен на 35/35 минут, без ослабления start limits и дневной
  квоты. **До отдельного одобренного применения установленного systemd unit
  production остаётся на прежнем таймере**. Не сбрасывать failures/journals
  и не перезапускать приёмку #33 автоматически.
- 24-часовую стабильность проверяет **только #33** 18.10.2026 16:44 UTC.
  При имеющемся `start-limit-hit` вердикт стабильности **не PASS**; нужны
  подтверждённые последующие запуски, исправление и оценка окна приёмки.

### Матрица доказательной приёмки Issue #2

| Критерий | Статус | Доказательства на 17.10.2026 | Осталось |
| --- | --- | --- | --- |
| Размещение и ресурсы | PARTIAL | Утверждённый Hermes VPS, 3915 MiB RAM, фактическая установка v0.22.2 по #33; bounded Docker | Полный 24h load/recovery #33 |
| Независимая OS identity | PARTIAL | Docker runtime nonroot UID 10000, no host Docker socket mount; wrapper systemd `User=root` | Отдельно зафиксировать границу привилегированного host launcher и негативные проверки |
| Изоляция storage/secrets | PARTIAL | Restricted `/etc/hermes-agent/h01-image.env`, `/var/lib/hermes-h01`, read-only Ops state и отделённый Cloudflare secret, ограничения в unit и launcher | Повторить production-negative scope/mount tests в рамках #33 |
| Runtime и закреплённые версии | PASS | [Акт установки v0.22.2](../audits/H-01-limited-resident-v0222-2026-10-17.md), точные базовый OCI digest и derived image ID | Полный provenance/SBOM перенесён в #185/#199 |
| Границы инструментов и сети | PARTIAL | `-t bot_room`, patched native dispatch synthetic deny, internal bridge, nft guard, no fallback | Нет доказательства unrestricted MCP/OS boundary; не включать |
| Zero-tool и model smoke | PASS | Реальный VPS CLI v0.22.2/Workers Free exit 0, 140.97s; отдельные offline mock turns #260/#261 | Полезный production incident cycle ещё не наблюдался |
| CPU/RAM и таймауты | PARTIAL | Docker `--memory 640m --cpus 0.30`, oneshot `TimeoutStartSec=220`, `load1 <= 1.30` | 24h peak и enforcement/восстановление #33 |
| Перезапуск и восстановление | BLOCKED | Reboot guard/network ранее PASS (14.10); 17.10 systemd `start-limit-hit` на активном one-shot | Применить timer fix без потери истории; доказать восстановление по #33 |
| Rollback | PARTIAL | Остановка timer/service/proxy без удаления квот и state описана ниже и в операционных инструкциях | Реальный rollback именно ограниченного H-01 не проверен; согласовать в #33 |
| Независимость от YFC | PASS | Отдельный Hermes VPS/контур, YFC news/Second Brain credentials не подключены по #33, другие Hermes timers активны | Мониторить регрессии в 24h |
| CI и production CD | PASS | [Quality CI #39053006896](https://github.com/MikeMoore1337/hermes/actions/runs/39053006896), [UI #39053006855](https://github.com/MikeMoore1337/hermes/actions/runs/39053006855), [CD #39053067822](https://github.com/MikeMoore1337/hermes/actions/runs/39053067822); VPS canonical SHA совпал | Новый source fix требует собственного exact-SHA CI/CD; источник != applied unit |
| 24-часовая стабильность | DEFERRED | [#33](https://github.com/MikeMoore1337/hermes/issues/33), контроль 18.10.2026 16:44 UTC | Фактическая оценка журналов/нагрузки и принятие/отказ |
| Статусы и наблюдаемость | PARTIAL | [PR #266](https://github.com/MikeMoore1337/hermes/pull/266) разделяет limited H-01 и unrestricted NO-GO; журнал systemd выявил failure | Показать и подтвердить recovery, useful_cycle по реальному incident |

**Вердикт родителя #2: PARTIAL, оставить OPEN.** Узкие runtime-права
сохраняются. Закрытие возможно лишь после принятия #33, устранения
`start-limit-hit` и отдельной сверки критериев. Важно: deferred #185/#199
не становятся функциональными блокерами и не считаются выполненными.

Последующие разделы описывают прежние этапы и гипотезы; их даты сохраняются,
но они **не** заменяют данный текущий снимок.

---

## Исторический срез подготовки 17.10.2026 (до включения ограниченного H-01)

Целевой upstream для нового контура - **v0.22.2**, Linux/AMD64 `nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05`. Старый v0.21.6 используется только как историческое доказательство smoke от 11.10.2026. `deploy/smoke.sh` проверяет официальный v0.22.2 без сети/модели. `deploy/run-agent-sandbox.sh` и `deploy/smoke-cloudflare-agent.sh` теперь не могут молча использовать старый либо непатченный образ: нужен операторский полный local image ID производного v0.22.2 с применённым патчем native-tool dispatch. Патч, метки образа и статические проверки - **не** подтверждение полноценной runtime isolation.

Resident agent **не активирован**, `hermes-agent-sandbox.service` по умолчанию выключен. Workers Free признан владельцем по ADR-0002; это не снятие требований свежей live-квоты, отдельных разрешений на новую службу/egress и ограниченного burn-in. Нижеследующее описание версии v0.21.6 относится к историческому обследованию 11.10.2026.


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
