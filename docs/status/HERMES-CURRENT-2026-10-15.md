# Hermes - подтверждённое рабочее состояние 15.10.2026

**Фактическая проверка:** VPS `vps1777112993`, 15 октября 2026 года, начиная с 05:34 UTC. Код в main, CI, включённая служба и работающий полезный цикл - **разные состояния**. Этот документ не разрешает новый платный сервис, пересылку приватных данных, публикацию научных выводов и круглосуточный AI Agent.

## Работающие службы на VPS

| Функция | systemd timer | Реально проверено | Статус |
| --- | --- | --- | --- |
| Новостной сбор YFC Hermes | `hermes-discovery.timer` | активен; при последней проверке news service ранее был `Result=success` | **ACTIVE**, владелец runtime по-прежнему YFC |
| Ops Watch collector | `hermes-ops-watch.timer` | активен, запись инцидентов в SQLite | **ACTIVE** |
| Ops Telegram sender | `hermes-ops-alerts.timer` | активен, очередь на момент проверки 0, ранее владелец принял живое test `message_id=4` | **ACTIVE**, естественная доставка по настоящему сбою **НЕ НАБЛЮДАЛАСЬ** |
| QA Advisor CI watcher | `hermes-qa-watch.timer` | активен; первый автоматический tick 15.10.2026 04:25:41 UTC, private main Actions ответил SUCCESS | **ACTIVE**, Issue #5 CLOSED |
| Research Scout metadata | `hermes-research-scout.timer` | активен; **первый самостоятельный** tick 15.10.2026 04:44:20 UTC, 4 публичных запроса, 4 кандидата, 0 ошибок, `MANUAL_REVIEW`, 11 секунд | **ACTIVE**, научная экспертиза и выдача не завершены |
| Cloudflare network firewall guard | `hermes-cloudflare-network-guard.service` | `ensure_cloudflare_egress.py --check` -> `verified, changed=null` | **ACTIVE** |
| Постоянный Hermes AI Agent | `hermes-agent-sandbox.service` | единожды 3 ограниченных model/text/tool-turn PASS; **нет доказанного** безопасного постоянного runtime | **INACTIVE, NO-GO** |
| Выделенный Cloudflare CONNECT proxy | `hermes-cloudflare-proxy.service` | выключен после ограниченных ручных проверок, автоматическое включение запрещено | **INACTIVE by design** |

Фактические подтверждения последних трёх независимых источников:

- [H-02 Telegram](../audits/H-02-autosender-vps-2026-10-14.md), [безопасный тест восстановления](../operations/H-02-SAFE-INCIDENT-TEST.md), [Issue #3](https://github.com/MikeMoore1337/hermes/issues/3).
- [H-04 private Actions](../audits/H-04-private-ci-watch-vps-2026-10-15.md) - PR #85-#89, выполнен и Issue #5 закрыт; фиксированный Actions:read only `main` workflow ID 381262090, одна проверка/15 минут, root-owned файл состояния `0600`; без GitHub write/raw logs. Ошибка API не закрывает ранее зарегистрированный `ci_failed`.
- [H-03 Europe PMC + Crossref](../audits/H-03-research-digest-vps-2026-10-15.md) - PR #81/#90/#91/#92, ежедневный отдельный публичный отчёт в `/var/lib/hermes-research-scout/latest-citations.json` `0600 root`. Три темы, не более 4 GET за один проход (первый день установки мог включать дополнительные проверочные/начальные запуски); первый **автоматический** тик проверен 15.10.2026 07:44:20 МСК, exit 0; следующий на момент проверки был назначен на 19:34 МСК. Регистрация NCBI не требуется. `MANUAL_REVIEW` НЕ научная доказанность и не публикация.

## P0 H-01 - что теперь известно об официальном Docker-образе

- Задокументированный pin официальный `nousresearch/hermes-agent:v0.21.6` linux/amd64 => image id `sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22`, совпадает опубликованный registry digest.
- Image embedded Git source `a28a5d03...` на **39 upstream коммитов позади** одноимённого Git release tag `818c13be...`. Установленный образ совпал с embedded исходником в четырёх файловых blob, два из них не совпадают с Git release tag; **full source parity НЕ доказана**. В официальном registry index не найден опубликованный OCI SBOM/provenance attestation.
- Системная инвентаризация `dpkg-query` вернула **274** packages. Теперь добавлена проверка основной virtualenv Python 3.14.7: **146 записей дистрибутивов**, [PR #93](https://github.com/MikeMoore1337/hermes/pull/93) и [PR #94](https://github.com/MikeMoore1337/hermes/pull/94), CI green.
- Повторяемый **независимый** read-only аудит `scripts/image_local_inventory.py --execute` на VPS: **420 raw component entries** (274+146), SHA256 нормализованного списка `5ccee27eb21ec1e284e3c2938123f2784772c6fdb0c92cf86351eee706f6673e`, `INVENTORY_REQUIRES_REVIEW`. Выход `/var/lib/hermes-image-audit/local-components.json` файл 0600 root:root, каталог 0700. Docker `--network none --pull=never --read-only --cap-drop ALL`; пользовательские сервисы не тронуты.
- Обнаружен один **двукратно перечисленный, но физически один и тот же** `hermes-agent 0.0.0` в Python metadata: относительный `hermes_agent-0.0.0.dist-info` и абсолютный `/opt/hermes/hermes_agent-0.0.0.dist-info` имеют **одинаковый `resolve()` путь, одинаковый inode 3761798 и `Path.samefile()=true`** в изолированном Docker. Это 146 записей перечисления при 145 уникальных именах, **не две доказанные установки**. Первый audit JSON сохраняет обе записи и hash без изменений; не выдавать это за доказательство полной SBOM.
- Локальный список компонентов **не** является полноценной проверенной SBOM, лицензированием, сканированием уязвимостей, provenance, подписанным свидетельством издателя. По результатам PR #93/#94 ничего не развернули из нового образа.
- Ограниченный Agent text-only цикл 15.10 PASS `113.4` секунды и был разовым. Небольшая изолированная 45-секундная CPU-нагрузка выявила `load1 max=1.61` (выше защиты агента 1.30), минимум свободной памяти 2059MiB, swap 0, news/ops active; **совместная работа модели в пик не доказана**. Cloudflare Workers Free заявлен владельцем, но no-paid-fallback и счётчики реального биллинга ещё не доказаны независимо.
- В репозитории [H-10 роли/нулевые бюджеты](../operations/H-10-AGENT-ROLES-BUDGETS.md) проходят CI, но это **только офлайн политика**; она сама по себе не изолирует процесс и не доказывает, что API не спишет деньги.

## Строгая приоритетная очередь

1. [H-01-LIVE #33](https://github.com/MikeMoore1337/hermes/issues/33) - P0: выяснить по официальным CI/release artifacts точную сборку source->digest, объяснить дублирующий пакет и получить подтверждённую SBOM/provenance; затем ограниченное безвредное длительное наблюдение ресурсов и проверку billing gate. **Не активировать resident AI до выполненных условий**.
2. [H-02 #3](https://github.com/MikeMoore1337/hermes/issues/3) - P1: фиксировать **естественный** инцидент через существующий Ops и реальный Telegram ACK, затем реальное восстановление. Не разрушать news timers или запускать искусственный красный CI ради зелёного статуса.
3. [H-03 #4](https://github.com/MikeMoore1337/hermes/issues/4) - P1: от автоматического получения библиографических метаданных перейти к содержательному отчёту только после проверки первоисточника/методов/DOI/лицензий человеком и отдельного разрешения на канал выдачи.
4. [H-10 #62](https://github.com/MikeMoore1337/hermes/issues/62) - P2: бюджет/квоты по измерениям провайдера и подтверждение нулевого риска списаний до runtime.
5. [H-05 #6](https://github.com/MikeMoore1337/hermes/issues/6), H-11 #63, SEO H-12 #64 и миграция M-01 #7 - блокировки владельца/внешнего проекта, не делать write или продуктовые шаги без необходимых разрешений.

## Негативные инварианты

**Включено и работает:** новости, Ops/Telegram, GitHub CI наблюдение, поиск научных метаданных и сетевой guard.

**Специально выключено и не следует объявлять сломанным:** постоянный AI Agent, Cloudflare proxy. Факта успешной эксплуатации 24/7 модели нет, и включение без provenance/подтверждения bill-guard и ресурса нарушило бы P0 требования. Не копировать credentials, не подключать Second Brain vault, не использовать AGPL/платные внешние сервисы. Новая научная служба не меняет редакционный pipeline YFC и не заменяет ручной экспертный review.
