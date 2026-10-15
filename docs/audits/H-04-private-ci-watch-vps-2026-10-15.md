# H-04 #5 - read-only private GitHub CI watcher: активация на VPS

Дата: 15 октября 2026 года, 04:23 UTC. Канонический news YFC, Ops Watch collector и Telegram alert sender на VPS `vps1777112993` не выключались и не изменялись ради диагностики.

## Код, проверки, границы

- [PR #85](https://github.com/MikeMoore1337/hermes/pull/85) - классификация ошибок 401/403/404/429/5xx и офлайн-диагностика CI без raw log / token / PII, [CI #38680004024](https://github.com/MikeMoore1337/hermes/actions/runs/38680004024) PASS.
- [PR #86](https://github.com/MikeMoore1337/hermes/pull/86) - read-only main-branch CI client по проверенному workflow ID `381262090`, [CI #38680376389](https://github.com/MikeMoore1337/hermes/actions/runs/38680376389) PASS.
- [PR #87](https://github.com/MikeMoore1337/hermes/pull/87) - последний зелёный запуск не является сам по себе «доказанным восстановлением», [CI #38680500354](https://github.com/MikeMoore1337/hermes/actions/runs/38680500354) PASS.
- [PR #88](https://github.com/MikeMoore1337/hermes/pull/88) - state-store, sandbox/systemd и интеграция фиксированного кода `ci_failed` в существующий networkless Ops Watch. [CI #38681042586](https://github.com/MikeMoore1337/hermes/actions/runs/38681042586) PASS.

## Фактическая установка и проверки

Исходники `qa_advisor/github_public.py`, `ci_snapshot.py`, `signal_store.py`, `watch_once.py`, `ops_watch/state_store.py`, `ops_watch/collector.py` и новые unit/installer перенесены в `/opt/hermes-agent-owner` с совпадением Git blob SHA проверенной ревизии. Источник кода и ключ не печатались в journal.

- `bash -n deploy/install-qa-watch.sh` PASS. `systemd-analyze verify` PASS; только старые предупреждения RuntimeMaxSec существующих news oneshot units, не относящиеся к новой службе. Без `--execute` команда `qa_advisor.watch_once` вернула `NOT_EXECUTED`, без HTTP.
- При установке `install-qa-watch.sh` подтвердил все три прежних активных таймера, root-owned private PAT `0600`, провёл одно успешное реальное чтение GitHub. Журнал нового `hermes-qa-watch.service`: `{"outbound_notifications": 0, "signal": "SUCCESS", "status": "STORED"}`, `Result=success, ExecMainStatus=0`.
- `hermes-qa-watch.timer` active/enabled, ограничен одним запросом каждые 15 минут (первый автоматический tick должен быть подтверждён отдельно).
- `/var/lib/hermes-qa-watch`: `0700 root:root`; `ci-signal.json`: `0600 root:root`, без токена и текстов CI. Отдельный snapshot при контрольном чтении: `status=SUCCESS`, `run_id=38681081864`, `fresh_status=SUCCESS`.
- После включения источника **вручную запущен существующий** `hermes-ops-watch.service` (без остановки/рестарта новостей). Журнал: `active_codes=[]`, `raised=[]`, `resolved=[]`, `queued_incident_events=0`, статус `ok`. Production outbox `total=0`, `acknowledged=0`, `unacknowledged=0`, `exhausted=0`. Никакого Telegram уведомления без события.
- `hermes-discovery.timer`, `hermes-ops-watch.timer`, `hermes-ops-alerts.timer` все active; сетевая защита `ensure_cloudflare_egress.py --check` вернула `verified,changed=null`.

## Что подтверждено и что пока нет

**Подтверждено:** правильный PAT к приватному репозиторию, доступ только к метаданным ограниченного основного CI, первая успешная запись автономного мониторинга, защищённая проверка networkless collector, отсутствие ложного инцидента на здоровом CI, отдельные тесты `FAILURE -> UNKNOWN -> SUCCESS` и восстановления при ошибке API.

**Ещё не подтверждено естественным инцидентом:** реально новый красный `main` workflow, его автоматическая запись `ci_failed`, реальный Telegram `message_id`, затем последовательное `resolved`. Ранее живой бот и receipt проверялись только отдельно на синтетическом инциденте `message_id=4`. Не создавать умышленно красный main и не трогать связанные новости systemd units ради теста.

## Остановка и восстановление

```bash
sudo systemctl disable --now hermes-qa-watch.timer
```

Отключение этого **нового, локально установленного** standalone unit не останавливает `hermes-discovery.timer`, `hermes-ops-watch.timer` или `hermes-ops-alerts.timer`. Это НЕ инструкция отключать systemd-symlink news timer (ранее это приводило к потере связанного unit). Если источник долго недоступен, Ops Watch сохраняет уже открытый `ci_failed` до фактически более нового успешного наблюдения; старый snapshot после TTL не подтверждает восстановление.
