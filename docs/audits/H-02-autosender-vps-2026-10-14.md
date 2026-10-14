# H-02 - автоматическая доставка Telegram: VPS, 14.10.2026

Статус: **ENABLED (sender timer)**, но сквозная доставка при *новом естественном production-инциденте* ещё не наблюдалась. Основание: явное разрешение владельца после успешного ручного E2E с сообщением `message_id=4`.

## Код и проверка
- [PR #73](https://github.com/MikeMoore1337/hermes/pull/73): реальный ручной E2E в отдельной временной БД. Пользователь сообщил `ACCEPTED_BY_TELEGRAM_AND_ACK_PERSISTED`, `message_id=4`, attempts=1, duplicate_send_blocked=true, подтвердил текст в личном боте. Не означало включения планировщика.
- [PR #74](https://github.com/MikeMoore1337/hermes/pull/74): отдельный ограниченный sender/timer. [CI #38636016140](https://github.com/MikeMoore1337/hermes/actions/runs/38636016140) SUCCESS.
- Первая установка остановилась до включения таймера: `root` без capabilities не мог пройти `/var/lib/hermes-agent` (владелец `hermes-agent`, 0700).
- [PR #75](https://github.com/MikeMoore1337/hermes/pull/75): безопасный `BindPaths` только очереди в `/run/hermes-ops-alerts/outbox`; `InaccessiblePaths` закрывает прямой доступ к данным Hermes/YFC; `CapabilityBoundingSet` остаётся пустым. [CI #38636679152](https://github.com/MikeMoore1337/hermes/actions/runs/38636679152) SUCCESS. Чтение очереди в таком systemd sandbox проверено отдельным read-only запуском.

## Фактическая установка
На VPS `vps1777112993` положены только необходимые проверенные исходники и два systemd unit файла. Проверка `git hash-object` совпала с GitHub:
- `telegram_sender.py`: `7490cc10011b4b1d0c0ec6ba0a3634a4e429ab19`
- `delivery_contract.py`: `cadbfeac8d712078e37e4e64e4a0eb49b12e9de5`
- `telegram_dispatch.py`: `3684e67330ee739fd6df98f15e0d245f1f5f5b85`
- `hermes-ops-alerts.service`: `e06d8f95ccbedfa67e1ced15fd03b84d29da4030`

Проверки `bash -n`, `systemd-analyze verify` и `python3 -m ops_watch.telegram_dispatch` (DRY_RUN_ONLY, 0 событий) прошли. Предупреждения `systemd-analyze` о `RuntimeMaxSec` других oneshot units не относятся к новому sender.

## После активации (21:00:48 UTC)
- `hermes-ops-alerts.timer`: `loaded, active/waiting, enabled, Result=success`.
- `hermes-ops-alerts.service`: последний запуск `Result=success, ExecMainStatus=0`, единственный текущий результат `EMPTY_OR_LEASED`. Старая неуспешная попытка записана в journal, новая служба заработала после исправления.
- `hermes-ops-watch.timer` (локальный сборщик) active; `hermes-discovery.timer` active; постоянно работающий Hermes AI Agent inactive.
- Рабочая очередь SQLite: `total=0, acknowledged=0, unacknowledged=0, exhausted=0`.
- `/etc/hermes-agent/ops-watch.env`: `0600 root:root`. Секреты, URL с токеном, персональный chat ID не публиковались.
- `hermes-ops-alerts.timer`: `OnActiveSec=2min`, `OnUnitActiveSec=10min`, `Persistent=false`; до одного события за проход, без догоняющих массовых запусков. Telegram ACK фиксируется лишь после реального положительного `message_id`.

## Ограничения
- Пустая очередь означает отсутствие HTTP отправки в ходе первичного старта: это не доказательство работы самого планировщика при реальном инциденте. Ручной E2E транспорт/ACK ранее подтверждён отдельно.
- Возможны дубликаты, если Telegram принял сообщение, но его ответ потерялся до записи в SQLite. Поэтому не обещать exactly-once; максимум пять попыток на событие и 90 секунд аренды.
- Внешние read-only сигналы YFC/CI, ложные тревоги и уведомления о реальном восстановлении ещё подлежат отдельной приёмке в [Issue #3](https://github.com/MikeMoore1337/hermes/issues/3).
- Отключение: `sudo systemctl disable --now hermes-ops-alerts.timer` (не выключает сборщик и YFC news). Существующий активный отправитель проверять отдельно.
