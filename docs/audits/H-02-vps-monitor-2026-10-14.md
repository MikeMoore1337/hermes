# H-02: локальный мониторинг Hermes, реальный запуск 2026-10-14

**Реальное состояние: systemd timer активен.** На выделенном VPS `vps1777112993` установлен детерминированный мониторинг **без модели и внешней сети**. Он не заменяет H-01 и не является полнофункциональной системой уведомлений.

## Источники и развёртывание

- GitHub [PR #16](https://github.com/MikeMoore1337/hermes/pull/16) - коллектор, юнит, таймер и тесты. [PR #17](https://github.com/MikeMoore1337/hermes/pull/17) - необходимая привилегия чтения закрытого news state и контрактный тест. Оба объединены с `main`, оба CI зелёные.
- На Windows-посреднике исходники получены из GitHub exact head и сверены по Git blob SHA; первая копия получила Windows CRLF и была отклонена проверкой. Файлы нормализованы в LF, SHA повторно сверены **на VPS**, `bash -n` и `py_compile` прошли. Первичная попытка запустить systemd unit **fail closed** из-за закрытого приватного каталога.
- После замены `CapabilityBoundingSet=` на `CapabilityBoundingSet=CAP_DAC_READ_SEARCH` systemd проверка прошла, `Result=success`, `ExecMainStatus=0`. Это право позволяет **читать** закрытое состояние новостного Hermes; оно не разрешает запись в новости, но само по себе даёт более широкий доступ на чтение, поэтому код фиксированный, сеть отключена и unit должен оставаться жёстко ограниченным. Перенос на scoped health API может убрать это право в будущем.
- Фактические `enabled=enabled` и `active=active` подтверждены для `hermes-ops-watch.timer`.
- `OnUnitActiveSec=10min`, randomized delay 30s, `Persistent=false`. При начальной проверке: предыдущее выполнение 2026-10-14 **10:14:32 MSK**, следующее назначено на **10:24:32 MSK**. Это моментный снимок плана.
- Последнее `hermes-ops-watch.service`: статус **success**, `active_codes=[]`, `changes.raised=[]`, `changes.resolved=[]`.
- Новостной `hermes-discovery.timer` остался активным. Оригинальные файлы и публикационный контур YFC не изменялись.
- News guard после запуска: **ready**, `MemAvailable=2622 MiB`, `swap_used=0`, `disk_free=12879 MiB`, `load1=0.37`.

## Ограничения, которые нельзя скрывать

- Результат хранится локально в закрытом `/var/lib/hermes-agent/ops-watch/findings.json` и в journald, **не отправляется в Telegram** и не создаёт удалённые уведомления.
- Сборщик читает только локальный `health` и systemd timer. Доступа к YFC bot polling heartbeat, GitHub CI и удалённым серверам нет - соответствующие сбои пока **не отслеживаются**.
- Cumulative `provider_rate_limit_count` сознательно не трактуется как сегодняшние ошибки; реальную недавнюю динамику 429 нужно подключить отдельно.
- Проверка показала только текущие состояния и ручной запуск плюс первый таймер, **не** испытание нескольких суток/месяца и не 100% защиту от всех атак.
- Самостоятельный AI gateway `hermes-agent-sandbox.service` остаётся **disabled/inactive**, Groq key отсутствует. Не объявлять H-01/H-02 завершёнными.

## Эксплуатация

```bash
systemctl list-timers --all hermes-ops-watch.timer
systemctl is-active hermes-ops-watch.timer hermes-discovery.timer
systemctl show hermes-ops-watch.service -p Result -p ExecMainStatus
journalctl -u hermes-ops-watch.service -n 30 --no-pager
```

Для остановки только нового мониторинга (без касания YFC news): `systemctl disable --now hermes-ops-watch.timer`. Это не выключит `hermes-discovery.timer`.

## Следующий шаг

Нужны отдельный контур безопасной отправки уведомлений с новым одобренным каналом и credentials, read-only YFC/GitHub collectors и выверенный runtime Hermes Agent с подходящим провайдером. Последний не активируется только потому, что локальный watchdog прошёл smoke.
