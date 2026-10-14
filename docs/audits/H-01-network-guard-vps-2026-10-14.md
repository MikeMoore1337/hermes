# H-01: системная защита Cloudflare, проверка на Hermes VPS

**Дата:** 14 октября 2026, production VPS с существующими сервисами YFC/Hermes. Отдельный выделенный ресурс для нового Agent не добавлялся.

## Код / проверки

- [PR #30](https://github.com/MikeMoore1337/hermes/pull/30), merged CI green: идемпотентная проверка и восстановление `--internal` Docker bridge + nftables, systemd oneshot `hermes-cloudflare-network-guard.service`, жёсткий отказ при расхождении.
- [PR #31](https://github.com/MikeMoore1337/hermes/pull/31), merged CI green: точная повторная `--check` перед каждым стартом Cloudflare CONNECT proxy и agent CLI. Требующий администраторского чтения NFT проверочный `ExecStartPre=+` выполняется отдельно; сам прокси остаётся непривилегированным, с пустым capability bounding set.
- [PR #32](https://github.com/MikeMoore1337/hermes/pull/32): дополнительные детерминированные проверки сценария исчезновения таблицы/сети и порядка восстановления, без разрушительных тестов на живом сервере.

## Действительно проверено на хосте

- Исходники доставлены через GitHub, exact blob SHA для Python и двух units совпали на VPS.
- `ensure_cloudflare_egress.py --check`, затем `--ensure` и повторный `--check` вернули `status=verified`.
- Хеш полного `nft -j list table inet hermes_agent_isolation` до и после был одинаков: `80f392e6adb9aae0dd96ee67f4ed617715a4c584df45049d3a9f5bdbdc4a9f28`. Это подтверждает неизменность действующих правил.
- При ручной остановке нового guard unit и запуске прокси systemd **автоматически** поднял guard, `Result=success, ExecMainStatus=0, ActiveState=active`. Прокси стартовал и был выключен.
- У guard unit `enabled + active`; у прокси `disabled + inactive`; полноценный AI Agent gateway `inactive`; новости `hermes-discovery.timer` и `hermes-ops-watch.timer` оба `active`.
- Повторный пробный старт прокси после PR #31 прошёл через короткую read-only проверку сети и завершился успехом, затем прокси снова был выключен.
- При последней ресурсной проверке `status=ready`, load1 примерно 0.88, MemAvailable 2283 MiB, swap 0. Пиковую одновременную нагрузку всех сервисов этим не доказали.

## Сохраняющиеся ограничения

**Production VPS НЕ перезагружали.** Следовательно, начальная конфигурация восстановления в systemd проверена фактом успешного ручного старта/реинициализации, но восстановление после настоящего reboot ещё НЕ доказано. Не считать H-01 завершённым по одному включённому guard.

Существующая YFC news nft-таблица, прокси MTProto, YFC backend, Second Brain, код news worker не изменялись. В новой таблице rules создаются до отсутствующего bridge; любые **существующие изменённые правила/сеть** вызывают fail-closed без самовольной правки.

Для длительного Hermes Agent всё ещё требуются: устойчивость в течение нескольких циклов, проверка квоты и отказов Cloudflare в реальном агентном контуре, отдельный запуск с ограниченными правами/ресурсами без публикаций, а также испытание сети после настоящего reboot в согласованное окно или изолированной копии VPS.
