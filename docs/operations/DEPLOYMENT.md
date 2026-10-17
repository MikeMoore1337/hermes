# CI/CD и эксплуатация H-01

## Действующая поставка и ограниченный H-01 (17.10.2026)

Действует точный GitHub Flow и автоматическая production CD для одобренных
модулей: [MAIN-AUTO-DEPLOY.md](MAIN-AUTO-DEPLOY.md). Точный результат - main
Quality/UI checks, successful Production CD и canonical receipt на VPS;
зелёный CI **не** означает установленный systemd H-01 unit.

Ограниченный H-01 #33 установлен вручную: отдельный event-driven
`hermes-h01-ops-agent.timer` + oneshot и внутренний Cloudflare proxy.
Общий unrestricted `hermes-agent-sandbox.service` не разрешён/не активен.
Ограничения: verified Ops incident only, максимум 1 AI-call/UTC сутки,
load1 <= 1.30, pinned patched v0.22.2, без tools/MCP/shell/publishing,
no retries, no paid fallback. Подробнее: [актуальная приёмка](../architecture/H-01-runtime-plan.md)
и [операционный акт](../audits/H-01-limited-resident-v0222-2026-10-17.md).

### Диагностика без изменения состояния VPS

```bash
cat /var/lib/hermes-main-deploy/last-success.sha
systemctl show hermes-h01-ops-agent.timer -p ActiveState -p UnitFileState -p LastTriggerUSec
systemctl show hermes-h01-ops-agent.service -p ActiveState -p Result -p ExecMainStatus
systemctl is-active hermes-cloudflare-network-guard.service hermes-cloudflare-proxy.service hermes-control-center.service hermes-ops-watch.timer
systemctl is-enabled hermes-agent-sandbox.service
journalctl -u hermes-h01-ops-agent.service --since '2026-10-17' --no-pager
systemctl list-timers --all hermes-h01-ops-agent.timer --no-pager
```

`Type=oneshot` с `inactive/success` после успешного вызова - нормально.
`failed/start-limit-hit` - **не нормально** и не означает, что модель вызывалась.
17.10.2026 это состояние реально наблюдалось в 20:33:47 MSK после
трёх стартов внутри часа. В исходниках H-01 timer скорректирован на
`OnActiveSec=35min` и `OnUnitInactiveSec=35min` при неизменном
`StartLimitBurst=2/3600s`. Поставленный source/release snapshot сам
не заменяет уже установленный `/etc/systemd/system/hermes-h01-ops-agent.timer`.

### Остановка, восстановление и rollback (только оператором после проверки #33)

- **Штатная остановка:** `sudo systemctl disable --now hermes-h01-ops-agent.timer`;
  затем `sudo systemctl stop hermes-h01-ops-agent.service`. Если proxy не
  используется другими разрешёнными потребителями, его можно остановить
  отдельно. Guard, Ops Watch, news и остальные службы не трогать.
- **Состояние сохранять:** не удалять `/var/lib/hermes-h01/state.json`,
  `run.lock`, существующие журналы, секреты и записи о использованной
  UTC-квоте ради повторного запуска.
- **Применение новой ревизии unit:** сначала проверить exact deployed SHA,
  `releases/main-<sha>/deploy/hermes-h01-ops-agent.{service,timer}`,
  сравнить с текущими root-owned unit, проверить `systemd-analyze verify`,
  иметь backup и путь отката. Затем в отдельном разрешённом операторском
  окне заменить **только** проверенные unit, `daemon-reload` и
  `enable --now` таймер. Не пытаться применять через
  `deploy/install-h01-ops-agent.sh` поверх отличающихся unit: он
  преднамеренно вернёт `unit_conflict`.
- **Rollback конфигурации H-01:** после утверждённой остановки таймера
  восстановить предыдущую проверенную пару unit из backup и выполнить
  `daemon-reload`; включать обратно только после согласованного
  resource/guard preflight. При необходимости оставить H-01 выключенным,
  не откатывая другие Hermes сервисы и не трогая YFC. Операционный
  rollback ограниченного AI пока не имеет end-to-end evidence: #33.
- **Во время существующего 24h burn-in #33:** не выполнять
  `reset-failed`, `daemon-reload`, `restart`, `enable --now`,
  не очищать журнал и не менять unit/timer ради «зелёного» статуса.
  Изменение в GitHub и доставка immutable release snapshot **не являются**
  доказательством применения нового расписания в production.

## Исторический срез (2026-10-11)

## Сейчас

Этот репозиторий не имеет активного gateway, deployment workflow или секретов. 2026-10-11 на действующем Hermes VPS в `/opt/hermes-agent-owner` размещены только версии `host_capacity.py` и `smoke.sh`, подтверждены source git blob SHA и выполнен изолированный CLI smoke. Образ v0.21.6 pin-digest скачан, но **ни один постоянно работающий агент не установлен/включён**. Единственный workflow `.github/workflows/quality.yml` выполняет статическую проверку файлов и unittest на GitHub-hosted runner. В нём нет production secrets, Docker socket, SSH, моделей, API или сервисных ключей.

## Исторический план runtime (2026-10-11)

- Зафиксировать версию/commit upstream Hermes и SBOM/подписи; не использовать `latest`.
- Отдельные OS user, data dir, секреты, ограничение egress и resources; не менять news worker как побочный эффект.
- CI соберёт и проверит кандидат; deployment допускается только отдельным утверждённым механизмом и после контроля изменений.
- Проверить failure/restart/idempotency, алерты, snapshot, clean shutdown и rollback.
- Релиз Hermes не должен запускать релиз YFC; обратное также недопустимо без явного совместимого контракта.
- В документации раскрывать только идентификаторы утверждённых версий и безопасные метаданные, не адреса серверов или токены.

## GitHub settings

Включить защиту основной ветки/required CI, если функция доступна для приватного репозитория; проверить через GitHub API и задокументировать результат. До проверки защиты правило no-direct-push является организационным, а не технически принудительным.

Использовать scoped token только при реальном CI/CD-переходе; в bootstrap токены не нужны.

## Подтверждённые ограничения GitHub (2026-10-11)

- Репозиторий **private**, основная ветка `main`.
- `delete_branch_on_merge=true`, `allow_squash_merge=false`, `allow_auto_merge=false` проверены через GitHub API.
- Попытка настроить защиту `main` с обязательным `static-and-tests` получила HTTP 403: **«Upgrade to GitHub Pro or make this repository public to enable this feature.»**. Защита ветки **не включена и не считается действующей**. Для приватности репозиторий публичным не делали; переход на платный тариф без разрешения не выполняли.
- До появления доступной GitHub branch protection соблюдать Issue -> branch -> PR -> CI -> ручное слияние организационно. Статус required check не является техническим запретом прямого push.
