# H-01 #33: сохранение закреплённого Docker-образа при штатной очистке

Статус: **SOURCE FIX / NOT INSTALLED** на дату 2026-11-06. Этот документ и
`deploy/hermes-docker-gc.sh` сами по себе не изменяют VPS.

## Независимые доказательства проблемы

На реальном `vps1777112993`:
- источник H-01 установлен по `7cc4237721107434425c0e7638606aeb6296e253`;
- `hermes-h01-ops-agent.timer` enabled/active, 35 мин + randomized 3 мин;
- H-01 service за 6 ноября: шесть `BLOCKED/patched_image_not_verified`, без
  полезного модельного цикла;
- файл pin указывает на точный `sha256:1ae52b578f5944510beabfa71aaf1d469f24ad69258a38840cce02d57e89ea79`,
  но `docker image inspect` возвращает `No such image`;
- root-installed ежедневная `docker-gc.timer` 06.11.2026 в 04:29 MSK
  запустила существующий `/usr/local/sbin/docker-gc.sh`, включающий
  `docker image prune -af --filter until=168h`. Прямой журнал удаления
  конкретного образа не сохранился. Это **возможная причина**, не доказанный
  точный timestamp удаления.

Docker официально считает образы без container references неиспользуемыми
при `prune -a` и поддерживает отрицательный label filter:
https://docs.docker.com/reference/cli/docker/image/prune/

## Подготовленное исправление (только репозиторий)

`scripts/h01_docker_gc_safe.py` сохраняет предыдущие rollback-GC и
builder-prune стадии, но изображение H-01 исключается фильтром
`label!=hermes.native.tool.policy=bounded-v0222`. **Перед любым mutating
действием** он проверяет прежний pin через тот же `safe_image()`: точный
image ID/digest, архитектуру AMD64, upstream commit и bounded-policy label.
После GC повторяет проверку. Если pin отсутствует/неверен, GC блокируется,
не выбирает другой образ и не запускает модель. Это fail-closed поведение;
при отсутствии pin потребуется отдельный разбор предотвращения заполнения диска.

`deploy/hermes-docker-gc.sh` является будущей заменой
`/usr/local/sbin/docker-gc.sh`. Новых timers/systemd units он не создаёт.

## Production gate (только после отдельного разрешения владельца)

1. Сохранить копию **установленного** `docker-gc.sh`, его SHA256, и
   текущие `docker-gc.timer/service` и H-01 unit, без сброса статусов.
2. Восстановить **именно** ранее проверенный локальный derivative H-01,
   строго сопоставить digest, AMD64, `hermes.base.commit` и
   `hermes.native.tool.policy`. Ни `latest`, ни слепого `docker pull`,
   ни непроверенной замены runtime.
3. На установленном release SHA выполнить **read-only**
   `python3 -B -m scripts.h01_docker_gc_safe --dry-run` с
   `/opt/hermes-agent-owner`; ожидать `DRY_RUN/pin=VERIFIED`.
4. Только после отдельного production-approval и preflight заменить
   **существующий** `/usr/local/sbin/docker-gc.sh` на review-tested
   `deploy/hermes-docker-gc.sh` с правами root:root 0755.
   При ошибке немедленно откатить только этот файл из сохранённой копии.
   Не трогать unit/timer, H-01 reservation, creds, сети, Docker runtime.
5. Повторно проверить сохранность image ID после **естественного**
   запуска docker-gc.timer, отсутствие новых H-01 `BLOCKED` и обычную
   работу Ops Watch, Research Scout, Command Center и новостей YFC.

## Дополнительная проверка selector

В Ops Watch новые природные события #138 и #263 `drain_failures` уже
перешли в `resolved` (#263 закрыто #264). Предыдущая реализация H-01
выбирала максимальный `ADVISOR_CANDIDATE` из истории, не сверяя
канонические **текущие** incidents. Исправление в
`scripts/h01_ops_agent_service.py` добавляет read-only `read_current`
и исключает завершённые episodes до расходования reservation. Отказ чтения
источника остаётся fail-closed, никаких replay и новых model calls.

**Definition of Done** остаётся незавершённым до успешного естественного
живого `status=PASS`, `quality=PASS`, доказанной квоты/стоимости и
устойчивого эксплуатационного периода. Никакой искусственной записи или
сброса reservation ради PASS.
