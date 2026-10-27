# ECC для Hermes - штатное подключение «как есть» (Issue #632)

**Статус 2026-10-27: SOURCE_REVIEWED / ISOLATED_INSTALL_NOT_RUN / LIVE_HERMES_NOT_VERIFIED.** Документ не устанавливает ECC, не меняет Hermes Agent runtime, не предоставляет разрешений, не запускает процессы и не подтверждает совместимость с production.

## Проверенный upstream

- Оригинал: [affaan-m/ECC](https://github.com/affaan-m/ECC), ревизия [`25278e7d7b6cf6e6a4e7a6c8e10f14ff22f0eb5b`](https://github.com/affaan-m/ECC/tree/25278e7d7b6cf6e6a4e7a6c8e10f14ff22f0eb5b), `LICENSE` MIT (заявление upstream).
- Штатная Hermes-инструкция: [`.hermes/README.md`](https://github.com/affaan-m/ECC/blob/25278e7d7b6cf6e6a4e7a6c8e10f14ff22f0eb5b/.hermes/README.md). Указанная upstream команда для отдельной разрешённой среды: `bash ./install.sh --target hermes --profile minimal`. **Команда здесь не выполнялась**.
- [`docs/HERMES-SETUP.md`](https://github.com/affaan-m/ECC/blob/25278e7d7b6cf6e6a4e7a6c8e10f14ff22f0eb5b/docs/HERMES-SETUP.md) описывает более широкую операционную схему (MCP, память, сторонние сервисы, расписания). Это **не** безопасный обязательный состав для текущего Hermes.
- `install.sh` - исполняемый wrapper: если `node_modules` отсутствует, он вызывает `npm install --ignore-scripts --no-audit --no-fund`, затем `node scripts/install-apply.js`. Поэтому это не read-only проверка; простое прочтение README **не даёт разрешения на запуск**.
- ECC `Memory Vault` потребует отдельный `ecc-universal` и опциональный `ecc-memory-mcp`; он не является автоматически доверенным хранилищем. Не смешивать его с хранилищем Second Brain.

## Разделение поверхностей Hermes

| Поверхность | Правило |
|---|---|
| `.agents/skills` в этом репозитории | Это уже существующие справочные навыки **для разработки Hermes**, а не внутренний агентный runtime. Не копировать туда ECC и не менять `AGENTS.md` |
| Внешний Hermes Agent в изолированной среде | Только он кандидат на upstream `--target hermes --profile minimal`; установка в его отдельный рабочий HOME требует проверки file diff и разрешений |
| `skills/`, `evals/`, `policies/`, `qa_advisor/` и `control_center/` | Канонические компоненты Hermes. Не заменять оригинальными ECC, не создавать второй controller или новые CI-гейты без доказанной недостачи |
| Hermes BRC / Windows native bridge | ECC не устраняет текущие ограничения удалённого исполнения и не должен получать дополнительные права shell/файловой системы |
| Second Brain vault, YFC production, исследовательские источники, публикация | Не давать ECC доступ, автопубликацию или общий долговременный контекст |
| Общий ECC Memory Vault, MCP, cron, хуки | **Выключены/не подключены** до отдельного consent, проверки доверия и изоляции по ОС; upstream рекомендации - не разрешение владельца |

## Порядок штатной интеграции в изоляции

1. **Preflight:** определить реальную версию NousResearch Hermes и действующий HOME/пользователя, сохранить список файлов/прав, доступных skills/plugins/hooks/MCP и режим `READ_ONLY`; удостовериться, что это непроизводственная **изолированная** среда и нет подключённого YFC/Second Brain/секретов.
2. **Pin/source review:** сверить upstream SHA, исходники `install.sh` + `scripts/install-apply.js`, зависимости, профиль `minimal`, список целевых файлов и внешних вызовов. Выполнить действующий external-skill-review и проверить возможное перезаписывание `AGENTS.md`, существующих skills или hooks.
3. **Только после успешного preflight:** штатным способом установить **оригинальный ECC** в непроизводственный Hermes HOME с минимальным профилем. Никаких форков/ручного переписывания/копий из незафиксированной ветки. Не выполнять автоматически команды расширенного `docs/HERMES-SETUP.md`.
4. **Приёмка:** проверить один исходный ECC skill на вымышленных входах и отдельное отрицательное испытание на отказ shell/network/секретов. Записать наблюдаемые различия HOME до и после, ограничения доступа и точные версии. Статус `installed` не доказывает, что skill вызван.
5. **Rollback:** штатно удалить только объекты, которыми управляет ECC, восстановить сохранённое исходное состояние и повторить проверку Hermes policies и обычной работы. Не удалять содержимое пользовательского `~/.hermes` целиком.
6. **GitHub delivery:** этот документ проходит самостоятельные PR/CI/merge как кодовая документация; **production-activation** и постоянно работающие службы не включать автоматически.

## Требования к доказательствам и текущий блокер

Нужны: URL/пин исходника, проверенные зависимости, точный план изменений при установке, снимок разрешений, подтверждённый Hermes executable и isolated HOME, лог оригинального skill с вымышленным входом, негативный deny-test, rollback и отсутствие незаявленных вызовов/расходов. Без этого выдавать `NOT_VERIFIED` или `BLOCKED`, не `PASS`.

В доступной сейчас Hermes VPS Docker-песочнице проверены лишь `node v24.22.0` и отсутствие `git`, `python3`, локального Hermes runtime и ECC checkout внутри `/workspace`. Нативный Windows агент в другой рабочей среде offline/paused. **Ни одна из этих наблюдаемых сред сейчас не доказывает пригодность для штатной установки ECC в действующий Hermes Agent.** Нельзя переносить проверку Docker-песочницы на Windows или production.

Связанные правила: [AGENTS.md](../../AGENTS.md), [разделение владения](../architecture/OWNERSHIP.md), [модель угроз](../security/THREAT_MODEL.md), [development-only навыки](../../.agents/README.md), [H-01 #33](https://github.com/MikeMoore1337/hermes/issues/33). Пока не подтверждён изолированный runtime и его политики, **Issue #632 остаётся OPEN**.
