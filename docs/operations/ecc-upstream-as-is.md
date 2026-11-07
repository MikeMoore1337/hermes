# ECC для Hermes - штатное подключение «как есть» (Issue #632)

**Исторический статус на 2026-10-27: SOURCE_REVIEWED / ISOLATED_INSTALL_NOT_RUN / LIVE_HERMES_NOT_VERIFIED.** Документ не устанавливает ECC, не меняет Hermes Agent runtime, не предоставляет разрешений, не запускает процессы и не подтверждает совместимость с production.

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


## Изолированная приёмка от 03.11.2026 - реальные результаты #632

[PR #758](https://github.com/MikeMoore1337/hermes/pull/758) добавляет только проверочный стенд, тесты, CI и защиту от автоматического production-deploy. Он **не содержит ECC**, не меняет оригинальные `SKILL.md` и не устанавливает ECC в production. Этапы ниже подтверждены [изолированным GitHub Actions run #41718753287](https://github.com/MikeMoore1337/hermes/actions/runs/41718753287) и его JSON-артефактом, а не утверждением на основании исходников.

- Закреплён ECC `affaan-m/ECC@25278e7d7b6cf6e6a4e7a6c8e10f14ff22f0eb5b`, `ecc-universal 2.2.3`, MIT. Текущий upstream `main` отличается: автоматического перехода на него нет.
- Проверяемый оригинальный NousResearch Hermes: `v0.22.2`, commit `d923a5eb487a17c0a68801bba9ef0f56c81040a8`, образ `nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05`.
- Подготовка: GitHub-hosted disposable runner, `npm ci --omit=dev --ignore-scripts` по lockfile, затем оригинальный `install.sh` в Docker c `--network none --read-only --cap-drop ALL --user`. Нет production-монтирований, токенов или пользовательских данных.
- **INSTALL=PASS:** оригинальные dry-run и установка `--target hermes --profile minimal` завершились кодом 0. План: 534 файловых операции. Профиль `minimal` развёрнут в семь модулей с зависимостями: `rules-core`, `agents-core`, `commands-core`, `platform-configs`, `workflow-quality`, `shared-script-utils`, `skill-unified-memory`; автоматический hooks-runtime в профиль не входит.
- **REINSTALL=PASS:** повтор оригинального установщика завершился кодом 0 без дублирования файлов; обновлялись служебные state-файлы. Неподдерживаемый профиль отклонён с exit 1 и без мутаций.
- **DISCOVERY=PASS / VIEW=PASS / EXECUTION=NOT_VERIFIED:** `tools.skills_tool.skills_list()` закреплённого настоящего Hermes обнаружил 54 навыка, включая ECC `verification-loop` и `tdd-workflow`. Оба `SKILL.md` установлены байтово как в оригинале. `skill_view(preprocess=False)` реально открыл их в Hermes. Это **не означает исполнение** шести стадий verification-loop или TDD-процесса: модельный runner не запускался; без отдельно разрешённого бесплатного offline executor подтверждения полноценного skill execution нет.
- **OS DENY=PASS:** отрицательный запуск в одноразовом контейнере проверил отказ записи за пределами тестового HOME и отказ TCP-подключения. Second Brain vault, YFC production, secrets и Docker socket не подключались.
- **UNINSTALL_EXIT=0 / COMPLETE_ROLLBACK=PARTIAL:** исходный ECC uninstall удалил управляемые навыки и install-state, не изменив исходные синтетические owner-файлы. Однако собственный ECC state-store оставил `~/.claude/ecc/state.db` (внутри тестового HOME, но вне `~/.hermes`). Запуск штатного Hermes также создал `SOUL.md`, пустой каталог `hooks/` и резервную копию конфигурации; они не являются доказательством установки ECC hooks. Эти артефакты отдельно атрибутируются через снимки до/после native discovery.
- **POLICIES=PASS в проверенном отрицательном сценарии:** коллизия с заранее существующим синтетическим Hermes `AGENTS.md` не привела к его перезаписи. Настройки MCP и активные ECC hooks не разрешались и не запускались.
- **CI / MERGE:** исходный диагностический workflow завершался `FAIL` для неполного полного отката, что корректно отмечает невыполненное условие. Независимый общий CI и H-585 регрессии проходят на ранее проверенных SHA; итоговый verdict следует определять только по последнему точному SHA PR. Без полного подтверждения и разрешённого production scope автоматический merge недопустим.

Ограничение оригинала **нельзя скрывать зелёным CI**. Приёмка включения ECC в постоянный Hermes остаётся `NO-GO`; Issue [#632](https://github.com/MikeMoore1337/hermes/issues/632) остаётся **OPEN**. Для завершения нужны доказанный безопасный rollback всей изолированной среды и исполнение навыка реальным разрешённым модельным executor; наличие установленного файла или `skill_view` не удовлетворяет этому критерию. `Memory Vault`, cron, MCP, paid providers и резидентный режим остаются запрещены.

## Дополнение к изолированному тестированию - PR #760

На основе [PR #760](https://github.com/MikeMoore1337/hermes/pull/760) проведена расширенная проверка исходного ECC без изменения его кода. [GitHub Actions #41723614795](https://github.com/MikeMoore1337/hermes/actions/runs/41723614795) завершился `SUCCESS`; JSON-квитанция в артефакте `h632-original-ecc-isolated-receipt` подтверждает следующие **реальные** операции:

- План `minimal` - **534 уникальных** назначения, все 534 ожидаемые операции представлены созданными файлами; иных изменений вне разрешённой зоны не найдено, кроме исходного состояния `~/.claude/ecc/state.db`.
- Оригинальные `node scripts/doctor.js --target hermes --json`, `node scripts/repair.js --target hermes --dry-run --json` и `node scripts/auto-update.js --target hermes --repo-root /ecc --dry-run --json` реально выполнены с `exit=0`, `summary.errorCount=0`; снимок тестового HOME не изменился. Это **не обновление на новую ревизию**.
- После оригинального `scripts/uninstall.js` с `exit=0` отсутствуют все 534 управляемых назначения и install-state. **Собственный uninstall ECC всё ещё оставляет** `.claude/ecc/state.db`: `EXACT_SNAPSHOT_ROLLBACK=FAIL`.
- Исключительно в одноразовой тестовой среде после штатного uninstall **отдельная проверочная процедура** удалила один новый `.claude/ecc/state.db`, проверив SHA-256, inode и отсутствие symlink/hardlink. Она отказывает при предсуществующем, изменённом или вынесенном за тестовый HOME файле. Каталоги и созданные нативным Hermes `SOUL.md` / резервная копия config сохранены. Итог `ECC_OWNED_FILES_REVERTED_IN_DISPOSABLE_HOME=PASS`, **не** `UPSTREAM_UNINSTALL_EXACT=PASS`.
- Пара проверенных навыков `verification-loop` и `tdd-workflow` осталась в статусах `INSTALLED/DISCOVERED/VIEWED`; их модельное выполнение не запускалось. Ввиду действующего запрета на запрещённые исполнители оно остаётся `BLOCKED_BY_OWNER_POLICY`. Предварительная проверка использовала только бесплатные GitHub-hosted вычисления и синтетические данные.

**Вердикт #632 не меняется: OPEN / PRODUCTION ACTIVATION NO-GO.** Разделять «зелёный CI достоверности квитанции», успешное удаление управляемых файлов с контролируемой очисткой исключительно временного HOME и полноценную активацию навыков в production. Не применять тестовую процедуру очистки к общей пользовательской `.claude` или Hermes HOME.

## Итоговая приёмка изолированного контура - 05.11.2026

Этот раздел заменяет устаревшие промежуточные статусы выше **только для нового offline-сценария**, но не даёт разрешения на production.

- Оригинал `affaan-m/ECC@25278e7d7b6cf6e6a4e7a6c8e10f14ff22f0eb5b`, MIT, штатный `--target hermes --profile minimal`. Оригинальные `SKILL.md`, установщик и деинсталлятор не изменялись. Настоящий NousResearch Hermes закреплён на `d923a5eb487a17c0a68801bba9ef0f56c81040a8`.
- [PR #762](https://github.com/MikeMoore1337/hermes/pull/762) доказал модельный `skill_view` + `terminal` для оригинальных `verification-loop` и `tdd-workflow`. [PR #769](https://github.com/MikeMoore1337/hermes/pull/769) добавил настоящие шесть стадий проверки на специально подготовленном проекте: build, types, lint, 2/2 теста и 100% покрытия, security scan, Git diff.
- [PR #776](https://github.com/MikeMoore1337/hermes/pull/776) доказал две отдельные генерации кода бесплатной локальной Qwen3.5-2B: сначала **написанные моделью** два теста и реальный RED (`AssertionError` 2/2), только после этого **написанное моделью** исправление, GREEN 2/2, 100% измеренного покрытия `return`, 3 Git checkpoint. Модель не получала инструментов при написании кода; AST-фильтр отказывал в импортах, сторонних вызовах и побочных действиях.
- На точном HEAD `71d30d2b0f1ca08a8149f72eb5dc1167d660159b`: [H632 #41910647987](https://github.com/MikeMoore1337/hermes/actions/runs/41910647987) SUCCESS в обоих jobs; [общий CI #41910647785](https://github.com/MikeMoore1337/hermes/actions/runs/41910647785) SUCCESS, 3474 Python-теста. [Модельный артефакт #13363910228](https://github.com/MikeMoore1337/hermes/actions/runs/41910647987/artifacts/13363910228) проверен независимо (ZIP SHA256 `f46ae4ed7a81cc007d2cf2d6f06816d5b6a0f33f7699f900d4e88cb6a194f330`). [Lifecycle #13361074419](https://github.com/MikeMoore1337/hermes/actions/runs/41910647987/artifacts/13361074419) содержит доказательства исходных команд и OS deny-тестов.

### Известная граница rollback

- **`ISOLATED_TEST_HOME_ROLLBACK=PASS`**: штатный оригинальный uninstall удаляет все 534 ECC-managed назначения, после чего отдельный проверенный H632 guard удаляет только созданный тестом `.claude/ecc/state.db` в одноразовом HOME с проверками SHA256, inode, symlink/hardlink и сохранности посторонних файлов.
- **`UPSTREAM_NATIVE_EXACT_ROLLBACK=FAIL_KNOWN_CACHE`**: сам штатный `uninstall.js` по-прежнему оставляет `.claude/ecc/state.db`. Это не исправлено; дальнейшая upstream-зависимость отслеживается отдельно в [Hermes #777](https://github.com/MikeMoore1337/hermes/issues/777) и [ECC #3559](https://github.com/affaan-m/ECC/issues/3559). Тестовую очистку строго запрещено применять к shared HOME или production.
- **`GUIDED_SYNTHETIC_6_PHASES=PASS` / `GUIDED_MODEL_WRITTEN_RED_GREEN=PASS`**, но не автономное планирование всех этапов и не приёмка произвольного пользовательского проекта.
- **`PRODUCTION_DEPLOY=NOT_RUN` / `ECC_RESIDENT_ACTIVATION=NO_GO`**. Production workflow только ручной и требует отдельного разрешения; на тестовом PR никакие сервисы, секреты или production-права не активировались.

**Критерий задачи #632 ограничен изолированным offline-подключением и его проверенным одноразовым rollback; нативный rollback в общем HOME не принят и вынесен в #777.** Полноценная live-активация потребует отдельной приёмки и согласования.
