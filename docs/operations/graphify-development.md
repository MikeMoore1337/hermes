# Graphify для разработки Hermes (без resident-runtime)

**Область:** только анализ исходников и архитектуры репозитория разработчиком
или Codex Desktop. Это не навык работающего Hermes Agent, не MCP-сервис,
не изменение Control Center/BRC/VPS и не production-зависимость.

Оригинал: [Graphify-Labs/graphify](https://github.com/Graphify-Labs/graphify),
лицензия Apache-2.0, ветка upstream `v8`, официальный пакет
**`graphifyy`** (не `graphify`). Для этого руководства выбран upstream
[0.9.97](https://github.com/Graphify-Labs/graphify/releases/tag/v0.9.97)
от 27.10.2026. Перед обновлением проверить доступные исправления и
точный release; старые инструкции с `main` не использовать.

## Изолированная установка (только вручную)

После разрешения разработчика установить `uv` или `pipx`
отдельно от Python Hermes runtime:

```bash
uv tool install 'graphifyy==0.9.97'
graphify --version
```

Или `pipx install 'graphifyy==0.9.97'`.
Действие требует доступа к PyPI, но не требует платного AI API и не должно
появляться в Dockerfile, requirements, CI или production deployment.
На Windows проверить исполняемый файл в изолированном окружении. Нельзя
считать инструмент запущенным по одному наличию инструкции.

## Построение и запросы - нативный Graphify

Сначала `git status` и состав `.gitignore`: удостовериться, что в
репозитории отсутствуют неигнорируемые секреты и чужие приватные файлы.
Запускать из **корня Hermes checkout**, не из каталога-родителя:

```bash
graphify extract . --code-only --no-cluster
graphify explain "auth.py"
graphify explain "pilot.py"
graphify path control_center_oauth_broker control_center_auth
graphify path agent_budget_pilot agent_budget_policy
graphify query "which code imports control_center.auth?"
```

`--code-only` ограничивает обработку локальным AST, без LLM API.
`--no-cluster` оставляет исходные извлечённые связи без кластеризации.
Не использовать `--no-gitignore`; стандартный `graphify-out/` исключён из Git.

**При первом запуске на новом checkout** оригинальный Graphify 0.9.97
автоматически читает [корневой `.graphifyignore`](../../.graphifyignore)
**в дополнение к `.gitignore`**. Это штатный upstream-механизм, а не
собственная обёртка. Правила исключают `third_party/`, vendor/dependencies,
временные каталоги, `.env*`, ключи, базы, state/logs и приватные пути.
Не копируйте сюда настоящие credentials. Не сканируйте домашнюю папку или
родительскую директорию с несколькими проектами.

Уже заданные ранее `--exclude PATTERN` оригинальный CLI сохраняет внутри
производных артефактов Graphify для последующих запусков **того же графа**.
Это не заменяет `.graphifyignore` для нового checkout. После изменения
правил повторный `extract` пересматривает состав индекса; при сомнении
можно запустить `graphify extract . --code-only --no-cluster --force`,
не удаляя ничего из репозитория.

Проверяйте `graphify-out/graph.json` по путям `source_file`,
`source_location` и концам рёбер; совпадений с запрещёнными каталогами
быть не должно. У части узлов `source_file` может отсутствовать — нулевые
совпадения по маскам не доказывают абсолютного отсутствия секретов.
`git check-ignore -v graphify-out/graph.json` должен показать правило
`.gitignore`. Никогда не копируйте полный граф в Issue/PR или внешнее хранилище.

Команды `path` выше проверены по реальному исходному коду Hermes:
`control_center/oauth_broker.py` импортирует `control_center.auth`, а
`agent_budget/pilot.py` использует `agent_budget.policy.verify_metrics`.
Свободный `query` может выдавать нерелевантные узлы или усекаться по
бюджету — результат нужно проверять по исходникам и тестам.

Подтверждать найденные связи по **текущим исходникам и тестам**, а не по
графу. `EXTRACTED` и `INFERRED` - метки вывода Graphify, не гарантия
фактического вызова. Если граф устарел или Graphify недоступен, достаточно
обычного поиска и чтения исходников.

## Codex Desktop (опционально, штатный upstream skill)

```bash
graphify install --platform codex --project
```

Если оригинальный Graphify skill **уже** обнаружен в текущей сессии
Codex Desktop через существующую пользовательскую установку, не нужно
повторно устанавливать его в Hermes. При явном согласии на **проектную**
установку команда выше копирует оригинальный skill в
`.codex/skills/graphify/` (и его `references/`, если они поставляются
upstream). Сначала проверить файлы и точный diff на отдельной рабочей
ветке; не перезаписывать существующие навыки.

**Не** использовать `graphify codex install`: это другой режим,
который может изменить `AGENTS.md` и Codex hooks; здесь он не разрешён.
Сверить `AGENTS.md`, `.agents/README.md`, разрешения и owner gates.
В Codex используется `$graphify`. Никакой Codex CLI, Claude CLI или
копии upstream-движка в проект для этого не нужно.

**Не выполнять** `graphify install --platform hermes`: это другой,
resident-agent контур, который требует отдельного owner-gate и не входит
в Issue #631. Запрещено автоматически включать Graphify Cloud,
семантический LLM проход, платные API, MCP/HTTP-сервер, watch,
post-commit hooks, strict interceptors, фоновые задачи, изменение прав
или отправку исходников наружу.

## Откат и статус проверки

```bash
uv tool uninstall graphifyy
```

Для `pipx` аналогично `pipx uninstall graphifyy`. Удалять только
`graphify-out/` и явно установленные Graphify skill-файлы; не менять
несвязанные пользовательские навыки. При обновлении пина сначала
`uv tool install --reinstall 'graphifyy==0.9.97'`, затем повторять
реальный AST smoke и несколько `query/path/explain`.

**Доказательства (29.10.2026):** репозиторное внедрение [#631](https://github.com/MikeMoore1337/hermes/issues/631)
проверено на Linux/Docker sandbox: оригинальный Graphify 0.9.97,
code-only граф, `explain`/`path`/`query` с кодами 0 и ограниченный
аудит путей узлов и рёбер. Для безопасности нового checkout добавлен
штатный `.graphifyignore` ([#674](https://github.com/MikeMoore1337/hermes/issues/674)).
Для любой новой локальной приёмки отдельно фиксировать точный Git SHA,
версию CLI, состав графа, exit codes и сохранность Git.

**Не подтверждено:** фактический Graphify-run *на Windows* из Hermes
checkout в Codex Desktop. Песочница Linux не считается Windows-приёмкой.
Граф не равнозначен source/tests/ADR и не подключён к resident Hermes Agent.
