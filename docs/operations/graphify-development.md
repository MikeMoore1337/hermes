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
graphify extract . --code-only
graphify query "which code depends on the Control Center API?"
graphify explain "OpsWatch"
graphify path "SourceModule" "TargetModule"
```

`--code-only` ограничивает обработку локальным AST. Не использовать
`--no-gitignore`; стандартный `graphify-out/` исключён из Git.
После построения проверить `graphify-out/graph.json` и выборочные
результаты на включение `.env`, секретов, операционных данных, соседних
проектов/Second Brain vault, каталогов state/logs, артефактов и баз данных.
Никогда не копировать полученный граф в Issue/PR или внешнее хранилище.

Подтверждать найденные связи по **текущим исходникам и тестам**, а не по
графу. `EXTRACTED` и `INFERRED` - метки вывода Graphify, не гарантия
фактического вызова. Если граф устарел или Graphify недоступен, достаточно
обычного поиска и чтения исходников.

## Codex Desktop (опционально, штатный upstream skill)

```bash
graphify install --platform codex --project
```

Команда может добавить `.agents/skills/graphify/` и `references/`.
Разрешена только после просмотра официального механизма установки и
диффа на **отдельной рабочей ветке**. Прежде чем оставлять новые файлы,
сверить их с `AGENTS.md`, текущим `.agents/README.md` и политиками доступа.
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

**Доказательства:** upstream v8 и команда `--code-only` проверены
по исходникам, но локальная установка на рабочем Windows-узле и сборка
графа Hermes не подтверждены автоматически этим документом. Нужно
отдельно зафиксировать: версию CLI, hash checkout, результаты поиска,
проверку приватности, exit codes, diff и статус PR/CI. Источник истины -
код, тесты, ADR и утверждённая Issue. Любой прогон через отдельную
Linux-песочницу нельзя выдавать за проверку Codex Desktop.
