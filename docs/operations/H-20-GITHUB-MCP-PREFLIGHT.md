# H-20 / #187 - offline GitHub MCP preflight для QA Advisor

## Фактический результат

Официальный [GitHub MCP Server](https://github.com/github/github-mcp-server) изучен, **не устанавливался и не запускался**, API GitHub не вызывался. Текущий встроенный `qa_advisor.github_public` / `ci_snapshot` сохраняет прежний единственный ограниченный REST-клиент. Файл `qa_advisor/github_mcp_preflight.py` - исследовательский **mock-only** request gate на стандартной библиотеке Python; не импортируется работающей службой. Принимает только `OfflineFixtureTransport`, который возвращает заранее подготовленные данные и не умеет выполнять сеть.

Обоснование: для существующей задачи наблюдения `main` workflow 381262090 прямой GitHub REST проще, меньше и уже проверен на VPS. MCP увеличивает поверхность tool-discovery, разрешений и prompt-injection. Вывод текущего этапа: **для QA CI-watchers замена REST на MCP не обоснована**. Новый MCP можно рассматривать только для будущего анализа разрешённых PR/Issues и после отдельного допуска.

## Upstream API / политика

- Изученная версия: GitHub MCP Server `v2.0.2` (GitHub release 08.10.2026), основная лицензия MIT, источник https://github.com/github/github-mcp-server/releases/tag/v2.0.2 .
- Документация: https://github.com/github/github-mcp-server/blob/main/docs/server-configuration.md и https://github.com/github/github-mcp-server/blob/main/README.md .
- В реальном бинарнике настройки `--read-only`, `--tools`, `--lockdown-mode` существуют. Даже вместе они **не** заменяют repository-scoped credential, OS process isolation, network ACL, runtime-timeout и непрерывную проверку точного image/binary digest. `--lockdown-mode` - best-effort фильтрация недоверенного содержимого, не security boundary.
- До отдельного аудита запуска допустима концептуальная allowlist только для `actions_list`, `issue_read`, `pull_request_read`, плюс repo-scoped fine-grained PAT с read-only правами. При практической установке запрещено включать стандартные широкие toolsets. Никогда не использовать `actions_run_trigger`, `issue_write`, `create_pull_request`, `get_job_logs`, произвольное чтение файлов/репозиториев и внешние MCP tools.

## Реализованный mock-контракт

- `actions_list`: **только** `method=list_workflow_runs`, `owner=MikeMoore1337`, `repo=hermes`, `resource_id=381262090`, `workflow_runs_filter.branch=main`, `page=1`, `perPage=3`.
- `issue_read`: только `method=get` для `hermes`, числовой номер Issue. Из ответа возвращаются номер и `open/closed`, но **не содержимое Issues**.
- `pull_request_read`: только `method=get_status` для `hermes` и разрешённого числового PR; из ответа берётся фиксированный статус, без diff/comments.
- Все остальные инструменты, методы и параметры отклоняются **до** вызова fake transport. Недопустимы Second Brain vault, YFC production, получение сырых логов, произвольные URL, подсказки на повышение прав, заголовки авторизации, токены, сторонние tools.
- Только ограниченный размер JSON (64 KiB), типы/количества элементов, фиксированные коды ошибок. Сведения из title/body/commit message не возвращаются: недоверенный текст не становится инструкцией.
- Выход `status=MOCK_ONLY`, `credential_used=false`, `remote_mcp_called=false`, `production_enabled=false`. Это **не** подтверждение безопасности внешнего сервера и реального PAT.

## Проверка

```bash
python3 -m unittest tests.test_h20_github_mcp_preflight -v
```

10 локальных unittest проверяют разрешённые запросы, 13 запретов вызова, неоднозначности типов, секреты в ответах, границы размерности, закрытие отказов, статусы CI, ненастоящие credentials и невозможность передать произвольный вызываемый network transport. Используются только вымышленные данные. Измерения реального MCP latency/token overhead = **NOT_RUN**, потому что живой сервис и модель не допущены. Прямые CI-запросы существующего QA Advisor не меняются.

## Невыполненные условия для live GO

1. Проверенный immutable бинарник/контейнер с SBOM, CVE и происхождением сборки + проверенная версия/хеш (сама ссылка на release не заменяет проверку).
2. Отдельные минимальные `Actions: read` / `Issues: read` / `Pull requests: read` права, строго для одобренного repository. Не расширять текущий PAT по умолчанию.
3. Реальная sandbox-граница: OS identity, network egress к `api.github.com`, ограничение прав на уровне сервера и runtime; проверки отказов на настоящем MCP.
4. 10 проверенных end-to-end запросов с измерением качества/latency/объёма контекста и сравнением с текущим REST. Если MCP не лучше, не внедрять.
5. Отдельное разрешение для подключения каждого репозитория (YFC, Second Brain и т. д.), никаких private vault/direct DB и отдельный допуск по #33 для постоянно работающего агента.

**Текущее решение: REST остаётся рабочим контуром.** Реальное MCP-подключение **NO-GO**; production VPS, токены, модели и GitHub permissions не меняются.
