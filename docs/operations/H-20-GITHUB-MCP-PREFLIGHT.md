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


## Финальное исследовательское решение #187 - 18.10.2026

**Verdict: `KEEP_REST`; GitHub MCP runtime: `NO_GO`.**
Исследовательский вопрос "даёт ли MCP практическое улучшение действующего H-04" разрешён отрицательно; это не оценка всех потенциальных будущих применений MCP.
Действующий `qa_advisor.github_public` остаётся единственным production GitHub-клиентом.
Новых токенов, прав, MCP-сервисов, model calls, egress и изменений H-01 нет.

### Основание и границы доказательств

- Baseline `main`: `22c63c2d91286540bdb3e10e4ca99d79fb0aa44d` на начало исследования. Предыдущий preflight: [PR #196](https://github.com/MikeMoore1337/hermes/pull/196), CI [#38915068974](https://github.com/MikeMoore1337/hermes/actions/runs/38915068974).
- Проверен реальный REST-код `qa_advisor/github_public.py` и `qa_advisor/core.py`. Для private Hermes он выполняет один whitelisted `GET /repos/MikeMoore1337/hermes/actions/runs?per_page=3` (или `branch=main&per_page=3`), токен обязателен из root-owned 0600 без symlink; один HTTP-вызов, timeout 12 секунд, редиректы/прокси/повторы отключены. `core.analyze` валидирует SHA/status/заключение и выставляет осторожные гипотезы, а не доказанные причины.
- Официальный [GitHub MCP Server v2.0.2](https://github.com/github/github-mcp-server/releases/tag/v2.0.2) опубликован 08.10.2026, выпуск проверен по release metadata. Ссылки на checksums/digests upstream являются **опубликованными метаданными**, не результатом независимой проверки загруженного бинарника.
- [Официальная конфигурация](https://github.com/github/github-mcp-server/blob/main/docs/server-configuration.md): `--read-only`, `--tools` и `--lockdown-mode` доступны; env `GITHUB_TOOLS` и `GITHUB_TOOLSETS` влияют на состав инструментов. `--tools` может комбинироваться с toolsets, поэтому отдельный флаг не доказывает фактический allowlist. Lockdown - best-effort content filtering, не авторизация. `readOnlyHint` стороннего MCP-сервера не является гарантией отсутствия побочных эффектов ([#350](https://github.com/MikeMoore1337/hermes/issues/350)).
- Новые десять offline-проверок: `tests/test_h20_mcp_rest_decision.py`; это **проверка существующего mock-контракта и REST-обработки**, не реальный MCP SDK/HTTP/stdio и не end-to-end сетевой benchmark.

### 10 проверяемых сценариев

В таблице `REST` означает **имеющуюся реализацию**, а не гипотетически расширенный REST-клиент. MCP означает существующий `OfflineFixtureTransport`, а не внешний сервер. Один logical operation не означает один сетевой round-trip MCP.

| Сценарий | REST / текущий H-04 | Ограниченный MCP preflight | Offline evidence / ограничение |
|---|---|---|---|
| 1. Статус workflow | Один GET Actions runs; SHA, status, conclusion | `actions_list`, фиксированные workflow/main/page/3; статусы без SHA | PASS для разрешённого mock; реальный RPC NOT_RUN |
| 2. Упавший CI | `analyze` классифицирует `failure_unknown_root_cause` | `actions_list` сохраняет failure, не доказывает причину | PASS; диагностика root cause NOT_VERIFIED |
| 3. Flaky / infrastructure | Сигнал `same_commit_success_and_failure_check_environment` по одному SHA, не диагноз | В результате нет SHA и jobs: эквивалентной классификации нет | PASS для проверки потери полей; доказанный infra root cause NOT_APPLICABLE |
| 4. Статус PR | Текущий REST allowlist PR запрещает; новый GET потребовал бы изменения контракта | `pull_request_read:get_status` возвращает только статус mock, без diff | PASS для mock; production capability NOT_RUN |
| 5. Required CI checks | Текущий GET Actions runs не подтверждает именованные обязательные checks | `actions_list` также не возвращает именованные checks | PASS для доказательства отсутствия поля; полноценная задача НЕ поддержана |
| 6. Состояние Issue | Текущий REST allowlist Issue запрещает | `issue_read:get` возвращает лишь номер и open/closed | PASS для mock; отдельное `Issues: read` не выдано |
| 7. Повторяющийся CI failure | По метаданным можно увидеть повтор failures, но не доказать общую причину | Можно увидеть два failures, без SHA/логов не доказать общий сбой | PASS; корреляция root cause NOT_VERIFIED |
| 8. GitHub 403/429 | Строгая sanitization, отдельные коды, один запрос без retry | Только отказ mock transport: нет реального HTTP 403/429 mapping | PASS для REST fake-opener, реальный MCP 403/429 NOT_RUN |
| 9. GitHub недоступен | Offline fake-opener даёт `public_api_network_error`; никакого fallback | Отсутствующая fixture даёт `mock_transport_failure` | PASS для fail-closed контракта; реальный MCP outage NOT_RUN |
| 10. Prompt injection | REST пропускает строго выбранные типизированные поля через анализатор | Text/metadata scrub; `issue_write`, alias, repo-escape и merge запрещены до mock transport | PASS для mock, external server safety NOT_VERIFIED |

Таблица описывает **доступность сведений и исход проверки**, а не равную функциональную полноту. Для PR/Issue прямой REST можно расширить при будущей продуктовой потребности, без обязательного введения MCP. Сейчас такой потребности у CI watcher нет.

### Сравнительная матрица решений

| Критерий | Прямой REST H-04 | GitHub MCP как новый runtime | Подтверждённость |
|---|---|---|---|
| CI Actions metadata | Есть, один фиксированный endpoint | Есть mock `actions_list` | REST production подтверждён ранее; MCP offline |
| PR/Issue reads | Не включены в текущий REST-контур | Mock статус-only; потребует новых прав | Источник GitHub docs + исходники |
| Количество логических обращений | 1 GET для snapshot | 1 tool call + protocol/discovery при новом соединении | Реальные количества и handshake NOT_MEASURED |
| Настройка/зависимости | Python stdlib, один файл токена | Отдельный бинарник и клиент/транспорт/схемы | Архитектурное сравнение, не benchmark |
| Разрешения | `Actions: read` для конкретного Hermes | Для CI `Actions: read`; `Issues: read` и `Pull requests: read` только при новых задачах; `Contents: read` не нужно для текущих 10 кейсов | Матрица необходимых прав, не проверенные новые grants |
| Tool/injection surface | URL allowlist, typed normalized metadata, без model tool discovery | Tool schema, annotations, сторонний контент и новые RPC | Подтверждённая разница поверхностей; риск #350 |
| Write denial | Код без методов записи, нет непредусмотренного транспорта | Mock gate deny before transport, но remote readOnlyHint недостаточен | PASS offline; OS-level NOT_RUN |
| Network egress | Фиксированный API origin, no proxy/redirect | Нужен отдельный pinning egress, no shell/Docker socket | OS/network enforcement NOT_RUN |
| CPU/RAM | Нет постоянного отдельного процесса | Ещё один sandboxed process, лимиты и stop/rollback | Дополнительный runtime подразумевается; расход NOT_MEASURED |
| Ошибки/429 | Явная классификация 401/403/404/429/5xx/network | Реальная сериализация MCP ошибок неизвестна | REST offline fake errors проверены |
| GitHub rate limits | API rate budget без automatic retry | Тот же underlying GitHub API; нет доказательства лучшего budget | Оценка, реальные rates NOT_MEASURED |
| Latency / bytes / tokens | Не замерялись сопоставимо | Не замерялись сопоставимо | `NOT_VERIFIED`, mock timing не сетевой |
| Обслуживание | Один поддерживаемый существующий контур | Версия server, обновление, CVE, transport и allowlist | Оценка сложности |
| Практическая польза | Закрывает текущую задачу | Улучшение текущей задачи не продемонстрировано | `KEEP_REST` |

**Методика будущего benchmark** (только после нового полезного use case и owner GO): закрепить версию/image digest, один и тот же репозиторий/права, 10 идентичных заданий, холодный/тёплый старт отдельно, `initialize`/discovery отдельно, число реальных API/MCP вызовов, monotonic latency p50/p95, размеры request/response/metadata в байтах, число schema tools в LLM context и реальные токены модели только по её usage. Local fixture bytes и простая оценка JSON chars не равны network bytes или tokens. Здесь сетевой/модельный benchmark = `NOT_RUN`; нет сравнимого ускорения/экономии.

### Threat model и возможное будущее включение

Злоумышленник может контролировать Issue/PR title/body, commit text, описание tool, misleading `readOnlyHint`, JSON payload или неожиданный redirect. Новая интеграция обязана проверять owner-controlled allowlist и repo/workflow identity **перед RPC**; возвращать только очищенные сведения, ограничивать byte/response budget и не передавать инструкции из контента модели. Отдельный runtime: непривилегированная учётная запись, ограничение outbound `api.github.com`, закрытый shell/Docker socket/private vault/YFC, CPU/RAM/time caps, verified binary digest, фиксированные GitHub rights и отключаемый процесс.

Только для будущих PR/Issue сценариев отдельные scoped credentials (`Issues: read` / `Pull requests: read`) могут быть обоснованы после отдельного owner approval; текущий Actions PAT не расширяется. Никакого объединённого YFC/Second Brain/Hermes credential. `--read-only`/`--tools`/`--lockdown-mode` - defense in depth, а не самостоятельная security boundary. Real stdio/Streamable HTTP, permission side-effects, alias/cache/reconnect, runtime constraints и точный бинарник = `NOT_RUN`/ `NOT_VERIFIED`; вопрос фактических владельческих разрешений остаётся в #350, не блокирует H-01 #33.

### Приёмочная матрица исследовательского исхода

| Критерий | Статус | Основание |
|---|---|---|
| Existing REST baseline | PASS | `github_public.py`, #5, PR #39 |
| MCP offline contract | PASS | PR #196, mock-only gate |
| 10 comparison scenarios | PASS | `test_h20_mcp_rest_decision.py` + таблица выше, offline only |
| Read-only policy | PARTIAL | Mock deny; внешний runtime не протестирован |
| Forbidden tool rejection | PASS | Отказ до fake transport, не до real RPC |
| Prompt injection resistance | PARTIAL | Raw text scrub offline, внешний MCP NOT_VERIFIED |
| Runtime permission enforcement | NOT_RUN | Нет нового MCP runtime |
| Latency comparison | NOT_VERIFIED | Нет сопоставимых live измерений |
| Token overhead | NOT_VERIFIED | Нет модельных usage данных |
| Security boundary | PARTIAL | Offline граница есть, OS/network real MCP не проверены |
| Practical benefit | PASS | Не обнаружен оправданный сценарий замены REST |
| Production non-interference | PASS | Новая интеграция не активирована, H-01 не изменён |
| Architectural decision | PASS | `KEEP_REST`, MCP activation `NO_GO` |

Не считать `PASS` синтетического теста разрешением запускать GitHub MCP. Закрытие #187 означает завершение исследования и отказ от внедрения в текущем H-04, **не** эксплуатационную приёмку MCP. Возвращаться к MCP только при новом подтверждённом функциональном сценарии, доказательстве пользы против расширения REST и отдельном security/owner GO (#350).
