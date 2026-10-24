# Integration I1: безопасная передача контекста задачи (development-only)

**Owner:** Hermes #556, roadmap #555. **Это не отдельный оркестратор, agent runtime, доступ к GitHub или производственный publisher.**

## Назначение

При переносе инженерной задачи между ChatGPT, Codex и разрешённой средой можно передать небольшой JSON-пакет с идентификатором задачи, указанием workspace, выбранным профилем Toolkit и *заявленными* статусами PR/тестов/CI/доставки.

Пакет помогает не потерять контекст. Он **не доказывает** фактическое выполнение работы и не даёт новых полномочий.

Канонические источники остаются отдельными:

- **Hermes BRC**: list_workspaces / resolve_workspace подтверждают *каталог*, но не Git origin, clean worktree или право записи; отдельно проверять реальные инструменты и режим.
- **Toolkit**: toolkit_prepare_task и уже существующий QA change-impact дают рекомендованные навыки и проверки, но не выполняют их.
- **GitHub**: фактические Issue, PR head SHA, checks и deployment receipts; любой сообщённый в JSON URL нужно независимо открыть и проверить, что SHA и результат соответствуют именно указанному изменению.
- **Second Brain**: никакой прямой записи/чтения vault; интеграция требует отдельных действующих gates.
- **YFC**: собственные release и editorial guards сохраняются.

## Формат v1

Один строго ограниченный объект, только четыре явно зарегистрированных sandbox-кода (Hermes, YFC, Second Brain, Toolkit). Например:

~~~json
{
  "schema_version": 1,
  "task": {
    "repository": "MikeMoore1337/hermes",
    "issue": 556
  },
  "workspace": {
    "alias": "hermes",
    "scope": "sandbox",
    "git_verified": false
  },
  "toolkit": {
    "profile": null,
    "selection": "NOT_VERIFIED"
  },
  "evidence": {
    "pr": null,
    "tests": {"state": "NOT_RUN", "ref": null},
    "ci": {"state": "NOT_VERIFIED", "ref": null, "sha": null},
    "production": {"state": "NOT_VERIFIED", "ref": null, "sha": null},
    "owner_acceptance": "PENDING"
  }
}
~~~

Допускаются только REPORTED_* заявления о пройденных шагах; валидатор возвращает **VALID_SHAPE_ONLY** и **source_claims=UNVERIFIED** даже при заполненном PR, положительном CI и заявленной приёмке. Поля execution_authorized, release_authorized, ready_to_close **всегда false**. Никаких PASS, PRODUCTION_VERIFIED или DONE из чужого текста.

Результат не может содержать shell-команды, абсолютные пути, device ID, секреты, произвольные ссылки, сырые логи или текст заметок. Ссылки ограничены GitHub paths данного репозитория; это фильтр формы, не свидетельство доверия. Размер входа ограничен 8192 байтами, нет сетевых вызовов, сторонних зависимостей и записи.

## Как проверить локально

Сохранить JSON из примера в обычный файл вне приватного хранилища. Далее в корне hermes:

~~~bash
python3 scripts/check_task_handoff.py < packet.json
python3 -m unittest tests.test_integration_task_handoff -v
~~~

Первая команда печатает нормализованный безопасный отчёт либо REFUSED с кодом ошибки и exit 2. JSON и ссылки остаются самосообщением: результат VALID_SHAPE_ONLY не означает, что GitHub был проверен.

## Реальный E2E для I1

1. Получить list_workspaces и resolve_workspace в клиенте. Зафиксировать actual device и sandbox path вне пакета, проверить Git origin/HEAD отдельным разрешённым инструментом.
2. Открыть указанную Issue через GitHub и проверить отсутствие дублирующего PR. Проверить Toolkit routing, реально выданный профиль/навыки и соответствие политике проекта. Если не проверено — оставить NOT_VERIFIED.
3. После разрешённого code change/PR открыть **реальную** GitHub PR, получить SHA, CI по тому же SHA. Валидатор **не** запускает эти действия.
4. Проверить deployment и runtime отдельно; source-only delivery не равен работающему сервису. Ручную приёмку не заменять REPORTED_ACCEPTED.
5. Составить пакет и прогнать check_task_handoff.py; в новом чате повторно проверить канонические GitHub/BRC/Toolkit источники перед продолжением.

## Не входит в I1

Новая очередь/БД заданий, автономный H-01, запросы к LLM, новые OAuth/tokens, GitHub write execution, production service/cron, доступ к оригинальным Windows-папкам, чтение private Second Brain vault, автоматическое подтверждение выпуска. Отложенные функции развиваются в собственных Issues #454, #455, #271, #6.

## Граница доказательств

- **Offline unit** подтверждает только формат, отказы и сохранение запретов.
- **Actual BRC tool-use** подтверждает ответ вызванного инструмента, но device_status=online не означает git_verified=true или file-write capability.
- **GitHub CI** подтверждается по фактической run URL и exact SHA.
- **Production** подтверждается отдельно наблюдением установки/здоровья потребляющего компонента.
- **Owner approval** подтверждается отдельным решением, не полем из JSON.
