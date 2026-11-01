# Hermes QA Advisor - анализ GitHub Actions без записи

[H-04 #5](https://github.com/MikeMoore1337/hermes/issues/5). Отдельный ограниченный клиент GitHub API **установлен на VPS и вручную проверен**. 15.10.2026 после корректировки PAT запрос к *приватному* `MikeMoore1337/hermes` вернул `NO_INCIDENT_EVIDENCE`, `observed_runs=3`, exit 0. Чтение трёх запусков публичного YFC ранее также проверено.

Действия только для ручного запуска:

```bash
cd /opt/hermes-agent-owner
python3 -m qa_advisor.github_public --repository MikeMoore1337/hermes
python3 -m qa_advisor.github_public --repository MikeMoore1337/your-fitness-coach
```

Private Hermes использует `/etc/hermes-agent/github-actions-read.token`: отдельный fine-grained PAT с `Actions: Read-only`, только `hermes`, root-owned `0600`, отсутствие ссылок и неизвестных полей. Публичный YFC запрашивается без токена. Токен НИКОГДА не передаётся публичному репозиторию.

Разрешён **один** фиксированный `GET https://api.github.com/repos/MikeMoore1337/<hermes или your-fitness-coach>/actions/runs?per_page=3`: таймаут 12 с, тело до 700 KiB, без прокси/редиректов/повторов/других URL. Данные сужаются до безопасных номеров запусков, фикcированных кодов статуса и SHA. API получает только read-only запросы. Ни push, ни merge, ни перезапуск CI, ни публикация, ни чтение raw logs не реализованы.

## Приёмка и диагностическая достоверность

- `qa_advisor.core.analyze` на метаданных различает выполненный/ожидающий запуск, сбой, отмену, тайм-аут, невозможность запуска и `same_commit_success_and_failure_check_environment` как **возможный сигнал нестабильности**, а не доказанную flaky-причину.
- `qa_advisor.evidence.summarize_log` - **только офлайн-функция**. Если оператор отдельно предоставил *очищенный*, допустимый к обработке фрагмент журнала, она ищет ограниченные категории (429/quota, права, сеть, тестовые ошибки, deploy) и возвращает **только фиксированные коды**. Исходные строки, токены, адреса и URL никогда не входят в ответ, не сохраняются и не отправляются. Это **не доказательство причины сбоя**: текст журнала может быть поддельным. Логи реальных CI автоматически не загружаются.
- `qa_advisor.evidence.scenario_review` сохраняет отдельно факт status/conclusion, гипотезы и шаг ручной проверки. 401/403/404/429/5xx не трактуются как здоровый CI. 403 может означать и rate limit: это отражено в коде `github_forbidden_or_rate_limited`.
- Негативные тесты проверяют red CI, flaky, quota 429, failed deploy, здоровый CI, отсутствие логов, отсутствие секретов в отчёте, запрет сторонних URL и отсутствие retries.
- Отдельный последний ручной запрос к приватному Hermes выполнился успешно после исправления токена; сведения о его полном наборе разрешений и политике срока действия подтверждаются владельцем в интерфейсе GitHub.

## Что не подключено

Последующий [PR #88](https://github.com/MikeMoore1337/hermes/pull/88) добавил отдельную автоматическую read-only службу и надёжное хранилище; теперь этот прежний этап завершён. Текущее состояние см. в разделе ниже. Сбой чтения API не должен ошибочно закрывать уже открытый инцидент как восстановленный. При обнаружении нового CI failure будут требоваться привязка к конкретному repo/run и защита от устаревших/переигранных запусков.

В GitHub Issue #5 кодовые и проверочные этапы можно отметить выполненными отдельно от production-планировщика. Работающий новостной конвейер YFC и служба Ops Watch не меняются.


## Дополнительная проверка качества только основной ветки Hermes

\`python3 -m qa_advisor.ci_snapshot --execute\` читает только \`main\` и
только workflow \`quality.yml\` (официальный workflow ID \`381262090\`,
проверен по CI #38680004024). Запрос жёстко ограничен
\`/repos/MikeMoore1337/hermes/actions/runs?branch=main&per_page=3\`,
нужен тот же защищённый read-only PAT. Без \`--execute\` ни чтения токена,
ни HTTP-запроса нет.

\`SUCCESS\` означает, что **новейший среди полученных запусков именно этого
workflow** завершён успешно; \`FAILURE\` - завершён с failure,
startup_failure или timed_out. \`RUNNING\` и \`UNKNOWN\` нельзя трактовать
как восстановление. Никакого однозначного диагноза root cause по метаданным
не утверждается. Из-за ограничения окна из 3 запусков отсутствие нужного
workflow даёт \`UNKNOWN\`, а не ложное OK.

Одноразовый диагностический клиент сам по себе не хранит состояние и не пишет в Telegram. Следующий самостоятельный `watch_once` в PR #88 уже сохраняет защищённый state, а существующий networkless Ops Watch принимает только фиксированный код инцидента; новый таймер получил отдельную проверку и установлен на VPS.


Ключевой инвариант: `SUCCESS` последнего запуска значит **проверен успех этого запуска**, а не автоматически доказано восстановление от наблюдавшегося раньше сбоя. Поэтому `verified_recovery=false` во всех независимых одноразовых проверках; подтвердить recovery сможет только будущая отдельная служба с хранилищем предыдущего `FAILURE` и более новым успешным `run_id`.


## Реальная автоматическая работа на VPS с 15.10.2026

После [PR #88](https://github.com/MikeMoore1337/hermes/pull/88) и успешного CI установлены `hermes-qa-watch.service` и `hermes-qa-watch.timer` с частотой 15 минут и без повторов/догоняющих запусков. Первый реальный запрос вернул `SUCCESS`, записал только минимальный сигнал в `/var/lib/hermes-qa-watch/ci-signal.json` (`0600 root:root`). Ops Watch collector вручную проверен после установки: `active_codes=[]`, queue 0, новостной конвейер и Telegram sender активны. [Доказательства и rollback](../docs/audits/H-04-private-ci-watch-vps-2026-10-15.md).

Появление нового CI failure ведёт к событию `ci_failed` в **том же уже разрешённом** Telegram-канале Ops Watch. Пока настоящий красный `main` workflow не возник, такая автоматическая доставка не доказана. При UNKNOWN/RUNNING и устаревшем ответе API ранее открытый инцидент не закрывается. Read-only API, без доступа к сырым логам или изменению GitHub.

## GitHub Events: наблюдение за задачами и PR (Issue #707)

В дополнение к прежнему 15-минутному CI-наблюдателю добавлен **событийный**, а не периодический режим: [`.github/workflows/github-event-observe.yml`](../.github/workflows/github-event-observe.yml) обрабатывает события GitHub от репозитория Hermes. Он запускается в бесплатном GitHub Actions на `issues.opened/reopened`, `issue_comment.created`, `pull_request_target.opened/reopened/synchronize/ready_for_review` и `workflow_run.completed` **только для существующего Hermes repository checks на main**. Внешние REST/MCP запросы и новые PAT не требуются. Сам CI-наблюдатель `watch_once`, его защищённый токен и действующий таймер **не изменены**.

Запуск события выполняет `python3 -m qa_advisor.github_event_observe --observe --event "$GITHUB_EVENT_NAME"` над единственным переданным GitHub JSON-файлом. Используется строго основной исходный код (`main`) с закреплённым для события SHA; `pull_request_target` никогда не исполняет код участника PR. GITHUB_TOKEN не передаётся скрипту; разрешение Actions ограничено `contents: read` и ничего не записывает в GitHub. Результат находится **только в журнале и Summary соответствующего GitHub Actions запуска**, а не в Hermes Control Center.

**Уточнение #712:** GitHub Actions закрепляет `actions/checkout` на `${{ github.sha }}`, а не на движущемся `main`. Для разрешённых событий (`issues`, `issue_comment`, `pull_request_target`, `workflow_run`) это Git-коммит канонической базовой ветки, а не PR HEAD. Контроль `git rev-parse HEAD == GITHUB_SHA` сохранён. Этим устранена гонка [GitHub Actions #41343189948](https://github.com/MikeMoore1337/hermes/actions/runs/41343189948), где после события `main` успела измениться и проверка ошибочно завершилась отказом.

Режим `--summary` формирует **читаемую рекомендацию на русском языке** с ссылкой на конкретный Issue, PR или CI run. Ссылка составляется только из заранее фиксированного GitHub-репозитория и строго проверенного числового ID, а не из текста или URL события. Без `--summary` CLI, как и раньше, возвращает один JSON-объект. Отчёт не отправляется во внешний канал и не предоставляет полномочий на выполнение.

| Событие | Безопасное предложение | Состояние |
| --- | --- | --- |
| Создана/переоткрыта задача | `REVIEW_ISSUE` | `WOULD_REVIEW` |
| Новый комментарий в Issue или PR | `REVIEW_FOLLOWUP` | `WOULD_REVIEW` |
| Создан/обновлён PR в main | `REVIEW_PR` | `WOULD_REVIEW` |
| Сбой обязательного CI на main | `REVIEW_CI_FAILURE` | `WOULD_REVIEW` |
| Успех обязательного CI на main | `NONE` | `NO_REVIEW` |
| Отменённый/неподтверждённый CI | `REVIEW_CI_UNCERTAIN` | `WOULD_REVIEW` |

Вывод содержит только фиксированные коды, числовой ID/номер и хеш `observation_key`. Исходные тексты Issue/PR/комментариев, произвольные ссылки, журналы CI и секреты **не передаются**. Все записи возвращают `mode=OBSERVE_ONLY`, `owner_approval=NOT_GRANTED`, `action_authorized=false`, `execution_authorized=false`, `model_calls=0`, `state_writes=0`. `observation_key` стабилен для повтора одного GitHub Actions run ID; **глобального дедупа между разными событиями нет**, поскольку новой БД не создаётся. Даже `WOULD_REVIEW` не означает вызов агента. Никакие новые действия в Hermes, YFC и Second Brain не выполняются.

Для локального воспроизводимого теста без GitHub и моделей:

```bash
python3 -m unittest tests.test_github_event_observe -v
python3 -m qa_advisor.github_event_observe
```

Вторая команда без `--observe` возвращает `NOT_EXECUTED` и ничего не читает. Чтобы проверить фикстуру явным образом, использовать `--observe --event issues --event-file /absolute/path/event.json --run-id 1` с вымышленным JSON; он должен содержать корректные `repository.full_name`, `action` и типизированный объект события.

**Приёмка:** обязательны exact-head GitHub CI, main CI и хотя бы один настоящий запуск GitHub Actions observer после слияния. Эти проверки не доказывают наличие работающего автономного Hermes Agent или передачу разрешения от владельца. Будущий автоматический исполнитель - отдельная работа с подтверждёнными OS/инструментальными полномочиями, владельческими разрешениями и квотами. Источник архитектурной идеи - [DeepSeek research prototype](https://github.com/deepseek-ai/dsh-superagent-prototype/tree/6337fc823ce20251c8de8085948165c81aaa701e), без подключения его runtime.


## GitHub Observe → Operator Inbox (#717)

В штатном \`hermes-qa-watch.timer\` раз в 15 минут выполняется **один
дополнительный ограниченный GET** метаданных 12 последних запусков известного
workflow GitHub Observe (Actions ID 403765637). Используется **существующий**
root-owned PAT только с \`Actions: read\`, без расширения scopes. Не читаются
Issues/PR contents, комментарии, артефакты и логи GitHub. Дополнительных
таймеров/агентов/LLM/баз данных нет; legacy проверка main CI сохраняет свой
первоначальный однократный GET.

Новый \`run-name\` в GitHub Actions содержит только перечисляемые типы
событий и действий, числовой ID, фиксированный код исхода CI и
назначенный GitHub идентификатор этого workflow run (github.run_id).
Читатель сверяет указанное значение с run.id из REST; старые
пользовательские заголовки Issue/PR не становятся доверенными событиями. Он никогда
не включает заголовок, описание, текст комментария или URL из GitHub.
Старые workflow run titles не соответствуют строгому формату и
пропускаются. Только \`status=completed\`, \`conclusion=success\` и
проверенный workflow ID/repository принимаются как успешные запуски
**наблюдателя**, а не подтверждение качества GitHub-события.

Файл \`/var/lib/hermes-qa-watch/github-observe-inbox.json\` записывается
атомарно под прежней root-owned директорией \`0700\`, режим файла \`0600\`.
Это **очищенный снимок**, не самостоятельное хранилище событий и не
exactly-once. Если дополнительный GitHub GET недоступен, основная
проверка CI не ухудшается; последний снимок сохраняется, а через 45
минут отмечается как \`STALE\`. Охват ограничен 12 последними запусками
и последними 24 часами, не полным архивом.

Уже существующая \`hermes-control-center-snapshot.service\` каждую минуту
читает этот файл как root и копирует лишь нормализованные значения в
существующий \`overview.json\`, доступный группе \`hermes-control\`.
Web-процесс Control Center сохраняет \`IPAddressDeny=any\`, Caddy/OAuth,
не получает PAT, сеть или права записи. \`Operator Inbox\` уже умеет
отображать дополнительный источник и строки без нового компонента/стилей.
\`github_observe\` имеет статус \`PARTIAL\`, \`STALE\` либо \`NOT_AVAILABLE\`,
никогда \`SUPPORTED\` по ограниченному окну. Ссылки на отдельные GitHub
Issues пока не открываются из строк: показываются проверенные номера и
подсказка открыть их в каноническом репозитории вручную.

Поведение остаётся строго \`OBSERVE_ONLY\`. В Inbox нет кнопок исполнения,
автоматического назначения Codex или доступа к YFC/Second Brain. Ни
\`REVIEW_ISSUE\`, ни \`REVIEW_PR\` не являются \`owner_approval\`.
