# H-01: фактическое выполнение тестов официальных Docker-релизов

**Дата независимой проверки: 15 октября 2026 года.** Проверены официальные GitHub Actions завершённые задания и отдельные шаги (не только зелёный статус workflow). Все данные - публичный upstream [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent).

## Подтверждённые факты

| Официальный выпуск | Stable release workflow | Full CI pipeline | Docker slim/amd64 integration tests | Статус release run |
| --- | --- | --- | --- | --- |
| `v0.21.7` | [#38199200509](https://github.com/NousResearch/hermes-agent/actions/runs/38199200509) | **skipped** | **skipped** | success |
| `v0.22.0` | [#38491090442](https://github.com/NousResearch/hermes-agent/actions/runs/38491090442) | **skipped** | **skipped** | success |
| `v0.22.1` | [#38646275925](https://github.com/NousResearch/hermes-agent/actions/runs/38646275925) | **skipped** | **skipped** (также slim/arm64, desktop/amd64, desktop/arm64) | success |

Для `v0.22.1` в журнале успешного релиза **все четыре** сборки Docker отмечены `success`, шаг `Verify release image identity` - `success`, архивы тестового этапа прошли `sha256sum --check` перед `docker push`; однако шаг `Run docker integration tests` у каждой из четырёх сборок имеет **`conclusion=skipped`**, `Full CI pipeline` также `skipped`. Проверено по официальному [GitHub Actions jobs API](https://docs.github.com/en/rest/actions/workflow-jobs). Успешная проверка хешей не является интеграционным тестом.

В отчёте `v0.22.1` `All release acceptance checks pass` и `Stable release is green` - `success`. Это не отменяет вышеперечисленные пропуски; официальный stable pipeline разрешает отдельный режим пропуска тестов. Для старого выпуска `v0.21.6` claim RC4 прямо содержал `skipTests=true`. В claim нового `v0.22.1` такой явной записи нет, но фактические шаги свидетельствуют о пропуске. Причину режимов публикации не следует угадывать без официального подтверждения.

**Не утверждаем, что весь код вообще никогда не проверялся**. Возможно, upstream проводил тесты в отдельных workflow/до выпуска. Но соответствие **конкретного** опубликованного immutable образа полноценному тестированию этим конкретным релизным прогоном не доказано.

## Повторяемая проверка в Hermes

```bash
python3 scripts/verify_upstream_release_ci.py
# NOT_EXECUTED - по умолчанию сети нет

python3 scripts/verify_upstream_release_ci.py --execute --release v0.22.1
# Проверяет 1 официальный workflow + его jobs (до 4 страниц).
# UPSTREAM_REQUIRED_TESTS_SKIPPED, exit 2, resident_agent_allowed=false.
```

Скрипт допускает только зафиксированные публичные run IDs и исходные Git SHA для `v0.21.7`, `v0.22.0`, `v0.22.1`. Прямой HTTPS только к `api.github.com`, один run и максимум 4 страницы заданий, `per_page=100`, 8 секунд/запрос; никаких токенов, write endpoints, redirect/retry/ссылок от upstream. Проверка всех обязательных заданий по точному имени, отсутствия дублирования ID, полного количества страниц, заключений шагов и SHA. Не читает логи с потенциально приватными значениями; записывает только предопределённые признаки и результаты шагов. Изменение API или ошибка подключения - `UNKNOWN`, никогда не положительное заключение.

**Статус `UPSTREAM_TESTS_REPORTED_PASS_UNATTESTED` тоже не даёт разрешения**: даже полный успех шагов внешнего GitHub API не заменяет подписанную аттестацию исходник-сборка-образ, полный SBOM и независимую проверку текущего VPS/биллинга.

## Что делать дальше

1. Проверять отдельные upstream CI, относящиеся к тому же исходному SHA, без присвоения им статуса релизной аттестации. Запросить у производителя подтверждение тестов и provenance конкретного образа.
2. Скачивание/испытания нового образа `v0.22.1` вести на отдельной машине с ресурсами, а **не** на VPS с новостями: попытка загрузки на нём вызвала `load1` до 3.96, загрузка сразу отменена, рабочие таймеры не затронуты.
3. Не включать постоянный AI Agent или сетевую модель до подтверждения подписанного source-to-image, SBOM, нулевого биллинга, стабильности с новостями, выполнения собственных нагрузочных и функциональных тестов.

Связанные: [H-01 #33](https://github.com/MikeMoore1337/hermes/issues/33), [сверка release receipt](H-01-upstream-docker-receipt-drift-2026-10-15.md), [кандидат v0.22.1](H-01-new-release-v0221-candidate-2026-10-15.md).
