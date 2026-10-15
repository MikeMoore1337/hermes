# H-01 - оценка официального кандидата Hermes Agent v0.22.1 без скачивания и запуска

Дата: **15 октября 2026 года**, проверен публичный GitHub и Docker Hub через изолированные read-only запросы с VPS, без загрузки образа, model calls, остановки новостей или чтения аккаунтных секретов.

## Почему оцениваем новую версию

Согласно [официальным GitHub Releases](https://github.com/NousResearch/hermes-agent/releases), по состоянию на проверку опубликованы `v0.21.7` (12.10), `v0.22.0` (14.10) и **`v0.22.1` (14.10 23:59:24 UTC)**. Поэтому считать `v0.21.6` самой новой версией было бы фактической ошибкой. Исследованный ранее образ `v0.21.6` остаётся заблокированным из-за несовпадения его version tag и release receipt. [Аудит старой версии](H-01-upstream-docker-receipt-drift-2026-10-15.md).

## Прямые подтверждения по v0.22.1

- [Официальный релиз](https://github.com/NousResearch/hermes-agent/releases/tag/v0.22.1), исходный commit `297552a9d646119871391d202509822cd86330df`.
- Git annotated tag object `28106ea1a3230177edb30a0a4e8a099d839bbc2f` (**сам тег не подписан**) содержит `dockerManifestDigest=sha256:861c9756ed6c558530c73d5c27860343b00c0d5efd6997a1d8ec6416c8a2b485`, `claimTag=rc.5-v0.22.1` и `claimTagObject=dabfb2fed3d3172579a15a005fd784208db555d0`.
- Аннотированный `rc.5-v0.22.1` указывает на тот же исходный commit `297552a9...`, а GitHub показывает для этого конкретного claim **`verification.verified=true`, `reason=valid`**, имеется SSH signature. В теле claim нет явного `skipTests=true`; **не** считать отсутствие этой записи доказательством выполнения всех тестов.
- Два независимых запроса `docker buildx imagetools inspect` подтвердили, что текущий `nousresearch/hermes-agent:v0.22.1` и неизменяемый `@sha256:861c9756...` дают **один и тот же** digest `861c9756...`.
- Точный состав `linux/amd64` = `sha256:cd9cb455576d27c9b6311de1104494ad7e221b6e68dc77e9ac2a8af661a4dc21`; `linux/arm64` = `sha256:f24de2fd617c0bef83a8fcec4cda996aaa463705f8097e62ec4fb60eb2618d6b`. Состав `v0.22.1` соответствует новой release receipt, в отличие от старой версии.
- Проверено только метаданными: манифест AMD64 содержит 37 сжатых слоёв общим размером **1 122 427 033 байта**, config digest `sha256:72cd23dcea49ddb3a2ccf6cb24b9b38088034ab2b465c68913730d25678dd01f`. На VPS в момент проверки было около **13 ГБ** свободного пространства. Это **не** оценка реального суммарного размера после распаковки и **не** разрешение скачивать новый образ.

## Что НЕ доказано

1. Проверенный SSH-tag **не является** подписанной проверенной аттестацией всего процесса сборки Docker; поле OCI SBOM и полный состав ОС/Python/Node ещё не проверялись для **нового** immutable digest.
2. Переход на v0.22.1 не был выполнен. Предыдущие PASS model probe/нагрузки относятся к **другому образу v0.21.6**, не могут автоматически засчитываться новой версии. Новые tests/smoke потребуют sandbox и отдельного согласованного допуска.
3. Cloudflare Workers Free и режим денежных расходов имеют только пользовательское подтверждение, **не** доказанную независимую техническую защиту от paid fallback.
4. Не доказана длительная совместная устойчивость resident Agent с новостями, Ops и Research на текущем VPS.
5. Никаких автоматических публикаций, инструментов shell/MCP и доступа к YFC/Second Brain нет и не планируется давать при переходе.

## Повторяемая проверка

```bash
cd /opt/hermes-agent-owner
python3 scripts/verify_upstream_release_receipt.py
# NOT_EXECUTED

python3 scripts/verify_upstream_release_receipt.py --release v0.22.1 --execute
# Если тег не изменился: MATCHED_BUT_PROVENANCE_UNVERIFIED
# Exit 2 и resident_agent_allowed=false, даже при совпадении.
```

Скрипт сохраняет старый режим `v0.21.6` для выявления исторического mismatch и допускает только два фиксированных тега. Всего три read-only обращения к общедоступным Docker Hub метаданным, ни `pull`, ни `run`, ни выдачи нового секрета. Для разрешения постоянного Hermes Agent потребуется отдельное подтверждение SBOM/provenance, бюджета, стабильности и разрешения владельца. Даже идеально совпавшие хеши одного публичного реестра не означают `GO`.

Связанные: [H-01 #33](https://github.com/MikeMoore1337/hermes/issues/33), [H-10 #62](https://github.com/MikeMoore1337/hermes/issues/62).


### Проверки исходного коммита отдельно от проверки образа

[CI push #38644080305](https://github.com/NousResearch/hermes-agent/actions/runs/38644080305) для exact SHA `297552a9...` завершился успешно, прошли Python unit tests и часть OS/Dockerfile проверок. Но [стабильный релиз #38646275925](https://github.com/NousResearch/hermes-agent/actions/runs/38646275925) имеет `Full CI pipeline=skipped` и четыре `Run docker integration tests=skipped`; отдельный [Docker push #38644079413](https://github.com/NousResearch/hermes-agent/actions/runs/38644079413) отменён. Таким образом, код имеет подтверждённые upstream проверки, но **это не равнозначно проверке exact released Docker image**. [Разбор заданий](H-01-upstream-release-ci-2026-10-15.md).
