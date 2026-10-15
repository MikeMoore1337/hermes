# H-01 - проверка тестов исходников v0.22.1 отдельно от Docker-релиза

Проверено 15.10.2026 по [официальному GitHub Actions CI](https://github.com/NousResearch/hermes-agent/actions/runs/38644080305), точный исходный commit `297552a9d646119871391d202509822cd86330df`.

## Что действительно выполнялось

- Успешны Python tests (1/2 и 2/2), Ruff, Windows и macOS tests, Rust cargo test, JS/TS checks, реальные тесты SSH/Docker backend.
- Успешен итоговый `All required checks pass (v2)`.
- Отдельные задания `Supply-chain scan`, `Python tests / e2e`, `Desktop core E2E` в этом CI пропущены.
- [Стабильный Docker-релиз](https://github.com/NousResearch/hermes-agent/actions/runs/38646275925) содержит четыре успешных сборки образов и проверку опубликованных файлов, но его собственные `Full CI pipeline` и четыре `Run docker integration tests` имеют результат **skipped**.

**Следствие:** исходный код успешно проверялся, но это не доказывает, что именно опубликованный Docker-образ проходил те же интеграционные тесты. Противоречия между двумя фактами нет: это разные прогоны.

## Воспроизводимая проверка

Безопасный режим: `python3 scripts/verify_upstream_source_ci.py` -> `NOT_EXECUTED` без сетевых запросов.

Проверка: `python3 scripts/verify_upstream_source_ci.py --execute` - ровно два чтения из публичного GitHub API (workflow metadata и список его 40 jobs). Проверка фиксирует точные `run_id`, `head_sha`, статусы и обязательные задания, отклоняет подменённые и пропущенные элементы.

Даже если основные проверки прошли, выдаётся `SOURCE_CORE_CI_PASS_IMAGE_UNVERIFIED`, код выхода 2 и `resident_agent_allowed=false`. Инструмент не читает логи, не имеет GitHub write, не запускает Docker или модель и не запрашивает личный токен.

Открытые условия [H-01 #33](https://github.com/MikeMoore1337/hermes/issues/33): проверенная цепочка исходник -> сборка -> образ, полная SBOM, отдельные безопасные проверки immutable Docker digest, нагрузочная устойчивость, независимая техническая защита от платных списаний.
