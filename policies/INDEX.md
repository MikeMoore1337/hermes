# Индекс обязательных правил Hermes

Маршрутизатор **содержит только ссылки** на собственные канонические инструкции.
`AGENTS.md` обязателен для каждого типа задачи. Приоритет: системные ограничения и owner-approval -> `AGENTS.md` -> соответствующий источник истины и профиль задачи. Этот файл **не исполняет внешние SKILL/скрипты**, не делает web-fetch, не повышает права и не заменяет основной GitHub Flow.

| Работа | Что прочитать |
| --- | --- |
| Любая разработка | [AGENTS.md](../AGENTS.md), [ownership](../docs/architecture/OWNERSHIP.md), [CI/выпуск](../docs/operations/DEPLOYMENT.md) |
| Runtime / новая служба | [AGENTS.md](../AGENTS.md), [архитектура](../docs/architecture/OVERVIEW.md), [безопасность](../docs/security/THREAT_MODEL.md), [выпуск](../docs/operations/DEPLOYMENT.md) |
| Миграция новостей | [AGENTS.md](../AGENTS.md), [migration](../docs/architecture/MIGRATION.md), [ownership](../docs/architecture/OWNERSHIP.md) |
| YFC интеграция | [AGENTS.md](../AGENTS.md), [ownership](../docs/architecture/OWNERSHIP.md), [безопасность](../docs/security/THREAT_MODEL.md) |
| Second Brain интеграция | [AGENTS.md](../AGENTS.md), [ownership](../docs/architecture/OWNERSHIP.md), [безопасность](../docs/security/THREAT_MODEL.md) |
| Работа с внешним источником | [AGENTS.md](../AGENTS.md), [безопасность](../docs/security/THREAT_MODEL.md), [реестр интеграций](../integrations/REGISTRY.md) |
| H-03 исследование | [AGENTS.md](../AGENTS.md), [проверка исследований](../research_scout/REVIEW_RUN.md), [ownership](../docs/architecture/OWNERSHIP.md) |
| H-09 новая интеграция | [AGENTS.md](../AGENTS.md), [реестр](../integrations/REGISTRY.md), [безопасность](../docs/security/THREAT_MODEL.md) |
| H-02 уведомления | [AGENTS.md](../AGENTS.md), [Ops Watch](../ops_watch/README.md), [эксплуатация](../docs/operations/DEPLOYMENT.md) |

Состояние второго проекта, приватные данные или новые разрешения **не импортируются** только по ссылке. Для YFC соблюдать его собственный `AGENTS.md`, для Second Brain - его v4 #386 и отдельный GO. Ссылки проверяются локальным `scripts/check_policy_index.py` в CI; запрет внешних URL, выхода за корень репозитория и символьных ссылок.
