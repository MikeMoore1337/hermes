# Hermes

Приватный репозиторий **управления собственным Hermes Agent**: исследовательские агенты, мониторинг, правила, адаптеры и инфраструктурный код.

> **Статус: bootstrap / planning.** Репозиторий **не развёрнут** и не является владельцем работающего новостного конвейера YFC. Добавление этих файлов не меняет ни один сервер, сервис, секрет или публикацию.

## Зачем отдельный репозиторий

- Независимый жизненный цикл собственных агентов (Ops Watch, Research Scout, QA Advisor).
- Минимальные права для каждой интеграции: YFC, Second Brain, GitHub.
- Отдельные GitHub Issues, PR, проверки, решения и журнал совместимости.
- Предсказуемое использование upstream [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent): **не форк** и не копия движка.

## Документация

- [Правила для Codex и других агентов](AGENTS.md)
- [Архитектура и границы](docs/architecture/OVERVIEW.md)
- [Каноническое владение данными и контрактами](docs/architecture/OWNERSHIP.md)
- [План безопасной миграции конвейера новостей](docs/architecture/MIGRATION.md)
- [Безопасность и угрозы](docs/security/THREAT_MODEL.md)
- [Дорожная карта H-00...H-07](docs/roadmap/ROADMAP.md)
- [Эксплуатация и выпуск](docs/operations/DEPLOYMENT.md)
- [Решение о выделении репозитория](docs/decisions/ADR-0001-separate-repository.md)

## Текущие границы

Работающий новостной поток остаётся **в YFC**: discovery -> hardened editorial worker -> подписанный YFC intake -> ручная проверка -> Telegram. Его исходники, release, секреты, список источников и канонические проверки сейчас **не переносятся**.

Second Brain v4 проходит эксплуатационную проверку [#386](https://github.com/MikeMoore1337/second-brain/issues/386); прямой доступ к приватному vault и новые интеграции не разрешены. SEO Growth Operator уже учитывается в [YFC #322](https://github.com/MikeMoore1337/your-fitness-coach/issues/322) и блокируется условиями [#320](https://github.com/MikeMoore1337/your-fitness-coach/issues/320).

## Проверки

Только стандартная библиотека Python; запуск из корня:

```bash
python3 scripts/validate_repo.py
python3 -m unittest discover -s tests -v
```

CI проводит только статическую проверку репозитория, **не** развёртывает Hermes и не выполняет внешние AI-запросы.

## Начало работ

Первая задача - H-00: зафиксировать фактический runtime, доступы, ресурсные ограничения и схему размещения, **без изменений production**. Затем отдельным решением допускается H-01. Все последующие задачи оформляются Issues с критериями приёмки.
