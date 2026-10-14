# Интеграции и допуск источников

Реестр для задач Hermes: [H-09 / правила принятия](REGISTRY.md) и [машиночитаемые кандидаты](candidates.json).

Проверить безопасно, без сети и доступа к ключам:

```bash
python3 -m integrations.registry --validate
```

Статусы GO/DEFER/REJECT **не включают** инструменты, внешние сервисы или новые права. GO требует точный контракт в коде, CI и отдельное согласование фактического запуска. REJECT означает запрет на установку и обход платных/подписочных механизмов. Приватный GitHub Actions Hermes пока HTTP 404, поэтому DEFER; публичное чтение YFC подтверждено.

YFC остаётся владельцем новостного ingestion и публикации; Second Brain - своего vault и API. Нельзя выполнять write, публикации, обход защит или получать новые credentials только на основании записи в реестре.

См. [ownership](../docs/architecture/OWNERSHIP.md), [AGENTS.md](../AGENTS.md) и [H-09 #61](https://github.com/MikeMoore1337/hermes/issues/61).
