# Архитектура Hermes

## Сейчас (проверяемые границы репозиториев)

- `your-fitness-coach`: работающий специализированный Hermes Discovery и hardened Editorial Worker, версия upstream pinned for provenance; код worker не включает произвольные shell/MCP/browser/plugins.
- `second-brain`: собственные знания/права/NoteDraft/Safe Write; `second-brain-vault` - отдельное закрытое хранилище.
- **Этот `hermes`**: пока только независимый репозиторий для будущего общего агентного контура; нет запущенных сервисов, интеграций или секретов.

## Цель

```text
Owner -> Hermes Agent (separate runtime, dedicated identity)
                  |
                  +-- Ops Watch -> authorized read-only health / CI metadata
                  +-- Research Scout -> allowlisted public sources
                  +-- QA Advisor -> read-only GitHub evidence
                  +-- Knowledge bridge -> future authorized Second Brain API
                  +-- Growth operator -> existing YFC #322 when evidence gate clears

EXISTING AND UNCHANGED:
Hermes Discovery -> Hardened Editorial Worker -> signed YFC intake
                  -> YFC owner review -> Telegram
```

Каждый агент получает минимальный набор реальных инструментов, собственный журнал, лимит времени/ресурсов/вызовов и явные границы данных. YAML/markdown-описания роли без enforcement не заменяют sandbox, OS identity или сетевые ACL.

## Не принимаемые решения

- Не писать собственный LLM-framework; использовать версионированный upstream при отдельном решении о runtime.
- Не размещать новое исполнение внутри ограниченного новостного worker.
- Не выдавать Hermes Docker socket, YFC DB credentials или файловый доступ к vault.
- Не делать автоматические релизы, публикации и редактирование чужих пользовательских данных.
- Не копировать полностью сторонние workflow; исследовать полезные паттерны и лицензии отдельно.

## Связанные документы

[Ownership](OWNERSHIP.md) · [Migration](MIGRATION.md) · [Threat model](../security/THREAT_MODEL.md) · [Roadmap](../roadmap/ROADMAP.md).
