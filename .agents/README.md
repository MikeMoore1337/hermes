# Hermes: навыки для разработки (без доступа к runtime)

Содержимое `.agents/skills/` - справочные `SKILL.md` для AI-клиента, работающего с **этим репозиторием**, а не установка в resident Hermes Agent. Источник: [AI Development Toolkit](https://github.com/MikeMoore1337/ai-development-toolkit/tree/3a9bf14772ab579d37c6f4f9615db505ab6ac259) (commit `3a9bf14772ab579d37c6f4f9615db505ab6ac259`). Текущие GitHub Issue, `AGENTS.md`, `docs/architecture/OWNERSHIP.md`, `docs/security/THREAT_MODEL.md` и `docs/operations/feature-delivery-playbook.md` имеют приоритет.

| Задача | Условный skill |
| --- | --- |
| Новый runtime/framework, оркестрация | `agent-framework-fit` |
| Приём внешних навыков, MCP, hooks | `external-skill-review` |
| Trust boundary VPS, устройства, private data | `security-boundaries` |
| Free provider/лимиты/достоверная тарификация | `provider-reality-check` |
| Исследовательский источник, научные новости | `research-verification` |
| Версии API, JSON/events и интеграции YFC/Second Brain | `contract-testing` |
| Затронутые компоненты/расписания/тесты | `change-impact-analysis` |
| Комплексный аудит UX/UI Control Center и один дизайн-проект | `ux-ui-design-orchestra` - до трёх действительных read-only экспертиз либо последовательный режим, до визуального согласования |
| UX/UI Control Center (основная критика дизайна и полировка) | `impeccable` (pinned upstream, только разработка) |
| Browser/Control Center сценарий | `browser-workflow-evidence` |
| Проверка уже разрешённого выпуска | `release-safety` |

**Оригинальный Graphify - отдельно устанавливаемый по согласию разработчика инструмент для изучения зависимостей.** См. [локальную инструкцию](../docs/operations/graphify-development.md). Не копировать в runtime `skills/` и не включать resident `graphify hermes install`.

Загружай только необходимые в задаче навыки, обычно 1-2; роли, controller и копии состояния не создаются. Текущий `skills/` - отдельная потенциальная runtime-поверхность и остаётся неизменным. Ни один из этих документов не активирует агента, не даёт токены, не исполняет команды и не разрешает платные API, production, публикацию или доступ к чужому vault. Для изменений с последствиями нужен самостоятельный Issue/CI/owner gate.


Для отдельных задач разработки можно применять
[ограниченную QA/Feature Delivery оркестрацию](../docs/operations/feature-delivery-playbook.md#условная-оркестрация-экспертиз-только-разработка):
один исполнитель на ветку и PR; до трёх независимых read-only направлений только
при необходимости, иначе последовательный режим. Это **не** запуск
`Hermes Agent`, не разрешение на LLM API, публикацию, VPS или private vault.

Impeccable source доступен только после инициализации Git-подмодуля `.impeccable` (см. `../docs/ux/impeccable-control-center.md`). Это не runtime Hermes Agent и не новый разрешённый бинарник. Existing source Toolkit skills и owner approval первичны.
