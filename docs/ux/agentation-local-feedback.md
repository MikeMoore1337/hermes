# Agentation - локальные аннотации Control Center (#600)

Это **не функция Hermes Agent и не изменение production UI**. Включается только в локальном Vite dev-сеансе разработчика, чтобы выделять визуальные элементы, добавлять замечания и копировать их в задачу для Codex Desktop или ChatGPT. В production-сборку `control_center/web` не входит. UI evidence из [control-center-ui-evidence.md](control-center-ui-evidence.md) и визуальное согласование владельца остаются обязательными там, где они требуются.

## Запуск без установки в production

Внешний пакет [Agentation](https://github.com/benjitaylor/agentation) версии `3.1.2` лицензирован по **PolyForm Shield 1.0.0**, это не MIT. Учитывайте ограничения лицензии, не распространяйте чужой код и не устанавливайте пакет, если условия не подходят.

```sh
cd control_center/frontend
npm ci --ignore-scripts
npm install --no-save --package-lock=false --ignore-scripts agentation@3.1.2
HERMES_AGENTATION=1 npm run dev
```

Для PowerShell вместо последней строки: `$env:HERMES_AGENTATION='1'; npm run dev`. Открыть `http://127.0.0.1:5173/` на том же десктопе. Пакет ставится только по отдельному действию оператора и **не** включён в штатные зависимости и lockfile. Для отключения не задавать `HERMES_AGENTATION`, либо установить другое значение. Без opt-in Vite не внедряет devtools, а production `npm run build` не импортирует их при любых значениях переменной.

Интеграция использует только копирование аннотаций. Нет `agentation-mcp`, HTTP endpoint, webhook, автоотправки, авторизации к Hermes, изменения Caddy, Basic Auth, GitHub OAuth, фоновых процессов и резидентного AI. Пользователь копирует заметку вручную и должен удалить **персональные данные, приватные DOM-тексты, токены, имена компьютеров, внутренние хосты и снимки состояния** перед передачей внешнему ИИ или публикацией. Для снимков использовать синтетические данные из существующей галереи QA.

Аннотация - это указание на место дефекта, а не подтверждение его существования. Связывайте её с issue, SHA, маршрутом, темой, viewport, состоянием, ожидаемым поведением и реальным screenshot. Изменение дизайна происходит только после отдельного согласования владельца.

Offline проверка: `npm run check && npm test && npm run build` внутри `control_center/frontend` без необязательного пакета. В артефактах `control_center/web` не должно быть ссылки на `agentation`, `devtools/agentation.jsx` или сторонние сетевые сервисы. Реальное открытие Agentation в браузере остаётся `NOT_VERIFIED`, пока оператор не выполнит opt-in.
