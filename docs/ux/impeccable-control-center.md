# Hermes Control Center - Impeccable 4.7.0 как UX/UI-критик

Source: [pbakaus/impeccable](https://github.com/pbakaus/impeccable), Apache-2.0, pinned Git commit `dad8dbb3aac21ad1fa236c110315ef4abece23e8`.

Интеграция относится **только к разработке интерфейса** `control_center/frontend`. Resident Hermes Agent, `skills/`, `agents/`, `ops_watch/`, VPS, OAuth broker, production и API-runtime не затрагиваются. Skill загружается Codex из `.agents/skills/impeccable/SKILL.md`, затем использует оригинальные материалы подмодуля `.impeccable/`.

## Подготовка

После checkout: `git submodule update --init -- .impeccable`; проверь: `git -C .impeccable rev-parse HEAD` должен дать `dad8dbb3aac21ad1fa236c110315ef4abece23e8`. Не использовать `--remote`; SHA меняется только отдельным PR. При отсутствии подмодуля навык указывает на отсутствие источника и не имитирует выполнение.

В Codex: `$impeccable` либо запрос «Проверь Control Center через impeccable critique, затем подготовь улучшения интерфейса». Само добавление skill не включает никаких фоновых проверок.

## Рабочая последовательность

1. Прочитай `AGENTS.md`, `docs/ux/control-center-ui-evidence.md`, утверждённую тему Atlas (графитово-синий, шрифтовое направление, Lucide, H-monogram), current React/CSS и тесты. `Operate` для панели и статусов, `Read` для содержательных документов, `Persuade` только для отдельного лендинга.
2. `critique`: найти реальную проблему на существующем экране. Ищи шаблонные SaaS-плашки, одинаковую иерархию карточек, искусственные градиенты, заголовки без полезной информации, пустые состояния и случайное свечение **относительно** фирменного дизайна, а не список универсальных запретов.
3. `audit`: проверить навигацию, keyboard/focus, contrast, 320/393/768/1440, empty/error/loading, long text, reduced-motion, 503 mock. Любой незапущенный сценарий - `NOT_RUN`.
4. `shape`/ `distill` / `polish`: покажи обоснованную альтернативу и её полные визуальные материалы, не меняй композицию без owner «Принимаю». Запрещено выдумывать новые устройства, лимиты, показатели, авторизацию или статусы.
5. После одобрения: существующие Playwright тесты `qa/control-center.spec.js`, `qa/accessibility.spec.js`, `qa/visual-evidence.spec.js`; PNG и информация о route/state/viewport/mock; проверка реального входа отдельно от synthetic. Exact SHA, CI и реальный production release остаются независимыми gate.

## Источник и границы

Оригинал хранится как Git submodule, поэтому его лицензия и notice остаются с исходником. Новых `npm`-пакетов, runtime API, hooks, бинарных launcher процессов и платных API нет. Не выполнять `scripts/impeccable` автоматически: он может загрузить исполняемый файл. Не использовать внешние веб-сервисы для приватных снимков/исходников.

Быстрый безопасный маршрут - прочитать в подмодуле `SKILL.md` и нужные `reference/critique.md`, `reference/audit.md` или `reference/polish.md` как инструкции, после чего применить текущие локальные тесты. Никакая диагностическая рекомендация не отменяет палитру и решения владельца.
