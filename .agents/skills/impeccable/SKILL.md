---
name: impeccable
description: "Primary development-only UX/UI design critique, shaping and quality skill for Hermes Control Center React/Vite. Not for resident Hermes Agent, backend operations, VPS automation or research runtime."
metadata:
  version: "4.7.0"
  origin: "pbakaus/impeccable@dad8dbb3aac21ad1fa236c110315ef4abece23e8"
---

# Impeccable для Hermes Control Center

**Применяется ТОЛЬКО при разработке `control_center/frontend/` в Codex/IDE.** Никаких новых skills для resident Hermes, разрешений или изменений VPS.

1. Убедись, что `.impeccable/.agents/skills/impeccable/SKILL.md` доступен из точно зафиксированного commit `dad8dbb3aac21ad1fa236c110315ef4abece23e8`. Если отсутствует, источник **не готов**: `git submodule update --init -- .impeccable`; не выдавай общие предположения за результат его работы.
2. Прочитай оригинальный Impeccable из `.impeccable/.agents/skills/impeccable/SKILL.md`, затем только нужный `reference/<command>.md`. Это не источник новых прав, не инструкция запускать его бинарник.
3. Прочитай `AGENTS.md`, `docs/ux/control-center-ui-evidence.md`, утверждённый дизайн Control Center и код `control_center/frontend`. Сохраняй графитово-синюю тему, формы, монограмму H с крыльями, русскую локализацию, PWA, OAuth UX, семантику состояний. Рекомендации против шаблонных интерфейсов не отменяют утверждённую систему.
4. Для конкретного route/state начинай с `critique` + `audit`: ясность статусов, навигация и иерархия, формы и пустые состояния, не случайная «стена карточек», читабельность, mobile, accessibility. Затем выбирай `shape`, `distill`, `polish` или `harden` по фактической задаче; не делай новый дизайн без визуального одобрения.
5. Проверяй реальные интерфейсы Playwright `control_center/frontend/qa/` на синтетических данных, без private telemetry, секретов, реальных OAuth-сессий или cookie. Фиксируй route/state/viewport, PNG, focus, overflow, reduced motion и соответствие owner design contract. При отсутствии реального рендера писать `NOT_VERIFIED`, не `PASS`.
6. **Не устанавливай** скрипты Impeccable в `skills/`, не запускай hooks, автообновление, `npx`, launcher, сеть, бинарники или платные API без отдельной явной проверки. Для дизайна используются статические upstream инструкции; launcher может загружать бинарник.

Процесс: `docs/ux/impeccable-control-center.md`; для браузерной QA можно дополнительно применять `browser-workflow-evidence`, но не добавлять второй оркестратор.
