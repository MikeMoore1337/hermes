# Hermes Control Center: UI, визуальные свидетельства и внешние методики

Issue #440. Control Center **уже существует** как React 19/Vite frontend `control_center/frontend`, с Playwright, Lucide, графитово-синей темой и PWA. Называть Hermes проектом без UI некорректно. Этот протокол не изменяет backend, OAuth, resident Agent или production.

## Целевое применение

| Задача | Внешняя идея | Собственный инструмент | Решение |
|---|---|---|---|
| Визуальная проверка | `daymade/frontend-visual-qa`: захват конкретных состояний и размеров | `qa/accessibility.spec.js`, `qa/control-center.spec.js`, `qa/visual-evidence.spec.js` | Внедряем воспроизводимые Playwright evidence attachments, только синтетика |
| Критика интерфейса | `pbakaus/impeccable`, `ibelick/ui-skills` | текущий Atlas C+B / C+A, UI QA | Справка при конкретном дефекте, не новый дизайн, не хуки |
| Анимация/производительность | `iart-ai/web-animation-skills`, `LottieFiles/motion-design-skill` | CSS + `prefers-reduced-motion`, accessibility tests | Проверять функциональную обратную связь и кадры, только при изменении motion |
| React-компоненты | `shadcn-ui/ui`, `starc007/ui-components`, `motiondivision/motion` | существующие React/CSS и Lucide | Без новых зависимостей до подтверждённого пробела; отдельный прототип |
| Исследования | `199-biotechnologies/claude-deep-research-skill` | `research_scout`, `research-verification` | Переносить методы атрибуции/проверки утверждений отдельно, без поисковых API и оркестратора |
| Автоматизация браузера | `vercel-labs/agent-browser` | Playwright | Опциональное изолированное сравнение, не замена QA и не подключение production session |

## Исполняемый UI evidence сценарий

Исходник: `control_center/frontend/qa/visual-evidence.spec.js`. Он использует только локальный сервер и подменённый `/api/overview`, не обращается к OAuth, внешним аккаунтам или реальному мониторингу. Для каждого viewport сохраняет PNG **как Playwright attachment**, JSON с route/state/viewport и проверяет отсутствие pageerror, неверной геометрии и сохранение основных элементов управления.

Из корня репозитория после установки уже закреплённых frontend-зависимостей:

    npm --prefix control_center/frontend run test:e2e -- visual-evidence.spec.js

Остальной обычный QA: `npm --prefix control_center/frontend run test` и `npm --prefix control_center/frontend run build`. Если Chromium не установлен в тестовой машине, evidence = NOT_RUN, а не PASS; setup отдельный от production.

## Запись результата

Для каждого изменённого UI состояния: exact SHA, URL/состояние, viewport, mocked/live marker, PNG, видимый результат операции, консольная ошибка, проверка фокуса и overflow, применимость reduced-motion. Сопоставить с утверждённым Atlas/брендом и существующими контрольными точками. Не считать synthetic результат тестом реального GitHub OAuth, телефона, VPS или Telegram. Не прикладывать снимки с токенами, cookies, именами реальных устройств, квотами и приватными данными.

## Границы

- `AGENTS.md`, право владельца на визуальное утверждение, H-15 и политика read-only имеют приоритет над внешними советами. Никаких изменений `skills/`, `systemd`, провайдеров, серверных путей или продакшн-деплоя.
- Не устанавливать всё из Superpowers/Impeccable/Taste, не запускать сторонние hooks/CLI, не добавлять платные API. Сначала фактический дефект, потом точечный метод.
- Источники - ссылки для самостоятельной проверки, **не копии файлов**: https://github.com/daymade/claude-code-skills/tree/main/frontend-visual-qa ; https://github.com/pbakaus/impeccable ; https://github.com/ibelick/ui-skills ; https://github.com/iart-ai/web-animation-skills ; https://github.com/vercel-labs/agent-browser.
