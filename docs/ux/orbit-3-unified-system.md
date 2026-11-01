# Hermes Command Center - единый интерфейс Orbit 3.0

Это действующая система оформления для ранее принятого дизайна «Орбита 3.0».
Документ не предоставляет новых прав, команд, API, OAuth или resident AI Agent.

## Шрифты и фирменный стиль

- Логотип - winged H из /orbit-brand.svg, фавикон и PWA - существующая семья Orbit.
- Интерфейс - Inter, Segoe UI, Arial, sans-serif. Для технических значений:
  Consolas, SFMono-Regular, Liberation Mono, monospace.
- Шрифты не загружаются с внешних серверов. В активных экранах Georgia запрещена.
- Важны иерархия заголовков, читаемые подписи, русская локализация, фокус,
  320/393/768/1440 и системная настройка уменьшенного движения.

## Токены и компоненты

Фактический единый контракт - control_center/frontend/src/orbit-unified.css.
Подключается после orbit-operator.css. Все значения локальны для .theme-orbit.

- --orbit-panel / --orbit-panel-alt / --orbit-panel-inset - графит и синий.
- --orbit-border / --orbit-border-strong / --orbit-radius - панели/поля/линии.
- --orbit-text / --orbit-subtext / --orbit-muted - текст.
- --orbit-accent / --orbit-focus - действие и управление с клавиатуры.
- --orbit-good / --orbit-warning / --orbit-danger - только проверенные статусы.
- --orbit-font-ui / --orbit-font-mono - общее правило типографики.

Единая карточка имеет тонкую границу, 4px скругление, стабильные отступы.
Цвет состояния не доказывает успешность выполнения; требуется источник и подпись.

## Иконки

- Все React-компоненты используют установленный lucide-react 0.468.0.
- Пункты меню и панельные иконки имеют 18px line icons, толщину 1.7.
- Исторические read-only JS-виджеты подключают один локальный,
  серверно-разрешённый orbit-ui-icons.js: три безопасных фиксированных SVG
  (Analytics/chart, Infrastructure/server, Quotas/gauge). Скрипт работает только
  на авторизованном экране и не делает запросов к сети.
- Архив Desktop Commander - только линейные inline SVG и winged H.
- Декоративные пиктограммы скрыты от программ чтения экрана, текст рядом
  остаётся доступным.

## Все разделы

Обзор и реестр, Ops, Research, QA/CI, AI Agent, AI Limits/Codex, Operator Inbox,
редакция YFC, Hermes Commander, аналитика Codex, VPS и квоты. Экран входа уже
использует Orbit 3.0. Архив Desktop Commander сохранён отдельной read-only
страницей, но цвета/шрифты/знак/иконки согласованы.

Внешние наблюдатели не переписываются на React без необходимости: их действующие
контракты и маршруты остаются прежними. Не включать выполнение команд, Git
модификации, Windows bridge, новые секреты или автоматическую публикацию.

## Проверка и выпуск

- npm check/test/build; совпадение собранного Vite и tracked web assets.
- Playwright, включая orbit-design-system.spec.js, на синтетических данных:
  320/393/768/1440, клавиатура, активный пункт, иконки, названия, overflow,
  ошибки JS и отсутствие запросов к внешним провайдерам.
- Полный CI exact-head; PR/review/merge только при зелёных проверках.
- Доставка exact-main-SHA действующим workflow; фиксировать receipt.
- Synthetic PASS не является проверкой реальных OAuth, релеи или Windows.
