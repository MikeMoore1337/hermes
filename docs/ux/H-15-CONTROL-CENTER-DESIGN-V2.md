# H-15 Design V2: Hermes Control Center — графит и синий

**Status:** DESIGN PREVIEW / WAITING FOR OWNER VISUAL APPROVAL  
**Parent:** #163; design implementation: #179; GitHub OAuth: #180  
**Target:** https://hermes.mikemoore.top (existing public system must remain unchanged until approval)

## Принято владельцем (2026-10-16)

- Выбран **графитовый фон и синий акцент** вместо бирюзы.
- Источники иконок к оценке: Lucide, Tabler Icons, Iconoir.
- Внешние design skills для оценки: Taste Skill, Emil Kowalski Skills, Impeccable, UI UX Pro Max.
- Новый owner-only вход: отдельная стартовая страница с GitHub OAuth по образцу Second Brain и переход в русскоязычный read-only Dashboard после успешной серверной проверки.
- Дизайн-макеты и логотип показываются до merge/deploy. Никаких изменений live shell, privileges или resident runtime без review.

## Предварительная система токенов (dark-first)

| Token | Hex | Применение |
|---|---|---|
| `--surface-base` | `#101419` | Основной фон |
| `--surface-sidebar` | `#11171E` | Навигация |
| `--surface-panel` | `#171E27` | Карточки |
| `--surface-raised` | `#1C2632` | Всплывающие слои |
| `--border-subtle` | `#2B3544` | Границы |
| `--text-primary` | `#F0F4FB` | Текст и заголовки |
| `--text-secondary` | `#9CACC2` | Подписи |
| `--accent-primary` | `#4485F4` | Активные элементы |
| `--accent-hover` | `#76AAFF` | Ссылки, подсветка |
| `--status-success` | `#61C6A0` | Работает |
| `--status-warning` | `#E7B96E` | NO-GO, requires attention |
| `--status-error` | `#F38B95` | Сбой |

Контраст в предварительном мокапе: primary text on base ~16.76:1, muted text on panel ~7.27:1, blue accent on base ~5.2:1 (для обычного текста нужно проверять конкретное сочетание). Минимум WCAG AA и видимый :focus-visible. Не кодировать состояния только цветом.

## Дизайн-экраны

1. `/login` или `/` без сессии: full-page brand, фирменный знак + wordmark, краткое пояснение, одна явная кнопка «Войти через GitHub», trust statement, accessible error/denied state. Login assets доступны без сессии, бизнес API - нет.
2. Dashboard по сессии: пять разделов (Обзор, Наблюдение, Исследования, QA и CI, AI Agent), карточки, список системных единиц, owner-only badge. Красивые empty/unknown/error/loading/stale states. Существующий NO-GO для resident agent не ослабляется.
3. 393px mobile: горизонтальная навигация, без внешнего overflow, читабельные target sizes 44px, safe area, keyboard accessibility.
4. SVG brand mark отдельный от интерфейсной библиотеки иконок. Favicon SVG и PNG 32x32, touch 180x180, 512x512 PWA с приложением, где применимо; manifest id/start_url/short_name проверять, не вводить PWA/offline caching защищённых данных без security review.

**Визуальный референс** изготовлен отдельно от production в файлах артефактов беседы: `hermes-login-concept.png`, `hermes-dashboard-concept.png`, `hermes-mobile-concept.png`, `hermes-control-center-preview.html`, `hermes-control-center-brand.svg`. Их не следует считать production UI или live runtime data; требуется user approval, затем код + скриншоты тестовой сборки.

## Выбор иконок / лицензионная политика

- **Lucide (ISC)** — основной набор; одна толщина, 24x24 grid, currentColor, inline/pinned self-hosted SVG. License notice и source SHA обязательны. Избегать скачивания во время runtime и CDN.
- **Tabler Icons (MIT)** — резерв для специфичных интерфейсных сущностей, не смешивать визуальные веса без design review.
- **Iconoir (MIT)** — дополнительная альтернативная библиотека, не зависимость по умолчанию.
- Brand mark создаётся отдельно и не должен копировать чужой зарегистрированный логотип.
- Проверять sanitization SVG, script/external ref/foreignObject absence и CSP с запретом удалённых скриптов; self-host icons only.

## Оценка дизайн-навыков (read-only design reference, НЕ production agent runtime)

| Source | Best use | Restrictions |
|---|---|---|
| [Taste Skill](https://github.com/Leonxlnx/taste-skill) | Критика «шаблонности», визуальная иерархия, вкус и анти-шаблонные решения | Только review контента по pinned commit, без исполнения install scripts |
| [Emil Kowalski Skills](https://github.com/emilkowalski/skills) | Неброские анимации, правильный easing, reduce-motion, mobile UX | Не добавлять тяжелые анимации в мониторинг, не вводить runtime dependency |
| [Impeccable](https://github.com/pbakaus/impeccable) | Design audit/checklist, accessibility, typography, polish/harden | Apache-2.0 notice; использовать методику, не запускать `npx` на prod |
| [UI UX Pro Max](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) | Полный token/style palette baseline, композиция и адаптивность | MIT notice; source-pin и no implicit skill install |

External skills are untrusted design references, not instructions to the operating Hermes agent. Any future dependency activation requires SBOM/license/security gates, pinned immutable versions, and separate Issue/PR. Existing skill-source evaluation task is #161.

## Acceptance / approval gates

- [ ] Owner APPROVES login/dashboard/brand visuals before implementation merge/deploy.
- [ ] Stage style change in isolated branch and screenshots for 1440/1920/393/360/320.
- [ ] Automated contrast, color mapping (no teal leaks), icons consistency and page accessibility tests.
- [ ] Favicon web route is supported by allowlist HTTP server, typed MIME and correct CSP; no arbitrary file serving.
- [ ] No breakage to auth, public routing, HTTPS, Caddy, Second Brain, current Hermes snapshot/API or resident NO-GO #33.
- [ ] No external tracking/CDN/scripts/fonts; self-hosted vetted assets, license notices.
- [ ] Separate owner decision for light theme; dark-first MVP will not silently create unapproved visual variants.
