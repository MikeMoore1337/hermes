# Hermes Control Center: выборочный shadcn/ui + Magic UI - решение #606

**Решение: REUSE_EXISTING.** Обоснование по текущим исходникам Control Center, не заявление о проведённом human/browser просмотре production. Пользователь утвердил дизайн C+B Atlas с графитово-синей палитрой и Lucide. Нет разрешения менять макет, а Hermes Commander/BRC разрабатывается отдельно.

## Матрица

| Возможность внешней библиотеки | Проверка текущих исходников | Действие |
| --- | --- | --- |
| shadcn/ui Button | `control_center/frontend/src/main.jsx`: нативные `button`, `type=button`, `disabled`; `style.css`: явный `:focus-visible`, целевые размеры и токены | **REUSE_EXISTING**, не вводить Radix/Tailwind |
| shadcn/ui Select | Нативный `select` со связанным текстом в `<label>`, визуально встроен в `status-filter` и используется через React `value`/`onChange` | **REUSE_EXISTING**: полноценная keyboard/AT поддержка браузера без JS combobox |
| shadcn/ui Navigation | Навигация `<nav aria-label>`, интерактивные элементы имеют `aria-current=page` | **REUSE_EXISTING**: не подменять собственный BRC/панель сторонним роутером/поповером |
| Magic UI MagicCard | Существующие `stat-tile`, `registry-panel` используют контролируемые CSS gradients/solid fallback и заданные токены без motion JavaScript | **REUSE_EXISTING**: MagicCard + motion добавит duplicate animated style, не повысив информационную ценность |
| Magic UI animated indicators | `refresh-button` + `.spin` + `@media(prefers-reduced-motion:reduce)` уже дают осмысленное изменение с подавлением движения | **REUSE_EXISTING**, сохраняем reduced-motion |

## Ограничения и последствия

- Текущий `control_center/frontend/package.json`: React 19, Vite 7, Lucide; нет Tailwind/Radix/Base UI/Motion. Универсальный импорт shadcn или Magic UI вызовет непрошенный дополнительный toolchain/runtime CSS, JS или визуальные отклонения.
- Никаких новых зависимостей, скопированных внешних исходников или сторонних ассетов. Upstream лицензия и права проверяются отдельно по каждому конкретному компоненту, не распространять общую лицензию репозитория на несвязанные пакеты.
- Изменений в верстке, авторизации, роутинге, цветовом контракте, Basic Auth, OAuth, PWA, BRC или VPS-сервисах **нет**. Поэтому новая Dark/Light галерея не требуется для *этого* PR: фактический UI не меняется. При будущем изменении - 320/393/desktop и Dark/Light реальные synthetic screenshots плюс **отдельный owner visual approval** до внедрения.
- В scope дополнительно добавлен offline contract test существующего HTML/CSS: native buttons, labeled select, `aria-current`, keyboard focus, reduced-motion. PASS структурного теста - **не** доказательство всей доступности браузера и не результат runtime-применения upstream.
- Если появится подтверждённый дефект конкретного экрана, новая задача должна описать route/state/baseline SHA, поведение клавиатуры, снимки, бюджет bundle/performance, сравнить CSS-first с одной отдельной внешней зависимостью и предложить макет на утверждение. Общая фраза «внедрить Magic UI» не даёт обоснования для изменения дизайна.

## Итог

Актуальная функциональная потребность покрыта существующими компонентами. Полный UI-framework не форкаем; это предотвращает усложнение Control Center и неожиданный deploy. Статус `REUSE_EXISTING` - подтверждённое чтением исходников решение, не абсолютное утверждение, что у продукта нет дефектов.
