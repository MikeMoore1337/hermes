# Hermes Aero - утверждённая символика

**Владелец утвердил вариант A - Aero (02.11.2026).** Внедрение фирменной символики осуществляется отдельно от функционального редизайна [#695](https://github.com/MikeMoore1337/hermes/issues/695).

## Источники

- `control_center/frontend/public/orbit-brand.svg` - компактный крылатый знак для интерфейса, JSX и статических разделов.
- `control_center/frontend/public/favicon.svg` - упрощённая версия для вкладок 16/32 px.
- `control_center/frontend/public/pwa-orbit.svg` - стандартная PWA-иконка (тёмный фон и крылатая H).
- `assets/branding/hermes-aero-maskable.svg` - векторная основа PWA maskable с безопасными полями.
- `assets/branding/hermes-aero-wide.svg` - прозрачная широкая H для растрового `brand.webp` (1096 x 595).
- `assets/branding/hermes-aero-horizontal.svg` - дополнительная прозрачная горизонтальная подпись для печатных/маркетинговых материалов. Не подключена как маршрут.

## Публикуемые растровые файлы

Структура и существующие URL сохранены: `favicon.png` (32), `apple-touch-icon.png` (180), `pwa-192.png`, `pwa-512.png`, `pwa-maskable-192.png`, `pwa-maskable-512.png`, `brand.webp`.

Совпадающие PNG/WebP должны попадать и в `control_center/frontend/public/`, и в генерируемый каталог `control_center/web/` через штатную Vite-сборку. Не меняем OAuth, запросы к API, ограниченный service worker, кэш авторизованного содержимого и существующий JSON manifest. Не нужны платные API, новые шрифты/CDN или Node.js на VPS.

## Проверка

- `python -m unittest discover -s tests -p test_control_center_aero_assets.py`
- `cd control_center/frontend && npm ci --ignore-scripts && npm run test && npm run build`
- Обновить снимки/проверить реальный рендер на ширинах 320/393/768/1440/1920 и установку PWA на устройствах, доступных исполнителю.

Изменение состоит только в согласованном брендинге. Ни данные, ни разрешения Hermes не меняются.
