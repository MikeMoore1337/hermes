# Hermes Control Center - React/Vite frontend

Owner visual target (2026-10-16): C+B Atlas as the only main dashboard layout, using C+A sans-serif typography, and premium winged-H GitHub login page. The current OAuth start screen is explicitly a **preview**, not authentication.

Для разработки и проверки новых экранов используйте [протокол UI evidence](../../docs/ux/control-center-ui-evidence.md) и тест `qa/visual-evidence.spec.js`: он покрывает отрисованные состояния на синтетике, не требует production OAuth и не подменяет реальную проверку владельцем.

Для отдельной воспроизводимой галереи откройте Actions - 
**Hermes UI Visual Evidence (manual, synthetic)** - Run workflow.
Отчёт и PNG появятся в архиве `hermes-h440-synthetic-ui-evidence`
(7 дней, synthetic-only, без OAuth и реальных данных).
См. [протокол и границы](../../docs/ux/control-center-ui-evidence.md).
Это необязательная проверка и не выпуск нового дизайна.

## Development

```sh
npm ci --ignore-scripts
npm run test
npm run build
```

Use `npm run dev` to start Vite. The real backend remains the existing loopback Python server `control_center/server.py` with `/api/overview`. During isolated Vite development, the frontend will display an honest error until an allowed test or live API is supplied. Do not invent telemetry.

`vite.config.js` builds deterministic `../web/index.html`, `../web/app.js`, `../web/style.css` and local brand assets. This design deliberately uses **no Node.js runtime on the VPS**. The Python web server has an exact static allowlist and keeps no-write semantics.

The controls for service searching/filtering, refresh and navigation are client-side only. The right-hand status list only reports snapshot-derived facts and labels unsupported incident history as unavailable.

The login preview at `/?preview=login` displays a disabled OAuth button. It remains protected by Caddy Basic Auth. GitHub OAuth #180 must be implemented separately with its own numeric owner ID checks and failure tests before public authentication can change. Resident Agent remains P0 NO-GO (#33).

No deploy or replacement of Basic Auth is part of this work until separate security and visual acceptance.

## Approved HD branding (2026-10-17)

The login and header use a local transparent high-resolution `brand.webp` (1096 × 595 RGBA WebP). Opaque background rectangles and screen blending are disallowed. The PWA uses 192/512 PNG icons, maskable 192/512 PNG icons with safe padding, the Apple touch icon and favicon. Public assets must match `control_center/web/` after Vite build. No external asset/CDN requests. The OAuth, service worker, read-only API and sandbox security boundaries are unchanged.
