# Hermes Control Center - React/Vite frontend

Owner visual target (2026-10-16): graphite/royal-blue operator console C+A, alternative C+B Atlas, and premium winged-H GitHub login page. The current OAuth start screen is explicitly a **preview**, not authentication.

## Development

```sh
npm ci --ignore-scripts
npm run test
npm run build
```

Use `npm run dev` to start Vite. The real backend remains the existing loopback Python server `control_center/server.py` with `/api/overview`. During isolated Vite development, the frontend will display an honest error until an allowed test or live API is supplied. Do not invent telemetry.

`vite.config.js` builds deterministic `../web/index.html`, `../web/app.js`, `../web/style.css` and local brand assets. This design deliberately uses **no Node.js runtime on the VPS**. The Python web server has an exact static allowlist and keeps no-write semantics.

The controls for theme selection, service searching/filtering, refresh and navigation are client-side only. The right-hand status list only reports snapshot-derived facts and labels unsupported incident history as unavailable.

The login preview at `/?preview=login` displays a disabled OAuth button. It remains protected by Caddy Basic Auth. GitHub OAuth #180 must be implemented separately with its own numeric owner ID checks and failure tests before public authentication can change. Resident Agent remains P0 NO-GO (#33).

No deploy or replacement of Basic Auth is part of this work until separate security and visual acceptance.
