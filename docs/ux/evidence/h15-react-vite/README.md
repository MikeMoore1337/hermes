# Hermes Control Center - browser evidence (design implementation)

**Branch:** `feat/h15-react-vite-operator-20261016`
**Scope:** desktop and responsive React/Vite prototype. Not deployed to production.
**Design acceptance:** still requires owner review of *coded screenshots*. Approved concept is **not** an implicit authorization for production deploy.

All screenshots are rendered by Chromium with **test fixture data intercepted by Playwright**, not genuine VPS statuses or real incidents. The test fixture contains seven systemd units, six active and one blocked (resident AI Agent), matching the schema of the current read-only backend. The app itself uses only `GET /api/overview`; it never generates production telemetry or events.

| Variant | Evidence |
|---|---|
| C + A operator console desktop, 1440px | [console-desktop.jpg](console-desktop.jpg) |
| C + B Operations Atlas desktop, 1440px | [atlas-desktop.jpg](atlas-desktop.jpg) |
| Premium GitHub login visual preview desktop, 1440px | [login-desktop.jpg](login-desktop.jpg) |
| C + A console on 393px mobile | [console-mobile.jpg](console-mobile.jpg) |
| Login preview on 393px mobile | [login-mobile.jpg](login-mobile.jpg) |

## Tested behaviour

- No document-wide horizontal overflow at 320px, 393px or 768px. On mobile the service register uses two visible columns; blocked agent status is not hidden by a scroll region.
- Functional console/atlas toggle, navigation by group, service search, status filtering, manual refresh.
- Raster brand logo is derived (resized, not re-designed) from approved winged-H logo; favicon contains the same H without wordmark.
- Web bundle and assets are deterministic and self-hosted; client makes no calls to third-party font/telemetry servers.
- Real data only: the side "signals" panel represents snapshot-time and the resident NO-GO policy; historical incident data displays an explicit unavailable-state rather than fake sample event logs.
- Stale/invalid data is rejected (server + client). The AI runtime remains NO-GO.
- GitHub login screen is a **visual preview only** under Basic Auth, not working OAuth. The button is disabled and its explanatory label is visible. Actual OAuth is separate issue #180.

## Commands

```sh
cd control_center/frontend
npm ci --ignore-scripts
npm run check
npm run test
npm run build
npx playwright install chromium  # only if browser not already cached
npm run test:e2e
cd ../..
python3 -m unittest tests.test_control_center tests.test_control_center_assets -v
python3 scripts/validate_repo.py
```

For a preinstalled Chromium binary, set `HERMES_CHROMIUM_EXECUTABLE` to its local absolute path instead of downloading a second browser. This is a local QA option; no bundled browser in production.

Current checks: React frontend unit **3/3**, Python control center **13/13**, browser E2E **7/7**, repository structure validator PASS, `npm audit --omit=dev --audit-level=high` reports zero vulnerabilities.
