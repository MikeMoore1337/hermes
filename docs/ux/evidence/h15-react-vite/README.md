# Hermes Control Center - approved UI browser evidence

**Branch:** `feat/h15-react-vite-operator-20261016`
**Owner decision (2026-10-16):** C+B layout/navigation/composition with C+A sans-serif fonts; other visuals approved.

All screenshots below were rendered in Chromium with **Playwright fixture data**, not genuine VPS metrics. The real app requests `GET /api/overview` and rejects stale/malformed data.

| Approved view | Screenshot |
|---|---|
| C+B Atlas + C+A fonts (1440px) | [atlas-desktop.jpg](atlas-desktop.jpg) |
| C+B Atlas + C+A fonts (393px) | [atlas-mobile.jpg](atlas-mobile.jpg) |
| Branded GitHub sign-in visual preview (1440px) | [login-desktop.jpg](login-desktop.jpg) |
| Branded GitHub sign-in visual preview (393px) | [login-mobile.jpg](login-mobile.jpg) |

## Verified

- Approved Atlas is the single primary dashboard layout; no competing C+A console UI toggle.
- Fonts across Atlas headings, metrics, navigation, cards and login are professional sans-serif (C+A typography).
- Browser checks 1440px, 768px, 393px, 320px, no document-wide horizontal overflow. Service states including agent NO-GO remain readable.
- Data is derived from the sanitized systemd snapshot, not mock historical incidents.
- Group navigation, filtering, search and manual refresh work in the browser.
- Login screen is preview only and its GitHub button is **disabled**. OAuth integration is a separate security task #180.
- No Node runtime, CDN or additional privilege on VPS. Existing Basic Auth remains the security boundary.

## Reproduction

```sh
cd control_center/frontend
npm ci --ignore-scripts
npm run check
npm run test
npm run build
npx playwright install chromium
npm run test:e2e
cd ../..
python3 -m unittest tests.test_control_center tests.test_control_center_assets -v
python3 scripts/validate_repo.py
```

Current local checks: Node 3/3, Python 13/13, Chromium E2E 7/7, production npm audit zero findings.
