# Hermes #455 — Approved C project-first UI delivery

Owner selected **Concept C: Рабочие пространства**, 2026-10-25,
after three low-fidelity wireframes and desktop/mobile static review.

## Deployment and security boundary

- React Control Center / and its legacy Desktop Commander floating widget
  stay available. New concept C is a separate, reversible browser entry:
  `GET /hermes-brc`, linked from authenticated legacy widget.
- The page is served through existing `control_center.server` ASSETS
  allowlist; GitHub OAuth must authenticate before the HTML is served.
  On `mode=proxy`, rely on the existing external Caddy perimeter
  as for the main UI. No new endpoint or service is activated.
- The page loads two local static files (CSP script/style self) included
  in both `frontend/public` and reproducibly built `web`.
- Only `GET /api/providers/hermes-brc` is called (same-origin session,
  no-store; 8s AbortController timeout, refresh on visibility and at 60s
  when visible). No browser-side MCP, OS operations, secrets, tokens,
  device selection, arbitrary paths or privileged new onboarding.
- Validate exact sanitized schema, source, age <= 300s, <=60s
  future tolerance, three canonical sandbox devices, four canonical
  repository roots/branches, flags `false`, command execution
  `not_verified`, Git `git_verified=false`; otherwise hide all
  claimed availability and visibly mark unknown.
- The project selector is UI-only; clipboard copies only fixed canonical
  `/workspace/projects/*` sandbox roots. Disabled `Проверить инструменты`
  cannot trigger a backend action. Native original Windows remains closed.

## Visual QA and release gates

- Desktop 1440 and 768 px; mobile 390 and 320 px; reduced motion, no
  document-level horizontal overflow, focus-visible, distinct selected
  state, no secret-bearing output or synthetic-online fallback.
- Python HTTP contract test for owner page, guest HTTP 401,
  no-store/CSP, strict query, bounded static files.
- Playwright synthetic API tests cover four-project switching,
  original Windows path exclusion, 503, forged capabilities, expired
  observations, keyboard/button states and screenshots.
- GitHub Flow PR -> exact SHA required CI -> merge -> approved source
  deploy. Production owner with existing GitHub OAuth verifies UI
  in browser and compares it to accepted PNG/HTML visual target.
  **Do not remove /desktop-commander legacy from main page before
  that owner production visual gate.** Keep legacy for rollback.

## Subsequent migration

When owner confirms C visuals and live content on the new route,
switch the main nav entry to C and leave legacy Desktop Commander as
read-only archive/history with explicit label. Follow normal CSS/a11y
and rollback QA; #455 is not closed by this additive delivery alone.
