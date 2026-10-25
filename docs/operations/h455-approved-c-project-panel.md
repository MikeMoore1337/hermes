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

## Owner production visual acceptance and final migration

On 2026-10-25 owner explicitly **accepted** deployed Concept C after
the production release of #589. This is the visual gate for switching
the primary Hermes Commander main/top navigation to the existing protected
`/hermes-brc` page. Do not replace its backend, add remote execution
or extend original Windows access.

Main Control Center no longer loads the old `desktop-commander.js`
floating widget. It remains physically in source and production assets for
emergency UI rollback, but does not poll or render on normal operator pages.
Historic third-party telemetry is accessed explicitly through
`/desktop-commander-archive` (owner-authenticated, no-store HTML), which
reads only the old allowlisted `/api/providers/desktop-commander/history`
endpoint with bounded 1,7,30-day filters, and never calls the live cloud
Desktop Commander API. No automatic archive refresh is scheduled by this UI.

The accepted C page links to the optional archive; original native Windows
read-only remains offline/paused. Preserve independent existing scheduler
state, infrastructure data, authentication, and history database. The
historical backend collector is not removed or restarted as part of this
UI-only migration; any later retirement of that service needs explicit
separate operational verification.

CI gates: exact built `web` assets, repo Python API/owner 401/security
tests, Playwright primary-navigation/archival A11y at 320/393/768/1440,
legacy quiet on main page, offline history and malformed data fail-closed.
Final production gate: release receipt pinned to main SHA, owner 200 UI
after OAuth, main navigation -> C; archives show only historic records and
no new command/tool permissions. Keep prior Control Center symlink release
for rollback.


## Validated source check (follow-up to #591)

The new owner-only GET `/api/providers/hermes-brc/source-check` (also via the
existing `/control-center/api` prefix) revalidates the **same already
sanitized local snapshot** when the operator selects **Проверить источник**.
The response includes only the source validation time, a bounded age, three
canonical display names/statuses and explicit `not_probed` flags for relay,
OAuth, tools and Git. This is an idempotent read-only filesystem operation;
there is no remote MCP ping, command dispatch, new background job, collector,
mount, device enrollment, reconnect or request-supplied path. The result is
not a tool-execution proof and does not alter the old snapshot contract.

Security gates: same GitHub owner session (guest 401), exact Host and query
validation, no-store, sanitizer/TTL/schema failures 503, source symlink denial,
no IDs/bearer/session/host secrets, no client-controlled paths, no HTTP POST.
The `Проверить инструменты` command button remains disabled. The endpoint
is bounded by the existing 16 KiB sanitized snapshot and is suitable only
for confirming the quality of the observation currently displayed.

This is a scoped, incremental step toward #455, **not complete onboarding**.
Actual tool checks, grant/deny/revoke, reconnection and new-device enrollment
must be implemented against a separately authorized allowlisted device
executor with OS-level isolation; never infer such permissions from ONLINE.
Owner browser post-migration acceptance is still separately required.


## Guided client-side tool check (safe fallback)

For owners with an already connected Hermes Agent MCP in ChatGPT or Codex,
Concept C now offers **Скопировать запрос проверки** for the selected
canonical sandbox project. The button only copies a fixed, human-readable
read-only request into the clipboard. It asks the existing authorized client to
resolve the project with \`list_devices\`, \`list_workspaces\` and
\`resolve_workspace\`, then use \`list_directory\` and \`get_file_info\`
inside the three already approved sandbox workspaces. It neither transmits the
request to the Hermes Control Center server nor sends it to an MCP provider.

The generated request never contains bearer tokens, device IDs or guessed
host paths, and explicitly disallows native Windows and private vault access,
file modification, new permissions and shell process execution. A failed
clipboard permission reports an error; it never claims that a tool check
happened. The existing snapshot and source-check endpoints remain unchanged.

This improves reproducible owner-driven diagnostics while a separate
audited and explicitly approved server-to-relay identity is not yet present.
**Not a browser-executed tool check:** results must be independently checked
in the authenticated ChatGPT/Codex MCP client; the Control Center continues
to mark command execution and Git as NOT_VERIFIED. New device/project
enrollment, grant/revoke and automatic recovery remain outside this change.
