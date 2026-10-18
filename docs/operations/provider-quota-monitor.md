# H-15 #295 - Provider & Tool Quota Monitor

## Scope and inventory (October 2026)

This stage **reuses existing production readers**. All registered services have separate Atlas cards and a read-only `GET /api/providers/registry` behind current GitHub owner OAuth. Nothing queries an inference model or changes an account plan.

| Service | Evidence of Hermes use | Live account usage | Data source | Behavior without access |
| --- | --- | --- | --- | --- |
| Cloudflare Workers AI | H-01 Free-only runtime contract / ADR-0002 / #62 | **Unknown**: official account-wide billable Neurons not accessible by this integration | Documented 10,000 Neurons/day Free limit, reset 00:00 UTC | Show 10k **limit only**; used and remaining are `null`, no progress bar |
| Codex / ChatGPT | #255 existing independent `codex-app-server` reader | Provider-reported percentages for each independent limit/window, if fresh | Existing `/var/lib/hermes-codex-usage/usage.json` | Not connected / stale / auth_required, no invented reset |
| Desktop Commander Remote MCP | #275 independent `mcp-remote` collector | Provider-reported remaining percentage, if supported and fresh | Existing `/var/lib/hermes-desktop-commander/status.json` | `exhausted` blocks remote execution even if device online |
| GitHub API | Existing Hermes GitHub Issues / PR / CI/CD | **Unknown**: token/resource specific limits not collected by Control Center | Existing GitHub usage established by project; no new API token | Separate unknown card, no global account quota invented |

Documented Cloudflare sources:
- https://developers.cloudflare.com/workers-ai/platform/pricing/ : 10,000 neurons/day Free, daily UTC reset, over-quota fails
- https://developers.cloudflare.com/workers-ai/platform/limits/ : task/model rate ceilings are separate from daily Neurons
- https://developers.cloudflare.com/workers-ai/platform/errors/ : HTTP 429 / internal code 3036 signals daily allocation exhausted; 3040 signals out of capacity. Generic 429 **must not** be called quota exhaustion.

The Cloudflare UI is deliberately truthful: an official published Free allowance is **not** an observed personal account usage measurement. Requests from other clients may consume the account budget, so even future Hermes-local estimates cannot be called official remaining quota. No Cloudflare credential, GraphQL query or token scope is created in this stage.

## Contract

`GET /api/providers/registry` returns fixed allowlisted IDs, per-provider status, source kind, freshness, and per-window `quota_limit`, `used`, `remaining`, `used_percent`, `remaining_percent`, `reset_at_utc`. Absolute percentages from subscription windows are **not** translated into artificial request counts, token allowances or dollar values.

The endpoint is GET-only, owner-only in GitHub OAuth mode, and returns sanitized values only. It uses existing independent Codex/Desktop Commander snapshots, each already validated before use. Invalid snapshots result in an **unknown** card, without affecting other providers. `read_only=true` is not a promise that every listed provider is currently available.

Individual card history uses each existing source:
- Codex: `/api/providers/codex/history?days=1|7|30`; first available official quota window's remaining percent
- Desktop Commander: `/api/providers/desktop-commander/history?days=1|7|30`
- Cloudflare/GitHub: historical measurements unavailable; do not fabricate charts

Only first-party, separately collected provider data is used. Do not call ChatGPT connector account endpoints or obtain ChatGPT plugin OAuth bearer tokens for Hermes.

## Acceptance gates

1. Run `python3 -m unittest tests.test_provider_registry -v` plus existing Codex, Desktop Commander, OAuth and PWA tests.
2. Run `cd control_center/frontend && npm ci --ignore-scripts --no-fund --no-audit && npm run test:e2e && npm run build`. Review screenshot artifacts at 320, 393 and 1440 px; owner visual approval required before UI merge.
3. Confirm no network requests by the new quota registry; no paid provider upgrades or Workers AI inference; Cloudflare used/remaining JSON fields stay `null`.
4. Exact-SHA Quality CI, UI CI, merge and independently confirmed production deploy; read-only owner login and unauthorized 401 checks.
5. Keep #295 OPEN until an approved *official* Cloudflare usage source is verified, GitHub token-scoped header probes are implemented, combined histories/alerts complete, and a machine quota gate safely integrated with #271.

Rollback: restore the previous immutable Control Center release. Existing #255/#272/#275 independent collectors and quotas are unchanged.

## Not implemented here

Cloudflare official billable Neuron usage (currently unsupported/unverified), new GitHub token and rate-limit header collection, billing API support, provider-wide history for Cloudflare/GitHub, consolidated Ops Watch quota alert coverage and #271 admission. These require separate evidence and must not be inferred from an attractive UI.
