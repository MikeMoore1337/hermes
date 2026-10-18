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


## Stage 2 - genuine API-supported usage probes, opt-in only (not activated)

On 3 August 2026 Cloudflare announced an **official Billable Usage API**
covering Workers AI. Unlike previous assumptions, this is a viable **historical
account-wide source**, but the data is updated daily, so it cannot give
live quota remaining and must NEVER be fed into a real-time admission gate.

References:
- https://blog.cloudflare.com/billable-usage-api/ (2026-08-03)
- https://developers.cloudflare.com/api/resources/billing/subresources/usage/methods/get_account_usage_v1/
- https://developers.cloudflare.com/workers-ai/platform/pricing/
- https://developers.cloudflare.com/workers-ai/platform/errors/

The optional read-only collector `control_center/cloudflare_billing.py`
performs only GET `/client/v4/accounts/{ID}/billable-usage` once daily.
It accepts **only** unambiguous Workers AI billing rows whose
`ConsumedUnit` is Neurons and a complete previous UTC day is specified.
Any ambiguity, unsupported unit, authorization failure, 429 or malformed
response fails closed as unknown or auth_required. The raw HTTP response,
account ID, other products, token and costs never reach local snapshots or
the Control Center API. The UI shows such observations only as
**official delayed historical consumption**, while today's
`used` and `remaining` always remain null. A successful billing sample
is not a real-time 10k/day guarantee.

The `GET /rate_limit` GitHub REST API provides independently scoped,
token-specific bucket limits (`core`, `search`, `graphql`, etc.).
`control_center/github_rate_limit.py` reads only that fixed endpoint;
does not enumerate repositories or user data and refuses insecure credentials.
It makes **no claim of account-wide API/CI budget**. A zero-limit resource
means disabled/unknown, not available. The token is distinct from
GitHub Actions and the owner's ChatGPT/GitHub OAuth integration.

Both collectors are **opt-in**, pinned to one host and disabled in the
normal release. The new unit/timer files are intentionally not installed or
enabled by `deploy/hermes-main-deploy.sh`. For Cloudflare, an operator
must create a narrowly scoped API token with **Account Billing Read**
and root-owned 0600 files:
- `/etc/hermes/cloudflare-billing-read.token` - token alone, no quotes;
- `/etc/hermes/cloudflare-billing-read.env` - a single line
  `CLOUDFLARE_BILLING_ACCOUNT_ID=<verified-32-hex-id>`.

On a separately authorized Hermes VPS root console (not GitHub CI):
```bash
install -o root -g root -m 0644 deploy/hermes-cloudflare-billing-read.service /etc/systemd/system/
install -o root -g root -m 0644 deploy/hermes-cloudflare-billing-read.timer /etc/systemd/system/
systemctl daemon-reload
systemctl start hermes-cloudflare-billing-read.service
systemctl show hermes-cloudflare-billing-read.service -p Result -p ExecMainStatus
# Only enable after a reviewed success, real daily sample and owner proof.
systemctl enable --now hermes-cloudflare-billing-read.timer
```

For GitHub, create a **separate** root-owned 0600 token file at
`/etc/hermes/github-rate-limit-read.token` with a token whose quota is
meaningful for Hermes; install the two
`deploy/hermes-github-rate-limit.{service,timer}` units and run one
authenticated smoke before enabling its 10-minute timer. GitHub API rate
limits for other tokens and Cloudflare requests outside Hermes remain unknown.

These opt-in external probes run as isolated one-shot systemd services with
bounded timeouts and memory/CPU quotas. They do not modify existing
Codex subscription usage #255/#272, Desktop Commander #275, runtime #33 or
Cloudflare Free-only enforcement #62. Revoke credentials and disable
both timers to roll back external sampling without touching the UI.

CI covers HTTP 401/403/429/500, permission rejection, invalid unit/period,
complete-vs-current day, current snapshot age, independently scoped GitHub
reset/remaining, and secret redaction. **No live Cloudflare/GitHub
collector has been activated or authorized by normal release.**


## Stage 3 - actual quota-warning pipeline

The existing Ops Watch collector reads the **same validated local snapshots**
and emits fixed, service-separated warnings using the already installed
transactional SQLite outbox and Telegram sender. No new external model call
or HTTP query occurs in Ops Watch. The production entrypoint explicitly
passes provider paths; offline unit tests do not inherit live server files.

- For Desktop Commander Remote MCP and GitHub **configured token** only:
  80% / 95% usage of a documented provider window produces a warning;
  100% or explicit exhausted produces a critical incident. Each threshold
  uses a separate reviewed incident code.
- Stale and auth_required observations create a **distinct monitoring
  warning**, never a fabricated remaining quota.
- A previously confirmed threshold alarm cannot be automatically resolved
  by UNKNOWN, no connection, auth failure, or stale observation. Only a
  fresh authoritative lower-used reading proves recovery.
- GitHub independent window categories remain visible separately; a warning
  says *at least one* token resource is high, not "all GitHub calls blocked".
- Codex remains monitored through existing #255/#271 alerts so no duplicate
  notification is emitted by this new code. Cloudflare official billing is
  delayed; the historical Neurons result must **never** create real-time
  quota-exhausted signals or an ALLOW admission for H-01.

The code only describes the notification pipeline; delivery acceptance
requires a real Ops Watch event and an actual Telegram sender acknowledgment.
CI test proofs are synthetic, without simulated production alarm delivery.
