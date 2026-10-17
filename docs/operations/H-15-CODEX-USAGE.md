# Codex Usage Monitor - Hermes Issue #255

The module adds a read-only Codex quota collector, an authenticated GET
/api/providers/codex and a responsive widget in the existing Atlas Control Center.
The existing collector has been separately authorized and activated on the Hermes VPS.
That historical production check is recorded in Issue #255 (2026-10-17); a new
runtime verification is required after any subsequent deployment. This module
never activates a resident AI agent.

## Source and boundaries

The collector starts official Codex CLI app-server over local JSONL stdio and calls only
initialize, initialized, account/rateLimits/read. No inference, account rotation or
reset-credit consumption is part of this module.
ChatGPT account login is required; an OpenAI API key does not represent subscription quotas.
Codex subscription quota differs from Cloudflare Workers Free and paid API billing.

An atomic sanitized snapshot contains only window duration, remaining/used percentages,
reset timestamps and status. No emails, account identifiers, raw response bodies or tokens.
The GET endpoint uses the existing Control Center authentication and has no write operation.
It returns not_configured when there is no source; stale after more than 10 minutes.

## VPS activation (historical state, 2026-10-17)

The owner approved and completed official Codex CLI device authentication on
VPS vps1777112993. The existing five-minute timer was installed and a live
multi-window exhausted snapshot was confirmed, as documented in Issue #255.
This is **not** a fresh deployment or validation of the changes in this PR.
Do not replace credentials or modify the resident H-01 agent for this feature.

1. Pin an official Codex CLI release; verify actual app-server support on the VPS.
2. Create a hermes-codex system user with primary group hermes-control.
3. Provision /var/lib/hermes-codex-usage (owner hermes-codex, group hermes-control,
   mode 0750). Create auth/ under it with owner hermes-codex and mode 0700.
   The Control Center web service must not be able to read the auth directory.
4. Using exactly that OS identity and CODEX_HOME=/var/lib/hermes-codex-usage/auth,
   complete the official codex login --device-auth owner flow.
5. Test the actual subscription quota, re-authorization, 401/429/network failures
   and expiry. Keep original raw tokens off the web, logs, GitHub, YFC and Second Brain.
6. After approval, install the two new units and enable the timer. It runs a short
   one-shot probe roughly every five minutes and writes usage.json mode 0640.
7. For rollback, preserve the last known-good release and the existing collector
   data. Do not change the existing restricted network rules of
   hermes-control-center.service. Disabling the timer stops new observations.

When monitoring fails, no prior quota is interpreted as usable. Do not infer that
quota has been restored merely because the reset clock time passed.

## Tests and review

Run python3 -m unittest tests.test_codex_usage tests.test_control_center -v.
In control_center/frontend run npm ci --ignore-scripts, npm test, npm run build,
and npm run test:e2e. Screenshot evidence in docs/ux/evidence/h15-codex-usage
is fixture-based and awaits review before production UI changes.

## H-15 V2 backend (Issue #255)

The existing five-minute `control_center.codex_usage` collector now also writes
`/var/lib/hermes-codex-usage/history.sqlite3`, with no second probe/service.
The SQLite database is owned by the isolated collector identity, file mode
0640, and is read by the existing Control Center under the shared group.
Only normalized quota windows, status and UTC observation timestamps are stored.
Unexpected fields (including tokens and email) are excluded; error snapshots
do not erase earlier successful observations. Consecutive unchanged observations
are deduplicated within 30 minutes while an anchor sample is kept for charts.
Retention is 30 days with a 2,200-sample / 500-transition upper bound.
A clock rollback cannot overwrite existing chronological history.

Three owner-only, read-only endpoints exist:
- `GET /api/providers/codex` - unchanged live/stale snapshot;
- `GET /api/providers/codex/history` - up to 500 sanitized observations in
  the preceding seven days, 50 transitions and last successful observation;
- `GET /api/providers/codex/policy` - the fail-closed, current admission decision.

All use the existing GitHub OAuth gate (and Caddy auth in proxy mode),
`Cache-Control: no-store`, fixed response schemas and no write API. A
missing history returns an empty history. A corrupt history returns 503;
an invalid snapshot returns `UNKNOWN` from the policy endpoint.

`control_center.codex_policy.decision(snapshot, now, threshold_percent)`
evaluates all reported windows; its configurable integer threshold is 0-50%
(default 20%). Its outcomes are:
- `ALLOW`: fresh, `ordinary_usage_allowed=True`, all windows present,
  each remaining above threshold, no explicit provider denial.
- `DEFER`: confirmed quota exhaustion, explicit provider denial or a
  configured low-quota stop threshold.
- `UNKNOWN`: invalid/missing/stale data, missing ordinary allowance,
  authentication/network failure or incomplete windows.

The policy does NOT infer recovery from `resets_at`. `may_dispatch` also
requires independent task authorization. Callers must re-check policy and
task rights immediately before starting a **new** Codex job. Do not terminate
running jobs based only on a later quota change.

**Not yet wired:** the project has no general Codex task queue. No arbitrary
jobs are created, queued or resumed. The existing H-01 bounded operations
timer remains independent; connecting its dispatch or a future scheduler
requires a narrowly defined owner-approved integration. The existing Ops Watch
outbox accepts only its predefined incident catalog, so this PR does not
activate new Telegram alerts or change existing incident delivery rules.
The React quota history chart, local threshold control and new notification
types likewise still require their own UI review and runtime integration.
Treat these as open acceptance requirements, not completed production features.

This feature never buys API tokens, spends reset credits, rotates accounts,
uses Cloudflare Workers quota as Codex allowance or calls inference.

## V2 verification

Run `python3 -m unittest tests.test_codex_usage
tests.test_codex_policy_history tests.test_control_center -v`.
Quality and Control Center UI CI run these deterministic tests on PR HEAD.
Live timer, database permissions, OAuth boundaries and UI must be separately
validated in production after an authorized exact-SHA deployment.

