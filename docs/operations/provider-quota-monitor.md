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
Reported *billable* Neurons can omit usage covered by the free allocation;
therefore they are NOT a complete total of the Free daily budget.

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
requester/resource-scoped limits (`core`, `search`, `graphql`, etc.).
`control_center/github_rate_limit.py` reads only that fixed endpoint;
does not enumerate repositories or user data and refuses insecure credentials.
The authenticated-user primary limit can be **shared across user credentials**,\nnot isolated to one PAT; a GitHub App installation has different scope.\nIt makes **no claim of a single account-wide API/CI budget**. A zero-limit resource
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


## Stage 4 — concrete production read-back and external auth gate

A merge/CD receipt alone is not proof that all *real account metrics* are
available. The independently triggered
`.github/workflows/provider-boundary.yml` inspects only public HTTP
status codes after successful production CD:
`/healthz == 200`,
`/api/providers/registry == 401`, and
`/api/providers/registry/history?resource=core&days=7 == 401`
from an anonymous caller. No cookies, provider account data, API credentials
or redirect following are used. A job failure is **unverified**, not an
authorization to change OAuth/proxy settings or disable controls.

For a separate **owner-approved read-only VPS terminal**, run:

```bash
# On the Hermes VPS; only prints status metadata, not quotas or credentials.
active="$(readlink -f /opt/hermes-control-center/current)"
[[ "$active" =~ ^/opt/hermes-control-center/releases/main-[0-9a-f]{40}$ ]] || exit 1
sha="${active##*main-}"
cd "/opt/hermes-agent-owner/releases/main-$sha"
sudo -u hermes-control /usr/bin/python3 -m scripts.h15_provider_readback
```

The report has four fixed provider IDs, per-provider status, **number** of
fresh trusted windows and source-kind only; it excludes raw limits, observed
usage, account identifiers, filesystem paths, credentials and incident
payloads. `/healthz` must be 200 and a local request without owner session
to the quota registry must be 401. Exit code 0 means **local registry/auth
probe succeeded**; it does NOT mean Cloudflare and GitHub quota collectors
have been provisioned or their data verified. `UNKNOWN` is valid evidence
of an absent/unsupported source, not zero remaining.

The owner can separately sign in through the existing GitHub OAuth UI
and inspect the four cards (without copying OAuth cookies, response headers
or tokens to GitHub, terminal logs or chat). When real source credentials
are configured in root-owned `/etc/hermes` on the VPS through an authorized
owner console, perform **one bounded, read-only smoke per collector**,
confirm its sanitized snapshot is fresh and check the existing timer results
before enabling a recurring polling timer. Neither collector calls any
inference API.

The optional Cloudflare Billing API V1 can exclude usage covered by the Free
allowance. Cloudflare V2 explicitly includes Free usage but is **Alpha,
restricted-access**; it is not a production source until access and exact
schemas are independently confirmed. Do not infer today’s Free Neurons from
the current Billing V1 data. GitHub `403` can mean permission denial OR
primary/secondary throttling, so absent authoritative evidence it is
`unknown`, not a proved expired credential. A GitHub rate-limit window with
a reset timestamp already in the past must not be presented as a live budget,
even if the parent snapshot is newer than the 30-minute TTL.

**Full closure gate:** owner visual approval (passed), exact-main CI and CD
(passed for #315), anonymous production boundary, local registry readback,
and independently authorised live source smoke + relevant alert receipt.
Keep #295 OPEN if any externally privileged step remains unverified. H-01
#33 stays untouched, and the separate #271 Codex admission policy remains
fail-closed.


## Production incident — 18 October 2026: Ops Watch split-root imports

**Observed on owner VPS**: `hermes-ops-watch.timer` enabled/active, but the
one-shot `hermes-ops-watch.service` failed (`Result=exit-code`,
`ExecMainStatus=1`) before creating any `quota_*` incident. The import
traceback reported `ModuleNotFoundError: No module named 'control_center'`
from `ops_watch/quota_alerts.py`. The production deploy intentionally
places the Ops Watch Python package at
`/opt/hermes-agent-owner/ops_watch`, but places the Control Center
Python package at `/opt/hermes-control-center/current/control_center`;
a full-repository CI checkout obscured that production topology.

**Fix**: the quota observer imports its read-only Control Center adapter
from the immutable, root-owned, SHA-pinned Control Center release only if
the canonical monorepo import is unavailable. It verifies exact release
path, same-SHA Hermes owner release, and non-writable root-owned source
paths. An untrusted or missing release fails closed rather than importing
arbitrary Python. No `PYTHONPATH` injection, handler installation, new
systemd overrides, inference, or resident-agent change.

**Readback after the *new exact-SHA* production deploy** (read-only):

```bash
systemctl show hermes-ops-watch.service \
  -p Result -p ExecMainStatus -p ExecMainStartTimestamp \
  -p ExecMainExitTimestamp --no-pager
cd /opt/hermes-agent-owner
/usr/bin/python3 - <<'PY'
from ops_watch.quota_alerts import observe
for provider, state in sorted(observe().items()):
    print(f"{provider}={state}")
PY
```

Let the already enabled `hermes-ops-watch.timer` execute normally.
Then verify the real collector returns `Result=success`, and read
`events` joined to `delivery_receipts` in the existing
`/var/lib/hermes-agent/ops-watch/incidents.sqlite3` using SQLite
`mode=ro`. A new `ops:quota_desktop_exhausted` incident is expected
**only if** the fresh desktop snapshot still reports `exhausted` when
the collector runs and is not already a persisted active incident.
Delivery is confirmed only by a persisted acknowledged receipt whose
event fingerprint matches that quota incident. The queue has no synthetic
quota rows from this repair.

Do not reset timers, inject test incidents, run a Telegram sender manually,
or alter the unrelated H-01 burn-in. Missing Cloudflare Billing Read and
GitHub quota collector credentials remain independent owner gates.


## Telegram sender start-limit hit — 18 October 2026 (#295, #3)

Live owner-confirmed `ops:quota_desktop_exhausted`, phase `new`,
`acknowledged=1`, `pending=0` proves end-to-end acceptance in the
existing SQLite transactional outbox and Telegram API. The next production
readback showed `hermes-ops-alerts.service Result=start-limit-hit`,
while the journal contained multiple `EMPTY_OR_LEASED` sender runs and
one `ACCEPTED_BY_TELEGRAM`. An old 6-starts/1-hour systemd limit gave
essentially no margin for a 10-minute timer plus approved diagnostics.
A previous `ExecMainStatus=0` does **not** prove that later timer triggers
were accepted after `start-limit-hit`.

The reviewed fix raises the *systemd activation cap* to **12 starts/hour**
with unchanged 10-minute timer and unchanged **one queued event per start**,
fixed retry/receipt logic, credential isolation, memory/CPU protections and
sandbox. This is **not** 12 retries per event, nor a faster polling timer.

The normal GitHub CD handler intentionally does NOT replace any installed
`/etc/systemd/system` units. After the fix is merged, CI-clean and its
exact SHA is live, an authorized VPS operator must review/apply the service
file from the immutable release (never assume `/opt/hermes-agent-owner/deploy`
was updated). First verify the currently active fragment and SHA:

```bash
systemctl show hermes-ops-alerts.service \
  -p FragmentPath -p Result -p StartLimitBurst \
  -p StartLimitIntervalUSec --no-pager
active="$(readlink -f /opt/hermes-control-center/current)"
[[ "$active" =~ ^/opt/hermes-control-center/releases/main-[0-9a-f]{40}$ ]] || exit 1
sha="${active##*main-}"
candidate="/opt/hermes-agent-owner/releases/main-$sha/deploy/hermes-ops-alerts.service"
[[ -f "$candidate" && ! -L "$candidate" ]] || exit 1
grep -E '^StartLimit(IntervalSec|Burst)=' "$candidate"
systemd-analyze verify "$candidate"
```

Only with the exact production SHA and owner approval for this systemd
configuration edit, back up the existing installed service file, install
the reviewed candidate in `/etc/systemd/system/hermes-ops-alerts.service`
with root:root 0644, run `systemctl daemon-reload`, and then
`systemctl reset-failed hermes-ops-alerts.service` to clear the previous
start-rate failure. **Do not** restart the sender or sender timer just to
test the repair; keep the existing `hermes-ops-alerts.timer` schedule.
The next normal timer activation should be confirmed in `systemctl show`
and `journalctl`. Read-only `python3 -m ops_watch.telegram_dispatch`
returns aggregate pending ACK counts without sending any message.

Rollback: restore the securely backed-up service file, run
`systemctl daemon-reload`, and inspect the sender timer/state. Resetting
systemd's failure counter is distinct from deleting or acknowledging
messages; it must never modify `incidents.sqlite3`. The optional GitHub
and Cloudflare collectors remain independently owner gated.


## Stage 5 — safe owner-gated GitHub / Cloudflare activation

The owner-confirmed local readback after the October 18 production release
showed Codex and Desktop Commander source signals, while
`github_api=unknown` and current Cloudflare Free Neurons used/remaining
remained UNKNOWN. This is accurate; the **two external one-shot collectors**
are opt-in and NOT installed by normal CI/CD. The live Desktop Commander
`ops:quota_desktop_exhausted` event obtained a genuine Telegram
`acknowledged=1`; the Ops Watch timer was later verified active with
a successful normal sender invocation after applying the 12-start/hour
service rate-limit correction. Do not confuse this with GitHub/Cloudflare
source authorization.

A dedicated owner-only helper separates the steps below:

| Step | Exact command suffix | Effects |
| --- | --- | --- |
| Status | `status github` / `status cloudflare` | Local file metadata and validated source state only |
| Install | `install github` / `install cloudflare` | Back up and install just those two opt-in systemd units, no start |
| Smoke | `smoke github` / `smoke cloudflare` | Exactly one bounded official GET using a separately approved credential |
| Enable | `enable github` / `enable cloudflare` | Activate periodic timer **only with a fresh real source observation** |
| Rollback | `disable github` / `disable cloudflare` | Stop only that collector timer; preserve existing snapshots and unrelated services |

In the owner-authorized **root SSH console**, always invoke the helper
through a child `bash` process, never `source` it. Its fail-closed
`set -e` will then exit only that child and **will not log out SSH**.

```bash
active="$(readlink -f /opt/hermes-control-center/current)"
if [[ "$active" =~ ^/opt/hermes-control-center/releases/main-([0-9a-f]{40})$ ]]; then
  sha="${BASH_REMATCH[1]}"
  setup="/opt/hermes-agent-owner/releases/main-$sha/deploy/h15-provider-source-setup.sh"
  bash "$setup" status github
  bash "$setup" status cloudflare
fi
```

If `MISSING_OR_UNSAFE` appears, stop there. The helper does **not**
create, display, repair or request credentials. It refuses to install
or enable collectors until the owner **independently provisions**
root-owned non-symlink `0600` token files in `/etc/hermes/`.
The Cloudflare source additionally requires a root-owned `0600`
`/etc/hermes/cloudflare-billing-read.env` containing **only**
`CLOUDFLARE_BILLING_ACCOUNT_ID=<32-hex-account-id>`.
Never paste tokens, account IDs, browser cookies or .env contents
into ChatGPT, GitHub, CI, screenshots or journal logs.

### GitHub account selection and API semantics

The official [GET /rate_limit API](https://docs.github.com/en/rest/rate-limit/rate-limit)
**does not consume** primary REST quota. GitHub explicitly states that
fine-grained PATs do **not** require repository permissions for that
endpoint. Create a new short-lived, least-privilege fine-grained token
for the intended GitHub principal, **not** a ChatGPT connector secret,
GitHub Actions `GITHUB_TOKEN`, an OAuth session or a token for unrelated
repositories. Review GitHub's account/token settings independently,
and provision the bearer string directly into
`/etc/hermes/github-rate-limit-read.token` on the VPS with mode `0600`.

GitHub's `GET /rate_limit` reports per-resource windows for the requesting
identity/authentication context. **User limits can be shared across multiple
user tokens**, and installation limits can differ; do **not** label a
user's primary bucket as exclusively belonging to one PAT or as every
GitHub integration's aggregate quota. Primary rate limits alone do
not establish secondary throttling, Actions job usage or capacity.
When the official source fails, the card remains UNKNOWN.

After owner provisioning and review, the commands are deliberately
separate and no source is activated by the normal production deploy:

```bash
# GitHub; inspect returned fixed statuses between each step.
bash "$setup" install github
bash "$setup" smoke github
bash "$setup" enable github

# Cloudflare only after separate Account Billing Read scope,
# verified account ID and explicit owner opt-in.
bash "$setup" install cloudflare
bash "$setup" smoke cloudflare
bash "$setup" enable cloudflare
```

Each step validates the exact currently active immutable release
and rejects systemd unit drift. The `smoke` step is a **single bounded
official API read**, never inference; the `enable` gate validates an
actual fresh snapshot rather than just a token's existence. A delayed
Cloudflare V1 billing response with no unambiguous previous-day Workers AI
Neurons record is NOT sufficient to enable its timer; it remains
UNKNOWN even if the API replied 200. Cloudflare V1 may omit Free usage.
Cloudflare V2 includes Free but is currently **Alpha / restricted access**
and cannot be substituted without a separately validated response schema
and owner permission. No plan or paid feature is enabled by this helper.

Finally run the existing `sudo -u hermes-control /usr/bin/python3 -m
scripts.h15_provider_readback` from the matching Hermes source release
and inspect per-provider cards in the existing owner OAuth UI. Confirm
source_kind and independent reset windows, not merely collector exit=0.
Rollback via `bash "$setup" disable <provider>` leaves Ops Watch
and the existing H-01 fail-closed policy untouched.


## Stage 6 - capless provider snapshot ownership repair (#295)

On the Hermes VPS the one-shot GitHub collector's first official API read
succeeded from the owner console (`READ_STATUS=ok`, six resources), but the
systemd smoke reported `GITHUB_QUOTA_READ=unavailable`. Its StateDirectory was
`root:root 0750`; both optional collectors previously called `os.chown`
from inside a `CapabilityBoundingSet=` empty sandbox. Such runtime
ownership changes cannot be relied upon without CAP_CHOWN.

Both isolated service units now specify `User=root` and
`Group=hermes-control`. systemd provisions `StateDirectory=hermes-provider-quota`
with that user/group before applying the capless sandbox. Snapshot writers
assert matching owner/group and directory mode, write root-owned group-readable
files atomically, and **never chown**. The GitHub SQLite history writer
likewise checks inherited group ownership without a runtime chown. A missing
or wrongly provisioned StateDirectory fails closed; no world-readable file,
capability increase, extra API request, or runtime H-01 change is allowed.

After exact-SHA CI and production CD, source-deployed units are **not** installed
by the normal deploy. On the owner's root VPS console, use
`bash /opt/hermes-agent-owner/releases/main-$SHA/deploy/h15-provider-source-setup.sh install github`
to replace/backup the installed units, then `smoke github`, verify a fresh
`FRESH_OBSERVED` official snapshot and usable history, and only then
`enable github` for its 10-minute timer. Do not run install/smoke/enable
for Cloudflare until its own approved root-only token and account ID are
independently provisioned. Keep #295 OPEN until all source and UI proofs pass.


## Stage 7 - optional owner-only Cloudflare Analytics Read investigation (#295)

UI: independent cards now say **Сервис / квоты** instead of asserting every
listed provider's quota meter is connected. The Cloudflare card explicitly
distinguishes daily Free allowance, delayed Billing Read records which may
omit free consumption, and separately permissioned **Analytics Read**
(advisory sampled usage, NOT authoritative remaining Neurons). Both static
production JS copies and responsive Playwright acceptance are kept in sync.

Owner granted an isolated read-only account analytics credential for a
bounded research preflight. This does **not** authorize broad Billing Read,
plan upgrades, inference, an autonomous service/timer or use as a #271 quota
admission gate. Cloudflare GraphQL returns adaptive analytics and must not
be used as a current billing total. Official references:
- https://developers.cloudflare.com/analytics/graphql-api/
- https://developers.cloudflare.com/analytics/graphql-api/sampling/
- https://developers.cloudflare.com/analytics/graphql-api/getting-started/authentication/api-token-auth/
- https://developers.cloudflare.com/analytics/graphql-api/features/discovery/introspection/
- https://developers.cloudflare.com/workers-ai/platform/pricing/
- https://github.com/cloudflare/skills/blob/main/skills/cloudflare/references/graphql-api/patterns.md

**Credential owner step** - in Cloudflare dashboard create a *separate*
custom API token named `Hermes Analytics Read` with only
`Account > Account Analytics > Read`, restricted to the one Hermes
Cloudflare account (not all accounts/zones). Consider an expiry and an
egress-IP restriction where the VPS source IP is stable. Do not reuse
Workers AI model-inference tokens or legacy/global API keys.

**No credentials should be sent via chat, GitHub, CI, CLI arguments or
committed to the repo.** The root console must independently provision two
distinct regular files, root-owned 0600, non-symlink and single-hardlink:
- `/etc/hermes/cloudflare-analytics-read.token` - bearer token only.
- `/etc/hermes/cloudflare-analytics-read.env` - exactly one line:
  `CLOUDFLARE_ANALYTICS_ACCOUNT_ID=<verified-32hex-account-id>`.

On the Hermes VPS **after** confirming the released exact SHA and after
independent credential provisioning, run:

```bash
active="$(readlink -f /opt/hermes-control-center/current)"
[[ "$active" =~ ^/opt/hermes-control-center/releases/main-([0-9a-f]{40})$ ]] || exit 1
sha="${BASH_REMATCH[1]}"
cd "/opt/hermes-agent-owner/releases/main-$sha" || exit 1
/usr/bin/python3 -m scripts.h15_cloudflare_analytics_probe
```

The one-shot tool performs **one** size/timeout-bounded POST *GraphQL query*
to the account-scoped **read-only** Analytics API, for the **previous
completed UTC day**, requesting only the aggregate `sum.totalNeurons`
from `aiInferenceAdaptiveGroups`. It outputs only fixed result codes
and, if validated, `PREVIOUS_UTC_DAY_NEURONS_ADAPTIVE_ESTIMATE` plus
`QUOTA_REMAINING=UNKNOWN` / `BILLABLE_USAGE=NOT_VERIFIED`. If the
account has no reported groups, this is `no_confirmed_samples`, not zero.
If GraphQL denies the dataset, account or plan, the tool fails closed
without printing raw errors. No snapshot is persisted, no timer is installed,
and the public registry/Card stays UNKNOWN for the Free remaining budget.

Review the one-shot result for schema/permission availability, samples,
sampling uncertainty, historical lag and coverage before considering a
**separate** opted-in informational analytics collector. Cloudflare Billing
V1 and V2 remain independent sources with different grants and latency.
#295 must stay OPEN until the real owner-provisioned Cloudflare access and
fresh on-host query have been independently verified.


## Stage 8 - Cloudflare adaptive-data quality check (opt-in, no timer)

Owner's one-shot GraphQL account-scoped Analytics Read request was accepted on
the Hermes VPS. Sanitized proof, without account ID or bearer token:

```text
ANALYTICS_CREDENTIALS_PROVISIONED
CLOUDFLARE_ANALYTICS=advisory_estimate
PREVIOUS_UTC_DAY_NEURONS_ADAPTIVE_ESTIMATE=23.427
QUOTA_REMAINING=UNKNOWN
BILLABLE_USAGE=NOT_VERIFIED
```

The first result **only demonstrates access and one historical adaptive
aggregate**, not completeness across all groups, exact Free metering, or
real-time quota balance. A GraphQL `...Groups(limit: 1)` request may yield
just one aggregate bucket; absence of dimensions and single response row must
be empirically verified against the account's Cloudflare dashboard/schema
before describing the number as complete account-wide usage.

Cloudflare documents confidence intervals for adaptive `sum`/ `count`
metrics. To test whether this particular account/Workers AI field offers them,
an operator can issue **one additional bounded read-only GraphQL query**:

```bash
active="$(readlink -f /opt/hermes-control-center/current)"
[[ "$active" =~ ^/opt/hermes-control-center/releases/main-[0-9a-f]{40}$ ]] || exit 1
sha="${active##*main-}"
cd "/opt/hermes-agent-owner/releases/main-$sha" || exit 1
/usr/bin/python3 -m scripts.h15_cloudflare_analytics_probe --confidence
```

The optional flag requests a 95% confidence interval for the prior completed
UTC day. It prints a fixed success/failure category and only numeric estimate,
bounds and sample size when all are valid, without account IDs or credentials.
Any field/schema denial, absent/malformed CI, impossible interval, no samples
or auth errors **fail closed**. Cloudflare may not expose this field in the
target `aiInferenceAdaptiveGroups` schema; a rejection is evidence of
unsupported quality metadata, not authorization for alternative broad access.
No automatic retries, timers, snapshots, prices, billing changes or AI
inference are performed. Never use intervals or point estimates as a #271
quota-admission ALLOW.

Official references:
- https://developers.cloudflare.com/analytics/graphql-api/features/confidence-intervals/
- https://developers.cloudflare.com/analytics/graphql-api/sampling/
- https://developers.cloudflare.com/analytics/faq/graphql-api-inconsistent-results/
- https://developers.cloudflare.com/analytics/graphql-api/features/data-sets/


## Stage 9 - bounded advisory Cloudflare history (prepared, NOT enabled)

Owner's Cloudflare Analytics Read confidence probe successfully returned a
prior-day `estimate=23.427`, `lower95=23.427`, `upper95=23.427`,
`sampleSize=2` for the authorised account. Cloudflare's response supports
the GraphQL field and an estimate but **does not demonstrate full coverage**
or zero uncertainty: only two underlying samples and an apparent zero-width
interval. Never advertise this as the exact total Neurons, Free quota spent,
billing usage, or today's available budget.

The optional `control_center.cloudflare_analytics_history` module stores
up to 30 **completed UTC-day** estimates, their 95% reported bounds and
sample size. Sample sizes below 10 are tagged `very_small_sample`;
10 through 29 are `limited_sample` (display-only heuristics, not
statistical guarantees). The registry can expose these only under separate
`analytics_history` / `analytics_status` keys. Cloudflare's current
quota fields remain `status=unknown`, `source_kind=unknown`,
`used=null`, `remaining=null`. Do not feed these values into #271/#62,
Free-quota alerts, or machine ALLOW.

The optional collector is **one-shot only** and will refuse to query if
not running with root UID and primary group `hermes-control`, or if the
root-created StateDirectory does not exist. This stage deliberately does not
install a systemd unit or timer.

Root-only manual admission command after exact-SHA production deploy
and only while the source matches the immutable owner release:

```bash
active="$(readlink -f /opt/hermes-control-center/current)"
[[ "$active" =~ ^/opt/hermes-control-center/releases/main-([0-9a-f]{40})$ ]] || exit 1
sha="${BASH_REMATCH[1]}"
test -d "/opt/hermes-agent-owner/releases/main-$sha" || exit 1
cd "/opt/hermes-agent-owner/releases/main-$sha" || exit 1
runuser -u root -g hermes-control -- /usr/bin/python3 -m scripts.h15_cloudflare_analytics_collect
```

This performs exactly one bounded read-only Cloudflare GraphQL confidence
query, then writes only a sanitized `0640` atomic local archive in the
already-created `/var/lib/hermes-provider-quota/` directory. It does not
persist bearer tokens, account IDs, raw API data, prompts or request headers.
The existing GitHub timer is unchanged. No repeats or automated retries.
The above command should be executed in an isolated child Bash process in
SSH, not sourced into the owner shell, to avoid disconnects on `exit`.
A fail-closed non-zero outcome means no new estimate is published.
