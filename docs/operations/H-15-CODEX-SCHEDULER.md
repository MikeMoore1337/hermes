# H-15 Codex Task Scheduler (#271): operator and recovery contract

Status: production source release delivered by #274; opt-in worker follow-up #277. **Production live worker NOT YET ENABLED**.
Dependencies: #255 quota monitor/policy; #2/#33 H-01 burn-in; #272 analytics;
#273 offline benchmark. Nothing here restarts or reconfigures H-01.

## Architecture and data boundaries

Existing control_center.codex_usage (official CLI app-server, five-minute
collector) is the sole quota source; control_center.codex_policy.decision is
the fail-closed gate. All returned windows must allow ordinary usage and
have remaining quota above the low threshold. Reset time is not evidence of
recovery.

- control_center/codex_scheduler.py: SQLite journal, owner grant records, atomic claim,
  lease/fencing, cancellation, manual-review latch and idempotent receipt.
- QuotaWorker: serial, injected quota reader and executor. The optional timer is separate and not automatically installed by CD.
- control_center/codex_scheduler_executor.py: official Codex CLI exec adapter; disabled by default, accepts
  trusted out-of-band approval ID to immutable plan mapping only.
- control_center/codex_scheduler_status.py: bounded, sanitized, read-only projection.
- GET /api/codex/tasks: existing owner-only GitHub OAuth/proxy protection,
  returns not_configured if queue has not been initialized.

No second quota collector, payment/fallback, account rotation, system timer,
automatic H-01 coordination, or publicly accessible submission API is added.

## Versioned task and owner approval

Submission schema v1 has *exactly* these fields: schema_version=1,
requested_at, expires_at, initiator, approval_id, repository,
allowed_operations (subset inspect/test/patch/prepare_pr), model, effort,
resource_limits (max_runtime_seconds, max_memory_mb, max_output_bytes), and
idempotency_key. Timestamps must be timezone-aware; TTL at most seven days.
Unknown fields, arbitrary shell commands, caller-chosen job_id, unsupported
models and unauthorized repositories/operations are rejected. The server
generates job_id, created_at, approval_expires_at, timestamps, status,
attempt_count, fencing_token and result_ref.

A privileged local operator can call register_approval only after *independent*
confirmation of the actual owner's authorization and immutable scope.
The verified_owner text parameter is not a cryptographic signature. There
is intentionally no internet-accessible approval issuer. **Before live
activation, a verified and auditable owner-grant issuance path is mandatory**;
until then grants are only synthetic. Approval binds initiator, exact repo,
model/effort, operations, max budget and expiry. Every claim is checked again.
Quota availability never acts as approval.

Duplicate idempotency key with identical canonical request returns same
job_id; changed scope/budget/timestamps raise idempotency_scope_mismatch.

## State diagram

    VERIFIED OWNER GRANT => queued
    queued => claimed
    deferred => claimed (new snapshot + still authorized)
    claimed => deferred (DEFER / UNKNOWN)
    claimed => blocked (authorization revoked/expired)
    claimed => running (ALLOW, durable pre-call marker)
    claimed => deferred (expired pre-invocation lease)
    running => succeeded / failed (atomic terminal receipt)
    running => blocked/manual_review (uncertain outcome/cancel/crash)
    queued / deferred / claimed => cancelled (owner cancel)
    queued / deferred => cancelled (task or approval expiry)

BEGIN IMMEDIATE serializes transitions. Lease owner and fencing token prevent
a stale worker from finishing or initiating a job. An expired *running* lease
must never be treated as a stopped model call: it becomes blocked with an
uncertain invocation latch, and blocks all later claims until reconciled.
An expired *claimed* lease is recoverable only because the durable marker
still proves that the pre-call reservation was never committed.

QuotaWorker checks fresh telemetry and invokes existing policy immediately
before reserving a start. ALLOW is insufficient unless owner approval, scope,
TTL and budget are still valid. DEFER and UNKNOWN call no model and increment
no attempt counter. A new successful snapshot may release an unstarted
deferred task, but there is no reset-clock-based restart or new task creation.
The tick is callable and testable but **no periodic production tick enabled**.

## Recovery and cancellation matrix

| Durable state | After restart |
| --- | --- |
| queued/deferred | Re-evaluate with new quota snapshot and valid grant |
| claimed with never-invoked marker | Reclaim after lease expires |
| running, uncertain start ACK | Block/manual review, NO retry |
| model done but DB receipt not committed | Block/manual review, NO retry |
| succeeded with result_ref | Idempotent result ACK, no model call |
| delivered_at committed | Return identical receipt on repeated ACK |
| running and cancel requested | Do not imply stopped; block/reconcile |
| lease expired with real process possibly alive | Global safety latch |
| disk/SQLite failure before running | Fail closed; unstarted claim can recover |
| disk/SQLite failure after running | Manual review; never auto replay |

In manual review inspect OS process tree, CLI sessions, OS resources and the
journal without exposing credentials. Confirm termination of any orphaned
Codex subprocess, reconcile externally and only then invoke the privileged
release_safety_latch(job_id, process_termination_verified=True). The original
job remains blocked forever and must not automatically retry. Cancel of an
unstarted task is immediate. Cancel of a running task records a request, not
an assertion that the inference process has actually stopped.

Only the official CLI adapter is provided: fixed argv (global approval flags precede `exec`), stdin from trusted
approval-to-plan map, selected repo root, isolated CODEX_HOME, timeout,
CPU/memory/output bounds, own process group and NO shell. No prompt/response
content is surfaced in the API. The opt-in worker persists successful bounded JSONL output to a private
artifact directory (mode 0700, files 0600), fsyncs it before recording an
opaque artifact reference in SQLite, and can re-ACK the existing result without
another inference. The adapter's legacy digest-only mode is only for offline
unit tests. Verified root-owned grant manifests bind the full immutable
instruction digest. Operator-observed exact CLI version and one-shot canary
remain prerequisites for claiming live production operation.

## Diagnostics, retention, rollback

Queue capacity 1000 tasks; prune deletes only certain terminal tasks older
than configured 1-30 days. SQLite runs WAL and synchronous FULL; back up
through SQLite backup API or a quiescent filesystem copy including WAL. Do not
delete running WAL. DB owned by a restricted local scheduler account; allow
the web process access only to sanitized data, not CODEX_HOME/auth.json.
Any size, permission, DB integrity or quota telemetry problem fails closed.

Synthetic tests:

    python3 -m unittest tests.test_codex_scheduler tests.test_codex_scheduler_status -v
    python3 -m unittest discover -s tests -v

They use no CLI, provider calls, credentials, paid inference or VPS changes.
An isolated VPS smoke can use the same unittest tests and a temporary DB
without manipulating #33 timer, logs, quotas or runtime limits.

Delivery may place source on production while keeping worker **OFF**.
The read-only endpoint should show not_configured until a DB is provisioned.
Live activation requires separate owner approval for verified grant issuer,
OS identity/ACL, precise CLI version and flags, executable plans, selected
model, repository and operation allowlist, budget, network, artifacts,
cancellation/restart runbook, timer and real one-shot canary. H-01 #33 is
not to be interrupted. Normal PR/CI/deploy never implies activation.

Rollback is to keep/disable only a future scheduler worker unit (if
separately installed), restore the previous release SHA and preserve
existing SQLite/WAL evidence. Any active child process requires independent
termination/reconciliation before declaring the rollback complete.

Boundaries: #255 observation/policy; #271 admission/queue; #272 usage metrics,
not authorization; #273 verifier; #2/#33 independent agent acceptance.

## Optional worker implementation and explicit activation (#277)

The existing CI/CD installs the source and Control Center only. It does **not**
install or enable new systemd units, permissions, repositories, or a real job.
This is intentional: the restricted production deployment key accepts only
`deploy SHA archive_digest`; it cannot execute arbitrary shell commands.
Do not change that boundary or put a generic privileged SSH key in GitHub Actions.

- Entrypoint: `python3 -m control_center.codex_scheduler_worker --config /etc/hermes-codex-scheduler/runtime.json --run`.
- Each tick reads the **existing** quota snapshot produced by #255. It checks all
  windows; unknown, missing, expired, auth_required, low or exhausted snapshots
  never dispatch inference. No reset-clock guessing or paid API fallback.
- No resident Python daemon: one bounded systemd oneshot every approximately
  five minutes. The unit invokes a single task at most and another invocation
  cannot overlap the same service. SQLite fencing prevents competing workers.
- The service requires **both** `--run` and root-owned config
  `"enabled":true`. The example config is deliberately disabled.
- Each permission is an operator-created, root-owned JSON manifest in
  `/etc/hermes-codex-scheduler/grants`. Each manifest binds the exact
  permission scope, single task, instruction text and immutable SHA-256. The
  scheduler remembers the complete manifest hash; modifying the instruction
  after it was first admitted blocks further ticks.
- Root ownership here is a local operator/owner trust boundary, **not** proof
  of a remote cryptographic owner signature. Only the authorized owner/operator
  may place manifest files; do not expose a remote write endpoint.
- Queue journal is local to `/var/lib/hermes-codex-scheduler/jobs.sqlite3`;
  group `hermes-control` can read its SQLite records, but cannot write them.
  Output resides under a private `artifacts/` directory; no private Codex
  conversations, JSONL or CODEX_HOME tokens reach the Control Center UI.

### Activation gates on production VPS

1. Complete or preserve H-01 #33's protected 24-hour acceptance. **Do not run
   `systemctl daemon-reload`, restart H-01, change the H-01 timer, or disturb
   its journals during the restricted acceptance window.** Schedule the
   independent service installation afterward. Source deployment through
   established CD is allowed and does not enable this unit.
2. Confirm deployed exact main SHA via canonical deploy receipt and `/healthz`.
   Verify current host RAM/swap/load headroom and active #33 services before any
   new process; if headroom is insufficient, remain disabled.
3. Through a separate authorized root-capable VPS console or a deliberately
   provisioned narrowly scoped installation channel (not the existing forced
   deploy SSH key), verify the new release's `deploy/hermes-codex-scheduler.*`
   files and install them under `/etc/systemd/system/` as root:root 0644.
   The unit reuses existing `hermes-codex` OS identity and
   `hermes-control` group. It has a 768MiB cgroup memory ceiling, 45% CPU
   quota, and no privileges or writable source directories.
4. Under root, create `/etc/hermes-codex-scheduler/grants` owned by
   root:hermes-control and mode 0750, and `runtime.json` owned by
   root:hermes-control and mode 0640. Copy the disabled example, replace
   paths with the **observed** real resolved Codex executable, isolated
   ChatGPT-subscribed CODEX_HOME from #255, exact reviewed repository root,
   selected available model. Never commit this private config or task prompts.
   The executable path must resolve to a regular file; a symlink npm shim
   itself does not satisfy the current adapter check.
5. Perform `codex --version`, `codex exec --help` and non-inference
   authentication/quota preflight as `hermes-codex` against its existing
   isolated home. **Do not reauthenticate into a second account** or use
   `OPENAI_API_KEY`. Confirm flags accepted by this exact installed CLI.
6. Run `python3 -m control_center.codex_scheduler_worker --config ...`
   (without `--run`) for manifest preflight: no database mutation or model
   inference. With `"enabled":false`, `--run` must report `disabled`.
7. For the owner-authorized initial live canary, create exactly **one**
   root-owned grant manifest with an expiry no longer than one hour, operation
   `inspect`, `low` effort, `max_runtime_seconds:120`,
   `max_memory_mb:256`, `max_output_bytes:8192`, a unique idempotency key,
   and instruction limited to read-only inspection of the reviewed Hermes
   repository. Make the request expiry at or before grant expiry. Do not
   include shell scripts, destructive actions, publishing, or PR writes.
8. First validate and test a synthetic quota-deferred tick. After explicit
   `"enabled":true` and a fresh ALLOW snapshot, permit a **single**
   observable live canary and verify one attempt, exit status, artifact
   existence, result ACK idempotency, resource usage and unchanged H-01.
   No blind retry if startup/outcome is uncertain. Quota may remain exhausted
   (DEFER), in which case **no real canary occurred**.
9. Only after the one-shot success and resource checks, `systemd-analyze
   verify` the two units; `daemon-reload` and `enable --now` the new timer
   in the separately approved post-#33 window. Observe several ticks, restart
   and deferred recovery; manually check installed unit, exact source and
   result receipt. If any gate fails, keep the timer disabled.

### Example local grant manifest shape (not authorization)

All timestamps and unique IDs are assigned when the actual owner approves the
specific job. This **template is not a permission** and must not be put into
`grants/` unchanged. Model must match the observed local CLI and root-owned
runtime config; the request and approval must use identical scope and limits.

```json
{
  "schema": 1,
  "approval": {
    "approval_id": "owner-canary-unique-001", "initiator": "MikeMoore1337",
    "repository": "MikeMoore1337/hermes", "allowed_operations": ["inspect"],
    "model": "SELECTED_AVAILABLE_CODEX_MODEL", "effort": "low",
    "resource_limits": {
      "max_runtime_seconds": 120, "max_memory_mb": 256,
      "max_output_bytes": 8192
    },
    "expires_at": "REPLACE_WITH_UTC_EXPIRY"
  },
  "task": {
    "schema_version": 1, "requested_at": "REPLACE_WITH_UTC_REQUEST_TIME",
    "expires_at": "REPLACE_WITH_UTC_EXPIRY", "initiator": "MikeMoore1337",
    "approval_id": "owner-canary-unique-001",
    "repository": "MikeMoore1337/hermes", "allowed_operations": ["inspect"],
    "model": "SELECTED_AVAILABLE_CODEX_MODEL", "effort": "low",
    "resource_limits": {
      "max_runtime_seconds": 120, "max_memory_mb": 256,
      "max_output_bytes": 8192
    },
    "idempotency_key": "owner-canary-task-unique-001"
  },
  "instruction": "Inspect the Hermes repository read-only; summarize one small module; do not modify files, publish, call external tools, or execute a second task."
}
```

### Shutdown / rollback

Use a separately authorized root console, not general-purpose CI privileges:
`systemctl disable --now hermes-codex-scheduler.timer`; check whether the
oneshot service/child process is still active, and if so stop and reconcile it
without deleting its SQLite/WAL or artifact evidence. Do not auto-retry any
job in `blocked/manual_review`. Set config `enabled=false` and review
process termination before releasing the safety latch. Retain prior approved
source, deployment receipt, and artifact evidence for rollback. H-01 #33 and
#255 quota service/timer are independent and must not be modified.

A green CI, merged source, or `PRODUCTION_DEPLOYED=SHA` **does not establish**
that the scheduler timer is installed/enabled or that a real Codex inference
occurred. Record actual on-host `systemctl`, journal, artifact and quota
observations before closing #271.
