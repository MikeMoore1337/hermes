# H-15 Codex Task Scheduler (#271): operator and recovery contract

Status: source and synthetic MVP; **production live worker NOT ENABLED**.
Dependencies: #255 quota monitor/policy; #2/#33 H-01 burn-in; #272 analytics;
#273 offline benchmark. Nothing here restarts or reconfigures H-01.

## Architecture and data boundaries

Existing control_center.codex_usage (official CLI app-server, five-minute
collector) is the sole quota source; control_center.codex_policy.decision is
the fail-closed gate. All returned windows must allow ordinary usage and
have remaining quota above the low threshold. Reset time is not evidence of
recovery.

- codex_scheduler/core.py: SQLite journal, owner grant records, atomic claim,
  lease/fencing, cancellation, manual-review latch and idempotent receipt.
- QuotaWorker: serial, injected quota reader and executor; no timer.
- executor.py: official Codex CLI exec adapter; disabled by default, accepts
  trusted out-of-band approval ID to immutable plan mapping only.
- status.py: bounded, sanitized, read-only projection.
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

Only the official CLI adapter is provided: fixed argv, stdin from trusted
approval-to-plan map, selected repo root, isolated CODEX_HOME, timeout,
CPU/memory/output bounds, own process group and NO shell. No prompt/response
content is surfaced in the API. A successful SHA-256 receipt is a digest,
**not** replayable full model output. Verified grant issuance, dedicated
artifact persistence, live termination coordination and independently
observed CLI flags remain prerequisites for live unattended use.

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
