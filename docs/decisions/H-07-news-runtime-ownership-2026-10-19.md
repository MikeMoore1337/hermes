# H-07 / M-01: ownership of news runtime and migration decision

**Date:** 2026-10-19  
**Issue:** [Hermes #7](https://github.com/MikeMoore1337/hermes/issues/7)  
**Decision:** **KEEP_CURRENT** (no production migration or new worker/scheduler)  
**Status:** architecture decision proposed by #7 review; operational freshness remains **NOT_VERIFIED** on 2026-10-19.

## Decision and scope

Keep the already deployed **specialized** Hermes news discovery and editorial worker in the **YFC repository / YFC release and deployment lifecycle**, running on the **dedicated Hermes VPS**, *not* on the RU YFC application VPS. This is not the separate general-purpose **Hermes Agent** runtime, even though both refer to "Hermes" and can share physical host resources.

Keep YFC as the canonical owner of source definitions, editorial safety, signed intake, review and publishing. The Hermes Agent repository must not become a second editable source registry, editorial service, state store, producer, timer owner or publisher. Hermes may consume explicitly authorized, privacy-safe **read-only** status/health evidence. No new credentials, provider calls, deployment or endpoint are approved by this decision.

**Why:** YFC #415 already established and validated the dedicated-VPS topology; a repo/runtime move has no evidenced reliability, cost, permission or resource advantage. Moving code while preserving YFC contracts would add a release boundary, credential handoff, state/cutover machinery and split-brain risk. Renaming the historical pipeline does not justify a migration.

**Operational qualification:** historical PASS is not evidence of **today's** live service status. On 2026-10-19 remote Desktop Commander reports **0% calls left; all three devices offline**. Thus an independent new VPS health/timer/digest/queue inspection was impossible. Do **not** turn that absence of fresh evidence into a made-up current PASS.

## Source evidence, with dates

1. [YFC #415 final closeout](https://github.com/MikeMoore1337/your-fitness-coach/issues/415) (2026-09-22): dedicated VPS `separate-vm`; news discovery and worker image digests pinned, HMAC `hermes-editorial-intake-v2` accepted in a real bounded drain and then a scheduled run; dedicated discovery timer enabled/active; RU Task-403 Hermes footprint removed. All 11 old RU jobs were reconciled (4 previously accepted, 7 terminal); **copying** them would have caused duplicates. YFC local/public readiness HTTP 200 immediately after cleanup.
2. [Hermes H-00 read-only audit](../audits/H-00-2026-10-11.md) (2026-10-11 12:58-13:00 UTC): dedicated host `hermes-discovery.timer` active/enabled; last successful discovery `2026-10-11T12:38:24Z`, drain `2026-10-11T12:38:29Z`; both consecutive failure counts 0, pending/outbox 0. Installed news release then `hermes-1622aa19decf-6efa86d17f94ef34`, YFC build source SHA `1622aa19decfe4b109dd5f2f891d2c24f3c00c12`. This later read-only receipt supersedes the **September release ID** as the last observed news runtime; neither is asserted current on October 19.
3. [YFC discovery README](https://github.com/MikeMoore1337/your-fitness-coach/blob/master/deploy/hermes-discovery/README.md), [worker README](https://github.com/MikeMoore1337/your-fitness-coach/blob/master/deploy/hermes-editorial-worker/README.md), [YFC registry](https://github.com/MikeMoore1337/your-fitness-coach/blob/master/backend/fitminiapp_api/resources/news_sources.json), [renderer](https://github.com/MikeMoore1337/your-fitness-coach/blob/master/scripts/generate_hermes_source_definitions.py) inspected against YFC `master=2c5db3d845bf95682b7cc4c879d97a8e0d076eba` (2026-10-19). Registry has 26 entries (14 enabled); rendered `hermes-source-definitions-v1` embeds raw-source SHA-256 and `definitions_version=yfc-news-sources:<sha256>`. External discovery validates exact artifact SHA, host allowlist and schema. The deployed artifact's **present-day** hash was not read back.
4. [YFC discovery tests](https://github.com/MikeMoore1337/your-fitness-coach/blob/master/tests/integration/hermes_editorial_worker/test_discovery_contract.py) and [YFC signed intake tests](https://github.com/MikeMoore1337/your-fitness-coach/blob/master/backend/tests/test_news_hermes.py) already include registry determinism/digest mismatch, item relevance, stable keys, scheduler overlap, non-floating image refs, signed intake, invalid signature and idempotency cases. **Source inspection only in this review:** no checkout-based test suite was executed; current master CI was not substituted for targeted tests.

## Canonical ownership matrix

| Boundary | Canonical owner | Constraint |
|---|---|---|
| Source registry and generated read-only definitions | YFC | `backend/fitminiapp_api/resources/news_sources.json`; no second editable registry in Hermes |
| Discovery, relevance filter, outbox/state | YFC code and release lifecycle | Dedicated Hermes VPS; isolated bounded service |
| News worker, prompt/release manifest, image digests | YFC code and release lifecycle | Existing immutable YFC images; do not add a Hermes Agent worker |
| News schedule / timer configuration | YFC deployment owner | Exactly one active dedicated-VPS scheduler; RU co-location removed per #415 |
| Provider credentials and signed delivery sender | Existing news worker operator / YFC deployment | Never duplicate or disclose credentials; sender has no publish API |
| HMAC intake schema, nonce/replay and idempotency receiver | YFC backend | `hermes-editorial-intake-v2` and immutable revisions |
| Medical/editorial/taxonomy policy, manual owner review | YFC backend and owner | Worker draft/preflight is **not** publication approval |
| Publishing path and Telegram delivery | YFC | No direct publishing from Hermes discovery/worker or Hermes Agent |
| General Hermes Agent, Ops Watch, QA Advisor, Research Scout | Hermes | Distinct lifecycle/capabilities; read-only news health only if separately authorized |

## Existing bounded pipeline (no new runtime)

```text
YFC canonical registry
  -> generated versioned definitions (YFC)
  -> dedicated-VPS discovery timer (YFC deployment)
  -> HTTPS host/DNS/redirect/relevance/freshness gates
  -> stable-key atomic outbox + state/locks
  -> bounded editorial worker (isolated secret-bearing phase)
  -> source-grounded draft + deterministic preflight
  -> signed HTTPS YFC intake (v2; nonce/HMAC/idempotency)
  -> YFC immutable revisions and manual owner-review gates
  -> YFC-approved publication only
```

Discovery has no provider keys and no publication path. Worker cannot bypass the YFC manual review; provider requests are bounded and no paid fallback is authorized. Source metadata/abstracts are **not** verified medical conclusions. The canonical registry is neither copied nor independently edited by Hermes Agent.

The YFC discovery implementation computes stable job identity from source ID, canonical URL, content hash and event date. The same key backs outbox names/job/idempotency/nonce. The atomic outbox, locks, restart retry/accepted-or-duplicate drain semantics exist in YFC; do not reimplement them in the Hermes Agent.

## Options reviewed

| Option | Benefit | Complexity, reliability, cost and permissions | Reversibility | Verdict |
|---|---|---|---|---|
| **A. KEEP_CURRENT** | Preserve observed end-to-end working news pipeline; no new releases/services/secrets | Lowest added complexity, no new provider calls or operational spend; existing resource contention still requires monitoring | No cutover required | **SELECTED** |
| **B. MOVE_RUNTIME_ONLY** | Centralized agent repo ownership of a service already deployed on a dedicated Hermes host | Extra release owner, credential boundary, queue transfer, two-scheduler guard, rollback coordination, possible RAM pressure and duplicated CI; no evidenced benefit | Possible only with prior verified snapshots and single-writer cutover | **REJECT for now** |
| **C. SHARED INFRASTRUCTURE** | Existing Hermes Ops Watch may use safe YFC health metadata | Read-only observation can be useful without moving worker; new connector/credentials should require separate need and approval | Easy to disable if no worker touched | **Optional future integration, not #7 migration** |

### Resource and operational boundary

The [2026-10-11 snapshot](../audits/H-00-2026-10-11.md) found dedicated VPS 2 vCPU / 1967 MiB RAM, `MemAvailable` ~941 MiB, swap used ~718 MiB, load1 ~0.62, disk free ~16865 MiB. Existing separate-VM news guard: memory >=768 MiB, swap <=1024 MiB, load1 <=1.50, free disk >=5120 MiB. Discovery and worker bounded containers were provisioned at 256 MiB/0.25 CPU and 512 MiB/0.50 CPU, respectively. **These are historical observations, not current headroom or peak-load evidence.** Agent H-01/#33 has its own tighter operating limits. No additional news worker or model quota shares its budget under this decision.

## Evidence and acceptance matrix

Statuses describe what the **available** evidence establishes, not generic implementation claims.

| Criterion | Status | Evidence / limit |
|---|---|---|
| Canonical source registry | PASS | YFC file and deterministic renderer; October source inspection |
| Runtime ownership | PASS | YFC source/deployment docs and #415; current live SHA NOT_VERIFIED |
| Single scheduler | PARTIAL | #415 and H-00 verified one dedicated timer, RU removal; no Oct 19 VPS read |
| YFC editorial ownership | PASS | Intake/review and publication remain YFC |
| Signed intake | PASS | v2 contract in source and real accepted #415 delivery; no live Oct 19 probe |
| Idempotency | PASS | Stable key and YFC backend receiver contract; source/tests inspected |
| Queue preservation | PARTIAL | #415 reconciled 11 RU jobs; current outbox NOT_VERIFIED |
| Release manifests | PARTIAL | H-00 active news manifest and #415 release evidence; current SHA NOT_VERIFIED |
| Immutable images | PARTIAL | #415 digests, H-00 immutable refs; no current registry/host digest recheck |
| Resource compatibility | PARTIAL | Oct 11 snapshot only; no current peaks or Oct 19 readings |
| Security boundaries | PARTIAL | Repo ACL/HTTPS/fail-closed contracts; runtime enforcement not re-probed |
| Offline shadow compatibility | NOT_VERIFIED | Existing YFC local E2E tests inspected, not executed in this work |
| Rollback | PARTIAL | YFC release/rollback support documented; no rollback performed now |
| No duplicate publication | PARTIAL | #415 replay reconciliation and owner review; no current publish audit |
| Existing YFC health | PARTIAL | #415 HTTP 200 after cleanup; new live smoke unavailable |
| H-01 non-interference | PASS | Only repository review/doc branch; no VPS/process/provider changes |
| Owner migration approval | NOT_APPLICABLE | No migration proposed, no cutover permission implied |

## Conditions for revisiting B (not authorized by this ADR)

Require a **new, explicit owner migration GO** and a measurable advantage over A. Before any switch:

1. Independently collect time-stamped, privacy-safe **both-host** evidence: installed news source/build SHA, release manifest and image digests, service/timer enabled/active states, last successes/errors, queue depth/oldest pending, CPU/RAM/swap/disk/peaks, and approved egress.
2. Validate matching YFC registry SHA, generated definitions SHA, versioned intake/job/state schemas, stable-key function, provider path and immutable image rebuild/re-pull ability. Fail closed on any mismatch.
3. Keep old YFC scheduler active while new environment has **all timers disabled**. Prepare release, permissions, networking and signed-intake checks against **mock** endpoints only; no provider key or production HMAC copied for offline tests.
4. Offline shadow: synthetic RSS/JSON/HTML, safe mock source registry, mock provider and mock HMAC intake; verify same IDs, dedupe, atomic outbox, crash/restart, replay, 429/timeout/no-paid-fallback, source prompt injection, negative schema/signature/nonce, non-publication and old/new schema compatibility. Compare outputs without two live production consumers.
5. Persist and verify restorable release/config/outbox metadata; do **not** purge jobs or export source bodies in evidence. Prove readiness to reconcile accepted, terminal and pending keys *before* any cutover.
6. Establish an **enforced single-writer fence** checked against **both** actual runtime/scheduler states, not an operator note. Stop/disable old scheduler and verify it cannot rearm; only then atomically activate the new owner. Do not overlap two live worker drains, even briefly.
7. Verify next bounded success, no duplicate intake/publish/provider charges, queue monotonicity, YFC review health, source hash, resource thresholds and safe alerts. Keep rollback parent and old state intact.
8. If any gate fails, disable new scheduler, recheck single-owner fence, restore the known-good old release/schedule and preserved queue without resending accepted jobs. Independently verify health; only after sustained success remove old code via separate YFC PR/CI.
9. **Never** manipulate #33/H-01 timers, Cloudflare proxy, secrets, firewall, tunnel, unrelated YFC services or production state as a side effect of #7.

## Closing H-07

This ADR resolves the **architectural choice**: **KEEP_CURRENT**. It does **not** certify an Oct 19 production check, any offline shadow results, or a migration. Before claiming fully verified operational completion, obtain a new read-only single-scheduler/queue/health receipt without altering services. If that is unavailable, leave #7 **PARTIAL** with the exact evidence gap; a documentation PR alone is not live acceptance.
