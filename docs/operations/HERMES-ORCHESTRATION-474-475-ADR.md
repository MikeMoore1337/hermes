# ADR: bounded Hermes delegation and Kanban DAG (Issues #474 / #475)

Date: 2026-10-22
Status: **PROPOSED / SOURCE_REVIEWED / RUNTIME_NOT_AUTHORIZED**.
Owners: [#474](https://github.com/MikeMoore1337/hermes/issues/474), [#475](https://github.com/MikeMoore1337/hermes/issues/475).
This ADR does **not** enable an agent, add permissions, install an upstream package, change #271, or grant model expenditure.

## Decision

- **#474: REUSE_UPSTREAM for the future resident Hermes runtime, DEFER activation.** NousResearch Hermes Agent already has a delegation mechanism. Do not implement another LLM executor/loop. For any real future delegation, enforce a parent-side and OS-side least-privilege envelope; a string in an agent goal is not a permission boundary.
- **#475: REUSE_UPSTREAM Kanban if durable inter-agent dependencies are actually needed; do not extend #271 for unrelated runtime orchestration yet.** The native Kanban board already models parents, children, ready/todo/running/blocked, structured completion metadata, and review. Neither a second queue nor a competing task database is justified.
- Prefer a single human-visible job/approval ownership source for each actual executor. Work that needs durable human review is **not** a transient delegate_task result.
- Both choices are source-level design decisions, **not** a production recommendation to switch on resident Hermes, new workers, model providers, or new permissions.

## Verifiable source baselines

| Source | Exact revision | Audited interface / status |
| --- | --- | --- |
| Local Hermes repo | [main at 13db1a5](https://github.com/MikeMoore1337/hermes/tree/13db1a5949e88db5632efd2d80005b621328eb7f) | Own scheduler: [codex_scheduler.py](https://github.com/MikeMoore1337/hermes/blob/13db1a5949e88db5632efd2d80005b621328eb7f/control_center/codex_scheduler.py); review only |
| NousResearch/hermes-agent | [v0.22.2, 7b77e29](https://github.com/NousResearch/hermes-agent/tree/v0.22.2) | [delegate_tool.py](https://github.com/NousResearch/hermes-agent/blob/v0.22.2/tools/delegate_tool.py); [delegate_tool_toolsets.py](https://github.com/NousResearch/hermes-agent/blob/v0.22.2/tools/delegate_tool_toolsets.py); [kanban_tools.py](https://github.com/NousResearch/hermes-agent/blob/v0.22.2/tools/kanban_tools.py) |
| NousResearch/hermes-agent | [main at 41dfcf2](https://github.com/NousResearch/hermes-agent/tree/41dfcf2c1bd7146d4ad46aea08b7dd007900602e) | Comparison **only**; not an approved upgrade or installed version |
| Official upstream docs | [v0.22.2 delegation](https://github.com/NousResearch/hermes-agent/blob/v0.22.2/website/docs/user-guide/features/delegation.md), [v0.22.2 Kanban](https://github.com/NousResearch/hermes-agent/blob/v0.22.2/website/docs/user-guide/features/kanban.md) | Describes semantics, not a test of this owner's runtime |

Source blobs checked: delegation toolsets **25ec633153f916a88585f46fa9d14af2e0545e2f** (identical v0.22.2/main), delegation implementation v0.22.2 **f393022cab464ae452c7d3188f6aee66c5a04754**, main **56c58a154b4bf1ba80ddc70dc01696201314907a**, native Kanban tools **c8b64c095c30a5d8f599869cace132d47d05654e** (identical v0.22.2/main). The differing delegation implementation requires separate regression before any upstream update.

## Why no second orchestrator

1. Native **delegate_task** creates independent child model contexts and task identifiers. The parent's enabled toolsets are inherited with child-specific denies. This is suitable for short independent read-only analyses, **subject to actual tool/OS restrictions**.
2. The model-facing delegation API does not offer an unrestricted ability to select a new provider or grant arbitrary tools per task. Internally, child-toolset resolution intersects explicitly passed toolsets with the parent's expanded capabilities, but optional MCP inheritance and the orchestrator role must still be reviewed. An issue-level field named allowed_toolsets is **not** enforcement.
3. Native **Kanban** already provides dependency edges, task identity, handoffs, metadata and dispatcher gating, so a new DAG database for a second agent queue duplicates upstream. Importing its database into Control Center without a verified boundary would create a second authority.
4. Local **control_center/codex_scheduler.py** has a serial SQLite job journal with immutable approval checks, unique idempotency keys, BEGIN IMMEDIATE transactions, fencing tokens and conservative uncertain-recovery. It accepts an exact request schema and currently has **no depends_on/handoff/child API**. It serves explicitly approved Codex jobs under [#271](https://github.com/MikeMoore1337/hermes/issues/271), not general free-form Hermes delegation. Do not add a bypass by sneaking a new field into requests.

## Safety/admission contract for any future live adapter

A child record, if future activation is separately approved, would require: parent_job_id, child_id, role, verified source_scope, parent-owned approval_id, allowed_toolsets, max_steps, deadline/expiry, idempotency_key, evidence_refs, and an immutable parent/child policy digest. These are **proposed contract fields**; they are NOT implemented in this PR.

Mandatory invariant checks before dispatch and before accepting a result:
- A child's effective permissions, filesystem roots, network targets and data scope must each be a subset of the parent's **enforced** capabilities. With no verified policy, reject; do not rely on prompt text or claimed read-only MCP annotations ([#350](https://github.com/MikeMoore1337/hermes/issues/350)).
- Permit at most **three independent child tasks**, flat depth 1, with strict lifetime and no default nested fan-out. Upstream's own defaults are not the owner's budget. Every live invocation additionally needs verified free-tier quota/allowlist and operator approval under [#33](https://github.com/MikeMoore1337/hermes/issues/33) and [#62](https://github.com/MikeMoore1337/hermes/issues/62).
- Default child operations to actual read-only technical capabilities, not merely a role label. Executor-side safety must survive aliasing, malicious tool metadata and reconnect. For uncertain execution/result state, **block/manual review**, not paid retry.
- A completed child may only submit evidence with exact repository SHA, fixture/source identity, tool trace, timestamp and independently validated references. Agent prose never attests its own success, truth or zero expenditure.
- Cancel must block new work and use the native owner/cancel mechanism. A timeout does not imply that a remote model/API invocation was not billed or completed.
- No production/YFC/Second Brain private vault, Telegram, untrusted MCP, new credentials or model calls are authorized by this ADR.

## Proposed low-cost evaluation (NOT EXECUTED as independent agents)

1. Synthetic, fully public **Issue -> read-only technical analysis A/B**, frozen SHA and full acceptance criteria. For B use two actual, separately identified workers (signal/contract and security) only if later authorized; coordinate and independently check findings. A uses one matching model/client.
2. For durable work only, use an upstream Kanban dependency: both analyses feed a verifier, which cannot be made ready until the parents are completed and evidence-verified. No autonomous publication or write side effects.
3. Negative cases: scope escalation, parent/child tool alias, forged approval or SHA, expired deadline, budget overflow, cycle, stale parent, duplicate handoff, cancel/recovery, lost result/ACK, restart and inaccessible device. Record PASS/FAIL only against executed tests on exact code, not a plan.
4. Measure wall time including coordinator, actual invocation IDs, attempts, verified findings, false positives and trusted usage receipts; otherwise label NOT_MEASURED. Running unit tests is not itself an A/B agent trial.
5. Keep earlier development-only [#453](https://github.com/MikeMoore1337/hermes/issues/453), [YFC #1157](https://github.com/MikeMoore1337/your-fitness-coach/issues/1157) and [Second Brain #412](https://github.com/MikeMoore1337/second-brain/issues/412) separate from resident-runtime #474/#475.

## Evidence and remaining gates

- Isolated Hermes BRC sandbox, Python 3.11.2, current mounted checkout **cf9cb1dfccd1b2a2573f594360fd898a71f00b1f**: targeted tests under tests/test_codex_scheduler*.py executed **32/32 PASS**, no actual Codex CLI or paid inference; working tree clean. This test baseline is older than the proposed PR's 13db1a5 base, although the codex_scheduler.py blob matched at both SHAs. Results cover #271 safeguards, **not** real delegation or Kanban.
- Public source comparison through GitHub at exact upstream revisions: SOURCE_REVIEW_COMPLETE. Real parent/child permission enforcement in a resident process, deterministic DAG negative tests against a newly scoped implementation and full A/B performance: NOT_RUN/NOT_MEASURED.
- PR CI at its exact HEAD is required; successful CI proves only the existing checks and the new **synthetic offline** contracts, not live agent execution or native upstream integration.
- Follow-up implementation/activation is separately gated by #33, #62, #350, available zero-spend enforcement, isolated runtime proof and operator GO. Any future code must have an explicit one-owner authority map and rollback before use.

## Rollback

This change contains **one ADR, one inert offline checker, one unittest file and one optional native upstream smoke-probe**, with no services, model calls, schema migration, dependency install, or live runtime behavior to reverse. Revert these three files if the decision changes. A later native upstream version change or adapter activation needs its own tested rollback, not this document as a substitute.

## Native helper execution evidence (2026-10-22, Hermes BRC, no model calls)

A fresh isolated Python 3.11.2 process on the `h15-win-05be75515428` **linux/docker sandbox** executed actual pinned v0.22.2 helper **function bodies**, extracted by Python AST from the two source files. The source text was fetched via GitHub and verified by computing the true Git blob SHA-1 (`blob <size>\\0<bytes>`); no installed Hermes agent, provider, plugin or worker process was imported or started. This tests those exact helper functions with minimal synthetic stand-ins for toolset registration. **It does not test the complete upstream dispatcher, filesystem/OS restrictions, real task linking, or effective OS permissions.**

- `hermes_cli/kanban_db_graph.py` checked blob: `e3a1f306c46d076069c4c80334e04b4440aa1d18`; native `_validate_children_graph` and `initial_task_state` exercised against in-memory SQLite / synthetic sibling DAG.
- `tools/delegate_tool_toolsets.py` checked blob: `25ec633153f916a88585f46fa9d14af2e0545e2f`; native `_resolve_child_toolsets`, `_expand_parent_toolsets` and related helpers exercised with a synthetic registry.
- First run: **17 cases**, 16 PASS and 1 **test-fixture ERROR**. The flawed test placed boolean `True` as a parent for sibling index `1` (equivalent to a forbidden self-reference). This was **not** a product defect. Rechecked correctly with a third sibling: **3/3 additional cases PASS**, including correct-index `True`, duplicate parent and cycle rejection. Do not claim a single clean 17/17 run.
- Confirmed: proper sibling DAG accepted; cycle/self-link/unknown parent/missing title rejected; child waits for a pending parent; missing parent cannot create a ready child; blocked stays blocked.
- Confirmed native toolset behavior: explicit request for a toolset absent in the parent's available set is denied; leaf loses delegation; parent's disabled toolsets are retained. **But** `toolsets=[]` selects the implicit inheritance branch, NOT an empty/no-tool capability set. A caller that means "no tools" must use an actual enforced deny rather than passing an empty list.
- Confirmed: effective role `orchestrator` causes `delegation` to be granted by a **role-specific exception even if the parent enabled only `web`**. This is intentional in the helper's documentation; whether untrusted callers can obtain that role was **not tested**. It is a mandatory privileged-role admission question, **not** a demonstrated production exploit.
- Confirmed: if `_get_inherit_mcp_toolsets()` is true, a parent MCP toolset is appended even when the explicit child request is narrower (e.g. `web` only). With this configuration disabled, such additional inheritance was not observed. Do not enable MCP inheritance for isolated read-only QA tasks by default.
- The native sibling-graph shape check accepts `True` as index `1` and a duplicated parent index in a list; this is a narrow input-validation gap in the helper, **not** evidence of a released cyclic graph or double execution. Full DB link validation was not exercised.

**Revised safeguards for future #474/#475 work:** disallow empty-list ambiguity at the application boundary; explicitly authorize privileged orchestrator role; prohibit MCP auto-inheritance for minimally scoped children; compare **resolved actual tool names** and OS rights with the parent's enforced permission envelope; reject malformed/duplicate/bool DAG references before submitting to native API if application inputs are untrusted. Continue to cap independent children at three and prevent nested execution without a separate gate.

**Boundary:** `NATIVE_HELPERS_OFFLINE_TESTED=YES`, `NATIVE_FULL_RUNTIME=NOT_RUN`, `MODEL_CALLS=0`, `NEW_B_AGENTS=0`, `PAIRED_A_B=NOT_MEASURED`, `PRODUCTION=NOT_TOUCHED`. This ADR remains a proposal and does not imply activating resident Hermes or installing external toolsets.

## Reusable offline contract smoke (#474 / #475)

The PR additionally includes `scripts/orchestration_offline_checks.py` and `tests/test_orchestration_offline_checks.py`. These are **deliberately inert** Python standard-library contracts, not a new dispatcher, durable journal or authorization server. Use:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p test_orchestration_offline_checks.py -v
```

On 2026-10-22, an isolated Hermes BRC Linux/Docker sandbox (Python 3.11.2) executed **26/26 PASS** against the original staged copies, prior to committing files to the PR. A subsequent isolated BRC Python check ran two independent deterministic read-only functions in a ThreadPool and validated the two separately checked SHA256 evidence receipts: **PASS, 0 LLM agents**. This check was added as the 27th unittest scenario in the PR; GitHub CI on the new HEAD is required to confirm the complete suite. Test cases cover correct two-input DAG order, cycle/self/unknown/duplicate/bool dependencies, expiration/approval/revision mismatch, scope and capability boundaries, step limits, unavailable devices, a three-node bound, schema rejection and evidence digest/identity/replay/expiry. **All inputs, grants, devices and trusted receipts were fabricated for deterministic testing.** The functions compare the supplied trusted receipt to a payload checksum but cannot authenticate the actual receipt issuer; the replay set is only in-memory. No actual LLM subagent, real device permission, model usage, native Kanban DB or dispatcher was exercised.

The pure `check_plan` preflight returns only an expected topological order; **it cannot execute that order**. `check_handoff` is a deliberately limited receipt-shape/digest fixture; it must **never** be used as a replacement for real signed/provider-attested evidence, durable replay protection or owner authorization. A runtime adapter must obtain independently attested grants and receipts, enforce OS/tool/network scopes, and implement the owner gates independently.

The tests therefore improve repeatable **synthetic acceptance** and regression visibility for #474/#475 without converting either issue to LIVE_VERIFIED. The PR HEAD must pass GitHub CI again after adding these files. Production delivery remains subject to the existing Hermes main/production rules.


## Exact pinned upstream native SQLite E2E — actually executed 2026-10-22

### Origin and isolation

- BRC: `h15-win-05be75515428`, reported platform **linux/docker**, Python **3.11.2**, local checkout `NousResearch/hermes-agent v0.22.2` (annotated tag **7b77e29eedd85a8497ce2821448dac7964dc46f6** peeled to commit **d923a5eb487a17c0a68801bba9ef0f56c81040a8**). The original source remained clean and unmodified.
- `hermes_cli/kanban_db.py` original blob `36d5736f73ea708450e2e8306b6b0264c75d95cd`, `hermes_cli/kanban_db_graph.py` `e3a1f306c46d076069c4c80334e04b4440aa1d18`. These are independently checked by the new [optional probe](../../scripts/orchestration_native_kanban_probe.py) before importing upstream.
- Only missing dependency `ruamel.yaml 0.18.16` was extracted to an **isolated sandbox directory** from the exact pure-Python wheel specified in upstream `uv.lock`; SHA256 `048f26d64245bae57a4f9ef6feb5b552a386830ef7a826f235ffb804c59efbba` verified before unpacking. No global/system/site-package install, no credential, no model API, no resident agent. Other optional provider plugins emitted missing `requests/httpx` import warnings but no request was executed.
- Temporary SQLite files were created inside sandbox scratch / isolated Python `tempfile` directories, then removed. No production database, deployment, H-01, Telegram, external provider or private source touched.
- Upstream detected **SQLite 3.40.1**, identified a WAL-reset corruption risk and intentionally ran `journal_mode=DELETE`. **Do not count these tests as WAL, production recovery, distributed coordinator, or installed runtime attestation.**

### Reproducible command

From a development/sandbox Python environment that already has the *exact pinned public upstream checkout and its required dependencies available* (no provider keys needed):

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  scripts/orchestration_native_kanban_probe.py \
  --upstream-dir /path/to/isolated/hermes-agent-v0.22.2 \
  --deps-dir /path/to/isolated/pinned-python-deps
```

The optional probe itself performs **no download, package installation, inference, persistent worker start or network operation**. Its `--deps-dir` is optional if the upstream local Python dependencies already exist. An incompatible upstream SHA/blob exits **2** rather than quietly substituting a different version. Keep this separate from the normal no-extra-dependencies CI, which cannot claim a native integration run merely because these files exist.

### Actual results

An initial interactive native SQLite trial passed **12/12** checks, and the now-committed, independently repeatable `orchestration_native_kanban_probe.py` passed **11/11**, `NATIVE_PROBE_EXIT=0` on the same pinned upstream sources. The probe covers:
- Native parent/child edges, two independent read-only tasks and QA dependency gate; QA result survives DB close/reopen.
- Native `link_tasks` cycle rejection and missing/self parent rejection.
- Native task `idempotency_key` deduplication.
- Two real concurrent *Python SQLite callers* attempting the same native `claim_task`: **exactly one wins**; this is not concurrent LLM inference.
- Reopen with a formerly claimed `running` task: a fresh plain `claim_task` does not duplicate the run. Additionally, an isolated child Python process was **really terminated via `os._exit(29)` immediately after a native SQLite claim committed**; the parent process reopened the database and verified `status=running` and second claim denied. This is an actual crash of a synthetic Python test process, **not** a real LLM worker, production recovery, or timed-out lease recovery.
- Explicitly blocked parent prevents premature QA; repeated `complete_task` cannot overwrite a `done` task.
- **Crucial native behavior:** an `archived` parent with **no result** releases a child to `ready`. It is upstream's documented terminal-edge behavior, not proof of trustworthy execution. The synthetic [evidence-gated eligibility helper](../../scripts/orchestration_offline_checks.py) now requires externally verified parent IDs before considering QA eligible. The repository unit tests reject a missing archived parent's evidence. This helper cannot authenticate receipts or enforce real dispatcher admission.

### Acceptance boundary

`PINNED_NATIVE_SQLITE_TESTED=YES` with DELETE journal and synthetic public task content. `WAL_RESTART/REAL_AGENT_PROCESS_KILL_RECOVERY=NOT_RUN`, `REAL_MODEL_WORKERS=0`, `SIGNED_RECEIPTS=NOT_IMPLEMENTED`, `OS_TOOL_PERMISSION_ENFORCEMENT=NOT_VERIFIED`, `PAID_API_CALLS=0`, `SPEEDUP/TOKEN_SAVINGS=NOT_MEASURED`. No code here changes native upstream or authorizes resident production deployment. #474/#475 remain OPEN until the remaining live-admission gates are separately approved and tested.


## Ambiguous inference recovery: native upstream gap and inert negative checks (2026-10-22)

Pinned v0.22.2 [`hermes_cli/kanban_db.py`](https://github.com/NousResearch/hermes-agent/blob/v0.22.2/hermes_cli/kanban_db.py) distinguishes a **task lease** from the actual model/provider call. In `release_stale_claims` around lines 2344-2441, an expired dead claim can be reclaimed into `_retry_status_for_run` (`ready` for ordinary work or `review` for review), subject to the existing failure breaker. `claim_task` around lines 2198-2230 may subsequently claim a `ready` task again. This does **not** show that paid inference was repeated during our tests, but source alone does **not** establish a once-only model invocation after a crash between provider request and its receipt. A SQLite lease becoming reclaimable cannot serve as a zero-additional-cost proof.

For the owner-required `$0`-additional-spend and no-repeat policy, any future **separately authorized** adapter must atomically and durably record a pre-call reservation outside native task lease bookkeeping, distinguish `never`, `reserved`, `started`, `uncertain` and `finished`, and fail closed on **every ambiguous outcome** (including lease expiry). Re-delivery of already verified results may be permitted without a new provider request after independent idempotency verification. A retry requires a fresh scoped owner decision and independent cost/quota evidence; an ordinary `ready` native Kanban status alone is insufficient.

To make this invariant regression-testable without starting a worker, `scripts/orchestration_offline_checks.py` provides `synthetic_one_shot_recovery_gate` and `tests/test_orchestration_offline_checks.py` includes **11 negative/positive cases**: first-only reservation, missing approval, elapsed lease, reserved/started/uncertain/finished calls, contradicting attempt counters, malformed booleans and unknown/extra fields. This is a **pure simulated verdict**, not integrated with native Kanban, not a durable reservation, not authenticated owner approval, not a provider billing receipt, and cannot itself prevent retries in production. `NATIVE_RUNTIME_RETRY_POLICY=NOT_IMPLEMENTED`; `REAL_MODEL_RETRY_PROOF=NOT_RUN`.

**Unchanged release constraints:** no new daemon/queue/LLM/CLI/network use; PR tests operate on synthetic data, and all real activation gates remain under #33/#62/#350. Source-only ADR and pure helpers can be reverted as ordinary source changes. New PR HEAD and CI must be checked independently after this amendment.


## Aggregate step-budget boundary (synthetic, 2026-10-22)

Issue #474 requires detection of budget exhaustion. Limiting each child to the parent's `max_steps` separately is **not** enough: three children can each pass that comparison while their *combined reserved* steps exceed the total parent budget. The offline checker now rejects a plan when `sum(child.max_steps) > grant.max_steps`. The synthetic fixture reserves 4 + 4 + 5 = 13 steps against a maximum of 16. Three regressions cover the overflow when each individual child still fits, exact equality (13/13) and an undersized parent budget (12/13). The bound is evaluated before DAG acceptance.

This is a conservative static admission invariant only. It does **not** meter actual token usage, provider-side billing, retries, concurrency or runtime steps, and it is not wired to native Hermes. A real executor would also need an atomic aggregate budget counter (and a previously authorized provider/usage gate) before any model request. No model was called to validate this policy. Recheck exact PR HEAD CI after these changes.


## Identity type and empty approval regression (2026-10-22)

During source-only review of the *synthetic* gate, a matching `approval_id=None` (or matching empty approval IDs) could satisfy the equality check. That falsely models an owner-approved operation when both plan and supplied grant are missing a real approval identifier. The checker now requires non-empty bounded ASCII approval IDs on **both** inputs *before* comparing them. It also validates producer node ID, revision SHA and receipt identity field types before comparing an evidence handoff. Seven new unit tests cover null/empty/whitespace owner IDs and missing/malformed receipt identities.

This closes a **synthetic contract validation gap only**. A non-empty matching approval string is not authenticated owner consent; a receipt supplied by the same synthetic test is not a cryptographically trusted source. No new runtime enforcement, model spawn, native Kanban connection or production delivery is implied. Check CI on the **new** exact PR HEAD, not the earlier 2364-pass run.


## Native probe reproducibility hardening (2026-10-22, #474/#475)

Previous `_verify_pinned_checkout` validated the Git HEAD and two critical blob hashes, but Python imports companion modules from the rest of the checkout. A modified tracked module or added/untracked/ignored importable could therefore contaminate a supposedly pinned *native* SQLite probe, despite matching the two hashes. The **optional standalone test helper** now first requires that `source_dir` is the repository root, matches the exact pinned commit and has no modified tracked or ordinary untracked files. It also rejects ignored/untracked `*.py`, `*.so` and `*.pyd` modules that `git status --porcelain` would suppress.

Seven independent **local fake Git fixture tests** under `tests/test_orchestration_native_probe_pins.py` cover a clean repository, modified companion file, added Python source, ignored Python source, wrong HEAD, wrong critical blob and nested directory alias. These standard-library tests can run in existing offline CI **without cloning NousResearch**. They validate that the probe refuses contaminated source; they do not execute the upstream Kanban suite.

**Residual provenance limits:** Git's ignored bytecode or arbitrary external `PYTHONPATH` modules, local interpreter, dependencies and Git remote are not cryptographically attested. Pinned Git SHA is not an image/provisioning supply-chain proof. The optional native probe still requires independent clean public upstream staging and a separately pinned local dependency source; this PR does **not** install or activate any LLM agents. The exact HEAD quality CI must be checked after adding these tests; do not promote an offline fixture to production assurance.


## Native OS-local cancellation extension (#474/#475, 2026-10-22)

A follow-up **separate** from merged PR #504 adds an opt-in pinned native Kanban probe scenario: create a temporary SQLite task, native `claim_task` with a host-local claim, start a short-lived *inert* Python sleeper, bind its actual process ID and restart-stable fingerprint via native `kanban_db_dispatch.adopt_worker_pid`, then archive the task with native `archive_task`. A test-controlled `signal_fn` refuses to send any signal to a PID other than this exact sleeper; the process is terminated and reaped in `finally` even on assertion failure. Assert verified fingerprint, an observed OS termination signal, child exit, terminal `archived` state and refusal to claim it again.

This is an **actual ephemeral Linux OS process-termination experiment** when verified by the new pinned GitHub workflow, not an LLM-worker experiment. It never uses model/provider credentials, live user data, persistent services, or target project production. A successful test may establish only that native local archive signals its own verified disposable child with the chosen process fingerprint in that runner. It cannot prove cancellation of a real LLM request, provider billing cancellation, protection on Windows/macOS, lossless handoff, or multi-device production enforcement. Do not update status to PASS before inspecting the exact-head native CI log.


### OS cancellation negative controls (separate PR #510)

The new native probe also exercises **an actual living disposable Linux process** against upstream `kanban_db_dispatch._terminate_reclaimed_worker` in three *negative* situations: an `UNVERIFIED_WORKER_FINGERPRINT`, a claim-lock belonging to a foreign host, and a recycled/foreign process-start fingerprint. The injected signal callback is deliberately fail-on-use, and the child is verified alive after each refusal, then terminated in `finally` by the test itself. This checks a specific fail-closed boundary of the **pinned original upstream code**, not permissions to execute a model.

**Important distinction:** refusal to signal an unverified live PID is a safety property against killing unrelated OS processes, **not** proof of successful user-requested cancellation. Such a live child may require manual containment; native archival alone does not prove it stopped or that external provider billing ceased. No claims about Windows/macOS, cross-device workers or zero-cost provider retries. The separate exact-head native CI must show all negative cases PASS before treating this as observed evidence.
