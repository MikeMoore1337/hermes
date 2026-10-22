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
- PR CI at its exact HEAD is required; successful documentation CI will prove only that documentation and existing checks are consistent.
- Follow-up implementation/activation is separately gated by #33, #62, #350, available zero-spend enforcement, isolated runtime proof and operator GO. Any future code must have an explicit one-owner authority map and rollback before use.

## Rollback

This change is **one documentation file**, with no services, model calls, schema migration, dependency install, or runtime behavior to reverse. Revert the documentation commit if the decision changes. A later native upstream version change or adapter activation needs its own tested rollback, not this document as a substitute.

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
