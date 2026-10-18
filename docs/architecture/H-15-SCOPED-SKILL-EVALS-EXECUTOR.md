# H-15 #349 — Scoped Skill Evals executor: dormant contract

**Status: source-only, OFFLINE / EXECUTION=DISABLED.** This is an independent,
one-purpose building block for [ADT #11](https://github.com/MikeMoore1337/ai-development-toolkit/issues/11).
It is not wired to production H-15 device presence, H-01, Control Center,
Codex scheduler #271, systemd, an HTTP endpoint, SSH or the existing WSS relay.

## Architecture decision

Reviewed the existing `control_center/codex_scheduler.py` and
`control_center/codex_scheduler_executor.py` as an alternative. They already
own the durable **Hermes/Codex** task queue on the VPS and include explicit
operator grants/quota checks. Reusing that executor for this pilot would add
non-Codex provider dispatch, a second source checkout, model billing and
OS filesystem permissions to an unrelated production service while H-01 #33
is undergoing separate acceptance. **Rejected:** no new general-purpose queue
or remote shell. Instead the local `eval_lane` package implements:

1. `protocol.py`: exact typed `adt_skill_eval_pilot_v1` request with a
   pinned 40-character ADT Git SHA, one allowlisted provider and model,
   allowlisted synthetic Python/JS/Go case IDs, bounded trials/time/memory/CPU/
   output, expiry ≤1 hour and stated maximum USD. Reject all extra fields,
   including `command`, `argv`, paths, `env`, URLs, hooks and endpoints.
2. Offline owner-side **HMAC-SHA256** approval tied to the canonical whole
   request digest, exact owner ID, expiry and approval ID. Verification rejects
   scope changes, invalid signatures and revoked approval IDs. The signing key
   must remain on a separately trusted owner device with narrow ACL; the
   repository provides **no production key or signing endpoint**. A test-only
   signing helper exists for synthetic tests. The approval ID is not sufficient.
3. `one_shot.py`: no queue; one exclusive worker lock and an immutable job-ID
   receipt claimed and fsynced BEFORE any executor callback. Reconnect,
   process crash or ambiguous outcome is **not** an invitation to retry.
   Operator must independently review the state and issue a new distinct
   signed approval if another attempt is justified. Revocation and expiry
   deny work before claiming a receipt. No raw prompts, secrets or model logs
   enter the receipt.
4. `fixed_plan.py`: produces a fixed argv for the **existing** ADT
   `scripts/agent_eval_runner.py`, never a caller-supplied command.
   Toolkit checkout SHA must match and be clean, model must be allowlisted by
   trusted local config and evidence goes to a pre-existing private directory.
   Aggregate proposed per-attempt runtime is bounded.

Only the library contract and **mocked callback** are implemented. There is
**no production executor binding, transport, service unit or default-enabled
configuration**. `OneShotLedger(enabled=False)` always denies execution.
There is no CLI that promotes an untrusted JSON job to operating-system
execution. The fixed plan merely describes what a separately reviewed worker
could invoke; it does not launch it.

## Important boundaries, not yet established

- Code-level `OperatorGates` booleans **are not OS enforcement** and must
  never be set on faith from remote payloads. Before real execution a trusted
  operator must prove the dedicated non-production OS identity/VM or container,
  hermetic workspaces, cgroup/resource ceilings, process-group cancellation,
  deny-by-default egress with only provider API, and separation from private
  YFC/Second Brain files. CI tests only the typed protocol and logic.
- A `budget.maximum_usd` field is **not a billing guard**. Real execution is
  NO-GO without a provider-side hard stop, quota measurement and a trusted
  local attestation for the exact provider, model, account and amount.
  No paid fallback, account rotation or automatic retries.
- In the future executor binding, provider CLI model authorization and exact
  SHA must be checked immediately before launch. Neither external process
  execution nor static `--sandbox` flags alone prove sandbox isolation.
- Artifacts must be reviewed/sanitized and their hashes independently checked
  before copying to the owner-approved destination. No secrets, token files,
  raw personal home folders, Codex credentials or unreviewed agent stdout
  should enter Hermes Control Center, GitHub or a public artifact.
- Untrusted model output may attempt to pre-create oracle directories, links
  or files. The ADT pilot now refuses these at the hidden-oracle boundary.
- Owner must separately authorize real model/provider charges, exact
  executor OS identity, budget ceiling and GO/STOP/rollback. **This Issue's
  approval is only to develop the dormant implementation.**

## Reproduce safe tests

```bash
python3 -m unittest tests.test_h15_scoped_skill_evals -v
python3 -m unittest tests.test_device_fabric_pilot_contract -v
python3 -m unittest tests.test_codex_scheduler_executor -v
```

No provider model call, SSH command, Docker runtime change or transport port
is required by these tests. The suite generates only synthetic jobs and keys
and monkeypatches the source pin for fixed argv inspection.

## Owner gates for a later iteration

- [x] Contract, offline scope checks, signed approvals, receipt fencing, no
  replay and test-only fixed plan.
- [ ] Dedicated disposable isolated runner and real measured resource/egress
  enforcement, with separate deployment/rollback plan.
- [ ] Trusted owner provision of signing key and file ACL, revocation store,
  provider quota hard stop with actual verified cap and cancellation.
- [ ] Implement narrowly reviewed OS executor callback, no WSS command frames.
- [ ] Run an owner-authorized single bounded canary and independently inspect
  receipts, logs, costs, denied egress and unchanged #33 operation.
- [ ] Run 2+ paired baseline/candidate attempts per case/provider and have an
  independent reviewer supply acceptance, regression, safety and activation
  verdicts to ADT #11. No unverified effectiveness numbers.

**Production proof:** source-only merge is not an active eval worker.
`DeviceRegistry.list_devices` must continue to advertise
`execution='disabled'` for every device.
