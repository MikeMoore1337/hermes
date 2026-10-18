# H-15 #349 — isolated smoke without touching the YFC VPS

## Decision — 2026-10-18

YFC VPS was considered **only if there were no risk to YFC**. Read-only
review of the public YFC `docker-compose.yml`, deployment contracts, and
`deploy/hermes-discovery/README.md` shows it is an active production
application host shared by Postgres, web backend, frontend proxy, Telegram
bot, zero-downtime blue/green deployment slots, and separately scheduled
Hermes discovery/editorial services. A new model-executing worker would
compete for CPU/RAM/disk and could interact with other Docker networks or
change kernel/network conditions.

YFC's existing Hermes discovery deployment contract explicitly defaults to
`separate-vm`; a colocated mode needs a separate owner approval and an
existing deployment lock. This is evidence against casually reusing the
production VPS for a new execution service.

**Decision: NO_GO for any installation, service, container, VM creation,
network/firewall edits, synthetic worker or live model on the YFC VPS.**
The Desktop Commander connection was also offline and the account indicated
0% monthly calls remaining; no production host resource probe was executed.
Capacity and true isolation cannot be established from a repository file.

## Safer substitute: GitHub-hosted ephemeral offline test

The opt-in workflow
`/.github/workflows/h15-evals-offline-smoke.yml` tests a limited kernel
boundary on a **GitHub-hosted Ubuntu runner**, never a self-hosted runner.
It does not touch YFC/H-01 VPS hosts or their deployments.

It runs only `python -m eval_lane.isolation_probe` inside a disposable
Docker container with:

- no network namespace access (`--network none`);
- an explicit **default-deny seccomp allowlist** excluding socket/connect
  and process-creation syscalls, so AF_INET/AF_INET6 socket creation
  should be observed as EPERM;
- non-root UID, no Linux capabilities, no-new-privileges;
- read-only root filesystem and read-only source code bind;
- container memory 768 MiB, CPU 45%, PID count 32 and bounded job time;
- no provider credentials, paid agent runtime or user project data.

The workflow is triggered only on pull requests that modify the offline
probe or its CI contract, or by an operator using manual
`workflow_dispatch`. It requires `runner.environment=github-hosted`.
It neither triggers a production deployment nor installs a persistent
unit on any VPS. Artifacts only contain safe probe booleans/limits.

The test checks **real kernel controls of the isolated CI container**,
but its success would not prove those controls on a future owner VM,
and a failed job must remain a failed acceptance check. Network egress
is disabled for the test; there is intentionally **no external HTTP,
DNS or provider connection**. The probe's
`actual_outbound_deny_test=NOT_PERFORMED` remains accurate even when
socket creation is blocked. No billing-cap proof or model results are
claimed.

## Next steps without production risk

1. Obtain actual GitHub Actions run and its SHA/artifact; check no test
   ever ran on YFC or Hermes VPS.
2. If the CI boundary fails, fix the **ephemeral CI environment** only;
   do not relax the default-deny seccomp policy or switch to a YFC worker.
3. After success, prepare a separate **disposable non-production Linux
   executor** for the real provider CLI. Owner approval must identify its
   hosting provider, account, model, enforced hard spend cap and rollback.
4. Issue #349 and ADT #11 remain open. No live model calls are authorized
   by permission to prepare the offline infrastructure.

The temporary GitHub runner is not a general remote command gateway or a
substitute for measured real Codex/Claude trials.
