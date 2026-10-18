# H-15 #349: offline Linux isolation evidence (no model invocation)

**Status: source-only, no service installation or activation.** This is a
preparation gate for an eventual dedicated disposable Eval Worker, independent
of Hermes H-01 #33, H-15 WSS presence and the existing Codex scheduler.

## Why this separate step

Hermes `eval_lane/local_executor.py` already has per-process rlimits and
a caller-provided `isolation_probe` callback. Neither establishes OS-level
memory/CPU/task ceilings or denies network egress. Owner approval to develop
this lane **did not approve actual worker activation, credentials or charges**.

The new `eval_lane/isolation_probe.py` reads **only** the current local
Linux process's status, cgroup v2 files and network interfaces. It does not
run shell commands, access provider keys, request model completions, create
directories or alter firewall rules.

Observed requirements:

- effective UID is non-root;
- `NoNewPrivs=1`, `CapEff=0`, `CapBnd=0` and `Seccomp=2`;
- current cgroup v2 enforces `memory.max <= 768 MiB`,
  `cpu.max <= 45%`, and `pids.max <= 32`;
- current network namespace exposes only loopback;
- fail closed for missing/unreadable files, unlimited cgroup quotas,
  malformed control values and symlinked pseudo-files.

The probe prints structured JSON with `status=OFFLINE_OS_CONTROLS_OBSERVED`
or `NO_GO`. In **both** cases it explicitly records:

```json
{
  "actual_outbound_deny_test": "NOT_PERFORMED",
  "provider_cost_cap": "NOT_VERIFIED",
  "live_model_execution_allowed": false
}
```

This is a read-only observation, not an independent egress deny test,
complete security attestation or runtime permission. A systemd unit's
configuration, even combined with this probe, must not be represented as
proof until executed on the intended isolated test host.

## Prepared but not installed service example

`deploy/hermes-skill-evals-offline.service.example` is deliberately **not**
a systemd unit installed by `deploy/hermes-main-deploy.sh` or GitHub
Actions. It has no `[Install]` section, so it cannot be enabled as-is.
It includes:

- `User=hermes-evals` (dedicated non-production OS identity);
- `PrivateNetwork=yes`, `IPAddressDeny=any` and
  `RestrictAddressFamilies=AF_UNIX` — **all model API calls remain blocked**;
- `CapabilityBoundingSet=`, `NoNewPrivileges=yes`, restrictive
  syscall/service sandbox settings and private home;
- cgroup CPU/memory/tasks limits matching the probe;
- a condition path requiring an explicit separately authorized offline smoke.

The example executes **only the read-only probe**, not a model, not the
ADT runner and not a shell. It does not create a listener, alter H-01
systemd, add a provider secret or expose a remote execution capability.
Do not copy it to the live VPS during the H-01 #33 protected acceptance
period or install it without a separate owner approval.

```bash
# Safe to run against your own current process, with NO infrastructure changes:
python3 -m eval_lane.isolation_probe
# Exit 0 means observed offline conditions, NOT approval for live model calls.
# Exit 2 means missing/insufficient evidence (expected on an ordinary shell).

# Safe CI / local synthetic fixtures:
python3 -m unittest tests.test_h15_offline_isolation_probe -v
```

## Next gate: real, independently observed offline smoke

1. Owner approves a specific **disposable non-production Linux VM** and
   separately provisions `hermes-evals`, exact-SHA read-only source and
   isolated storage without personal data, H-01 access or shared secrets.
2. Before running anything, preserve current #33 timers and active service
   boundaries; record a read-only baseline. Do not change H-01 systemd.
3. Through the approved owner console, inspect `systemd-analyze verify`
   and validate the exact template. Install/run one **offline-only** probe
   after explicit GO; capture the JSON, process UID, cgroup paths/limits,
   service exit and unit properties. The illustrative source template is
   not evidence of a real installed unit.
4. Independently demonstrate that outbound connections are denied and
   private YFC/Second Brain paths cannot be accessed. Do not treat
   `PrivateNetwork` or a `lo` interface listing alone as that test.
5. Stop the probe and remove only its separately installed service,
   identity and disposable state after checking no H-01 timers or WSS
   settings have changed.
6. A **different separately reviewed network-enabled worker** can be
   considered only after exact provider endpoints, enforced per-provider
   hard cost cap, authentication scope, egress proxy/firewall proof,
   approval receipt and budget are specified. Do not weaken the offline
   template's network denial to experiment.

Real Codex/Claude trials and independent result review remain blocked
in [ADT #11](https://github.com/MikeMoore1337/ai-development-toolkit/issues/11).
