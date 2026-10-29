# H454: protected owner-Windows init-candidate preparation

This extends the **read-only** candidate parity gate merged in PR #663.
The original Windows BRC device must remain online. The old incomplete
candidate is deliberately retained STOPPED. No re-pair, secret rotation, VPS
operations, Windows task mutation or Docker start/stop/replacement is allowed.

## Why the candidate is different from a working agent

Original private Windows launcher uses Docker --read-only with two tmpfs
mounts (/run/brc and /tmp), and a separate DPAPI credential-staging step.
The original image waits at most 90 seconds for /run/brc/ready before
starting the agent; a direct docker start without staging exits 2.
The previous stopped --init candidate omitted both tmpfs mounts, making
it unusable even though its ordinary workspace bind matched.

## Owner Windows operator

After the exact main revision passes Windows CI, use the same Windows
user who installed the agent. Existing Python 3.14 and Docker Desktop
are sufficient; no pip, Docker SDK, API keys or additional subscriptions.

READ-ONLY, no container changes:

    py -3.14 -B scripts/h454_windows_prepare_init_candidate.py

On a verified preflight PASS, the **already approved, non-disruptive,
stopped-candidate-only** create step may be run:

    py -3.14 -B scripts/h454_windows_prepare_init_candidate.py --create --owner-approved

The operator refuses anything except exact, pinned original container,
image, non-root UID, image-provided env/labels and entrypoint, source mount
corresponding to the owner workspace, bridge network, 1 CPU, 512 MiB,
128 PIDs, read-only rootfs and hardened capabilities. The image and
container must already exist. It creates exactly one new container
named h454-init-stage-571a1e2b-v2 using docker container create with
--init, both exact tmpfs options, and otherwise original launcher flags.
It does NOT START any candidate or stop the original.

No credential content, DPAPI key, original mount path, Docker inspect JSON,
SSH endpoint, or stderr is printed. If preflight or post-create parity
fails, it prints only safe error codes and retains any stopped candidate
for further manual inspection. The command refuses an existing v2 candidate.

Then **read-only** independently inspect the v2 candidate using the
previously merged operator:

    py -3.14 -B scripts/h454_windows_candidate_contract.py --candidate-name h454-init-stage-571a1e2b-v2

A successful config check is **NOT** an approved cutover or evidence that
credential staging, relay reconnection or Windows logon recovery works.

## Test contract

Offline tests (all synthetic; no credentials or Docker calls):

    py -3.14 -B -m unittest discover -s tests -p "test_h454_windows_prepare_init_candidate.py" -v
    py -3.14 -B -m unittest discover -s tests -p "test_h454_windows_candidate_contract.py" -v

CI executes both suites on Windows/Linux with Python 3.11 and 3.14.

## Follow-up release and operations gates

1. Confirm exactly one complete, STOPPED v2 candidate and independent
   read-only original/candidate parity PASS.
2. Validate reversible cutover and original immutable rollback ID.
3. Under explicit owner maintenance approval, perform a **single** switch:
   stop original, preserve rollback, activate v2 with existing encrypted
   owner credential source and live SSH tunnel, stage promptly; rollback
   if ChatGPT/Codex MCP fails. No auto-pair or token rotation.
4. Repair original on-logon Windows launcher to use --init + 128 PIDs
   while retaining tmpfs, exact staging, and fail-closed rollback.
5. Prove Codex Desktop live E2E and owner-controlled Windows login/reboot
   recovery. Keep Hermes #454 OPEN until those are actual evidence.

No new paid API, subscriptions or paid AI model invocations.

## H454 v2 field-diff recovery (non-destructive)

An owner Windows v2 container was **already created** and remains stopped.
Do not rerun `--create`: the operator refuses an existing candidate. An
observed `CONFIG_DRIFT` resulted solely from Docker `container create`
setting `AttachStdout/AttachStderr=True` where original `run -d` stored
`False`. The read-only contract now accepts **only** these exact false-to-true
stdout/stderr differences. It does not ignore stdin, tty, labels,
environment, security flags, mounts or other fields.

Before cutover, inspect the existing candidate **without recreation**:

    py -3.14 -B scripts/h454_windows_candidate_contract.py --candidate-name h454-init-stage-571a1e2b-v2 --diagnose

This emits **field names only**, including any remaining `HostConfig`
difference; do not paste raw `docker inspect` JSON, environment, image
metadata or mount source paths. The last unknown HostConfig difference
is NOT APPROVED and MUST be diagnosed and corrected before proceeding.

Once an exact, safe HostConfig difference has been proven and any subsequent
fix passed CI, rerun the normal read-only contract without `--diagnose`.
Never use the candidate or call `docker start` while any parity gate holds.

## Safe nullable OOM-killer default parity (owner evidence 2026-10-29)

Read-only v2 diagnostics reported `AttachStderr`, `AttachStdout`, and **only**
`HostConfig.OomKillDisable` as different. In Docker Engine this field is
nullable (`bool | null`); `null` and `false` both leave OOM killing enabled.
The comparison now treats ONLY this pair as equivalent after verifying:

- the original is running, the v2 candidate is stopped and never started;
- immutable image, 512-MiB memory limit, 128 PID cap, both tmpfs and other
  existing safety flags match;
- **both** OOM fields exist, and each is exactly JSON `null` or `false`;
- **any** `true`, integer, string, missing field or unrelated HostConfig
  difference is a hard HOLD.

For future candidates the command explicitly specifies
`--oom-kill-disable=false`. Docker's standard OOM-killer protection
remains active; **never** use `--oom-kill-disable=true`.

To verify the **already created v2**, use the exact pinned released source
without rerunning the create command:

    py -3.14 -B scripts/h454_windows_candidate_contract.py --candidate-name h454-init-stage-571a1e2b-v2

A successful parity check is source/config acceptance ONLY; it is not an
owner-approved cutover or a real run of the --init candidate. Keep the
original live device, DPAPI state and the stopped v2 untouched until the
separate rollback/cutover/launcher validation sequence is ready.
