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
