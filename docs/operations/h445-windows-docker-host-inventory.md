# Hermes #445 / #454 — Windows Docker PID1 host inventory before repair

**Status:** read-only operator SOURCE ONLY. No owner-host invocation,
Windows host mutation, container restart, access grant, or production deploy
has been performed by this change.

## Why host inspection is necessary

The permanent Windows BRC sandbox is a **Linux Docker container** named as a
Windows device in the Hermes relay, not an original Windows desktop.
2026-10-27 live ChatGPT MCP start_process and list_processes failed with
"Failed to get process ID" and "spawn /bin/sh EAGAIN". The device was still
online; two separate VPS sandbox devices ran shell/file operations normally.
#445 recorded PID ceiling 96 and over 20 PID1-unreaped zombies in earlier
observations. This evidence is consistent with process exhaustion, but
cannot prove the current host Docker launch flags or container identity.

The BRC sandbox is UID 65534, /workspace-only and has no Docker socket. Do
not broaden it to gain host access or kill unrelated processes.

## Read-only operator commands — owner Windows only, NOT yet executed

Stage the exact trusted, reviewed source and verify its Git blob from the
merged release. This operator expects Docker Desktop CLI at the fixed
Program Files/Docker/Docker/resources/bin/docker.exe, not an untrusted
docker.exe found on PATH.

From ordinary Mike PowerShell (not elevated unless the existing Docker
Desktop installation requires it), with the source present:

~~~powershell
$operator = 'D:\Pet-projects\hermes\scripts\h445_windows_docker_inventory.ps1'
& powershell.exe -NoProfile -File $operator -Mode Discover
~~~

Discover performs only a fixed Docker ps -a query, validates all rows,
and prints sanitized candidate IDs if names contain hermes, brc or
h15. Discovery is NOT evidence of identity. If no candidate appears, do
not guess by device ID; reconcile the actual Docker host first.

Select the full **64 lowercase hex** Docker container ID after independently
checking it is the existing Windows BRC sandbox and not a VPS/relay or
another user's container. Then run:

~~~powershell
$containerId = '<exact-64-lowercase-hex-container-id-from-Discover>'
& powershell.exe -NoProfile -File $operator -Mode Inspect -ContainerId $containerId
~~~

No script call will stop, restart, rebuild, modify or exec a container.
The output is compact JSON with actual ID, immutable image ID,
name, running flag, UID, Docker Init, pids and memory limits,
read-only rootfs, privilege flag and mount count only. It intentionally
does NOT request or disclose Docker Env, secrets, volumes' host paths,
entrypoint/command arguments, network credentials, device bearer,
original Windows project content, or private vault.

Some Docker Engine/API versions omit the optional HostConfig.Init key
entirely. A direct multi-field format that includes this key fails with
"map has no entry for key Init". The updated operator checks mandatory
container metadata first, then queries Init separately as an optional
best-effort read. Absent/invalid/unsupported Init becomes
"init":"UNAVAILABLE", "init_probe_status":"UNAVAILABLE", and
"suspected_process_reaping_risk":null — **never false**. A present explicit
true/false remains distinguishable. Docker settings must be checked on
the real host before proposing --init or a container replacement.

For a one-time interactive read-only check **without** staging the operator,
from an ordinary Mike PowerShell session and after selecting the actual
container ID, never print full JSON:

~~~powershell
$docker = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
$id = '<exact-existing-container-ID>'
& $docker container inspect --format '{{.Id}}|{{.Image}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.Memory}}|{{.Config.User}}' $id
if ($LASTEXITCODE -ne 0) { throw 'H445_REQUIRED_METADATA=FAIL' }
# Optional; may fail with missing map key, does not mean Init=false.
& $docker container inspect --format '{{.HostConfig.Init}}' $id
if ($LASTEXITCODE -ne 0) { 'H445_INIT_STATE=UNAVAILABLE' }
~~~

If the operator reports HOLD, exit 2 or malformed metadata, stop; do not
reinterpret failure as a pass. suspected_process_reaping_risk is advisory
only. The tool deliberately emits target_device_verified=false,
rollback_verified=false, host_change_authorized=false, and
changes_applied=false, even after valid Docker inspect.

If an upcoming separately authorized native Windows task needs the
existing restricted Windows PowerShell, open it from Mike's PowerShell:

~~~powershell
runas.exe /user:"$env:COMPUTERNAME\hermes-brc-readonly" "powershell.exe -NoProfile -NoExit"
~~~

This restricted identity is for the revoked original-file read-only
agent, NOT Docker host control. Never run Docker maintenance using that
account. Its original native device stays offline/paused.

## Next gates: controlled, evidence-based PID1 repair

1. **Read-only host baseline:** verify exact container/image, launcher
   (Task Scheduler or Compose), whether Docker Init is true, current
   PID/thread budget and observed PID1 zombie behavior. These are different
   facts: image presence and an online heartbeat do not prove exec.
2. **Rollback contract:** owner-local safe rollback snapshot of old container
   config/mount destinations/identities without revealing secrets in chat.
   Capture exact image and selected native BRC device identity. No overwrite
   of the four original project roots.
3. **Disposable candidate:** use the same pinned agent image and restricted
   UID/capabilities/network/mounts in a disposable no-device container to
   test Docker's built-in --init reaper or reviewed pinned tini, plus
   subtree termination and PID headroom. Do not merely raise --pids-limit
   or broad-kill zombies; zombies adopted by PID1 need proper reaping.
4. **Owner-approved maintenance:** only after host configuration and
   rollback proven, replace exactly one Windows sandbox container,
   preserving BRC device identity and all three permanent sandbox records.
   Do not enable broad host-native shell, production mounts or auto-pair.
5. **Live evidence:** start_process, git/python3/node, session
   termination, no PID1 zombie growth, 3 sequential+concurrent tasks, FS
   negative tests, fresh OAuth and ChatGPT/Codex tool E2E; then scheduled
   maintenance-window Windows reboot/login and reconnect proof.

PASS of the synthetic Windows CI means only that the operator parses and
denies malformed input. It does not prove host PID1 repair,
recovery, image swap, user access, Docker availability or reboot resilience.

## Rollback

This source-only change is reversible via PR revert; does not install a
Windows scheduled task, store an SSH key/token, or write Docker configuration.
For a future real host cutover, use the separate verified rollback procedure
specific to the original container. Do not perform that rollback from the
sandbox or via untrusted remote terminal access. Keep #445 and #454 OPEN
until live post-repair requirements actually pass.
