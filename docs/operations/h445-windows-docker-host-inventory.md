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


## 2026-10-28 owner PID saturation, safe follow-up

Owner's actual **read-only** Docker Desktop host snapshot:

- Identity: full 64-hex Docker container ID starting 571a1e2bede3 and
  ending f8ea162; name /hermes-h15-windows-permanent.
- Immutable base image: sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3.
- PIDs limit 96, live Docker stats PIDs **96**, headroom **zero**.
- Memory limit 536870912 bytes; UID:GID 65534:65534.
- HostConfig.Init absent/unknown, Docker PID1 reaping **NOT VERIFIED**.
- A read-only docker top request with only -eo stat failed:
  "Couldn't find PID field in ps output". This is a **format error**, not
  evidence of process corruption or absence of zombie processes.
- Last independent BRC process tool probe returned spawn /bin/sh EAGAIN.
  96/96 is sufficient to explain why the cgroup cannot create new tasks;
  zombie attribution and root cause of PID consumption need separate proof.

Docker (Moby) daemon's top parser **requires PID** as a header. The
read-only corrected request uses -eo pid,ppid,stat, never -eo stat alone.
It returns process-state summary **only**; a failure is marked
NOT_VERIFIED, with no PID/PPID, process name, command or argv printed.

For an optional fresh owner-host read-only measurement, securely stage the
reviewed source under the known trusted owner checkout. Use ordinary Mike
PowerShell, **not** the hermes-brc-readonly native-account context:

~~~powershell
$operator = 'D:\Pet-projects\hermes\scripts\h445_windows_docker_capacity.ps1'
$cid = '571a1e2bede31a07638b896e3ef2de677dafa1c000e4a7975e7996257f8ea162'
& powershell.exe -NoProfile -File $operator -ContainerId $cid
'H445_CAPACITY_OPERATOR_EXIT=' + $LASTEXITCODE
~~~

This diagnostic **intentionally returns exit 2** for low PID headroom,
while printing a bounded JSON HOLD receipt. It never creates or terminates
processes, builds images, changes settings, accesses Docker Env/mount paths,
or activates the original Win32 native reader. No new host permissions.

Next **separate owner-gated** step is to verify exact launcher
(Compose, Task Scheduler or explicit docker run) and preserve the original
container's rollback configuration (including mount source paths **locally
only**, never posted into public logs or chat). In a disposable no-device
container prove a proper init/reaper and process-group termination. Only
then consider a single-container maintenance cutover without changing
identity/bearer, root access, 96-PID budget or the 512MiB memory budget.
Real ChatGPT+Codex E2E and Windows reboot/login remain separate gates.


## 2026-10-28 scheduled launcher attribution — read-only gate

Latest owner-host task metadata:

- HermesDevicePresence is a separate LocalService Python boot-triggered
  presence task. DO NOT modify or revoke its registration.
- HermesH15BRCWindows is Ready, Interactive, LogonTrigger, one PowerShell
  -File action (not EncodedCommand), IgnoreNew instance policy. Last ran
  2026-10-24 23:45:54 +03:00; exit 3221225786 / 0xC000013A.
- Target Docker container started 2026-10-24 20:46:01.903Z, about
  eight seconds after the task started. It is still running with
  restart policy=no and restart count=0. This is strong correlation,
  not proof of the launcher script's exact behavior.
- Task NextRunTime null is not proof of error for an on-logon trigger.
- Owner Docker capacity observation: PIDs 96/96, five visible process
  rows, visible zombies zero, aggregate NLWP 67 and max NLWP 42. The
  delta of 29 is unexplained and must not be called zombies.

### Read-only preflight after SHA review

In ordinary Mike PowerShell, after the approved repository source
has been staged in the actual local Hermes checkout:

~~~powershell
$operator = 'D:\Pet-projects\hermes\scripts\h445_windows_task_launcher_preflight.ps1'
& powershell.exe -NoProfile -File $operator
'H445_TASK_PREFLIGHT_EXIT=' + $LASTEXITCODE
~~~

This probe reads the Scheduled Task -File target, hashes its source
without exposing the path, contents or arguments, and does not execute
the target file. Text-only Docker/flag indicators may match comments,
so they do NOT prove runtime execution or authorize maintenance.
The probe verifies the exact immutable original running container and
checks that the original image is still locally available. It always
sets rollback_verified=false, restart_authorized=false and
changes_applied=false. Any unexpected state fails closed.

Do not send the task XML, full Docker inspect JSON, action arguments,
full script contents, environment variables, host volume paths or
private credentials to chat or GitHub. The SHA alone does not mean a
tested rollback exists. Future owner-gated recovery requires the
actual LOCAL launcher and container settings, a disposable init/reaper
and process-tree test, then a single-container cutover and ChatGPT/Codex
end-to-end acceptance. Keep #445 and #454 OPEN.


## 2026-10-28 owner Windows launcher script LIVE verified

The owner independently downloaded the exact release SHA
ea8d93757ee299447aababa79ad149d61d56a980 of
scripts/h445_windows_task_launcher_preflight.ps1 and checked Git blob
6485f245f92c4db4f41775484697ac150d30ff3c. Windows preflight
returned OBSERVED_NOT_AUTHORIZED, exit 0, with:

- launcher file SHA256: 55EA1245671C8B656A3BBA944945198350668B2920CD46E36ED7CBA56637317E;
  launcher script size: 26893 bytes
- textual flags: docker=true; target container=true; run=true; 
  volume=true; env=true; pids-limit=true; init=false
- original pinned image available=true, Docker identity verified=true
- existing container mount count=1
- rollback_verified=false, restart_authorized=false, changes_applied=false

No source file, action arguments, env contents, mount origin or secrets
were exposed in chat or saved in GitHub. This is still *not a rollback*:
the Windows owner needs local backup of the launcher and original Docker
launch settings before any destructive action. Textual absence of an init
flag does not by itself attest to the actual PID1 implementation.

## Disposable no-device reaper trial (owner gate)

New SOURCE-ONLY helper: scripts/h445_windows_disposable_init_trial.ps1.

Preflight is read-only. It checks the exact currently running original
container ID, image ID, 96-PID/512-MiB/UID contract and local image
availability. It does not connect to the BRC relay or read credentials.

Do not run the Test mode without a *separate explicit owner approval* to
create a disposable Docker container on Windows. The intended command
after pinning to a reviewed immutable source SHA is:

~~~powershell
& powershell.exe -NoProfile -File .\scripts\h445_windows_disposable_init_trial.ps1 -Mode Preflight
# Only if the owner separately approves this specific Docker test:
& powershell.exe -NoProfile -File .\scripts\h445_windows_disposable_init_trial.ps1 -Mode Test -OwnerApproved
~~~

Test mode uses only the already local pinned image and a new transient
container with Docker built-in --init, --rm, --pull=never, network=none,
no bind mounts, no BRC device token/env, nonroot UID, read-only rootfs,
no capabilities, no-new-privileges, original PID+memory limits, a
temporary 16-MiB /tmp and an overridden Node entrypoint (not the BRC
agent). It checks a tiny set of orphan children and the absence of
PID1-owned zombies plus 24+ PID headroom. It prints only fixed receipts,
never subprocess arguments or local paths.

PASS proves only the isolated pinned image and Docker init worked in a
single short trial; it does NOT prove the old BRC container has init,
that BRC force_terminate kills descendant process trees, a validated
rollback, Windows reboot reconnect, original Windows host filesystem
access, or full Git/Python workspace parity. An unapproved Test call
must HOLD; a running old container is never stopped or altered by the
trial. No real host trial or original container mutation is part of
the repository merge.
