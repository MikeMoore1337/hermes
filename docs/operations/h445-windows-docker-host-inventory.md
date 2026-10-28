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


## 2026-10-28 owner real disposable Docker init acceptance

The owner verified exact source Git blob
1280640bf71e77acccbfc3807063fd04eea8a8d8. The sole separately
approved Windows trial with -Mode Test -OwnerApproved returned
H445_DISPOSABLE_INIT=PASS and H445_TEST_EXIT=0, no network or mounts,
process init/reaper fixture PASS. Direct original container inspect
before vs after test showed exact unchanged container identity, image,
running state, StartedAt and RestartCount.

A separate owner-host Docker read-only ps -a ancestor filter returned
H445_DISPOSABLE_CLEANUP=PASS and H445_ORIGINAL_CONTAINER=PRESERVED.
Thus the temporary image-matched trial container was actually removed.
This is **not** approval for re-creating the running original sandbox,
nor evidence that BRC force_terminate cleans a process tree.

## Original Windows launcher and Docker configuration snapshot

The original pinned image is present, the launcher PowerShell SHA256 is
55EA1245671C8B656A3BBA944945198350668B2920CD46E36ED7CBA56637317E
and 26893 bytes; the target has exactly one mount and its task is
HermesH15BRCWindows. A protected local backup is still REQUIRED before
maintenance and must NOT be uploaded to GitHub, a model or a remote VPS.

The reviewed SOURCE ONLY helper
scripts/h445_windows_local_rollback_snapshot.ps1 defaults to
-Mode Preflight (read-only). It checks the exact task action file hash,
Docker ID/name/image/PIDs/memory/nonroot UID/one mount/restart policy,
and immutable image availability, without showing the action, secret
environment or host volume paths. It refuses any mismatch and refuses
a previously existing backup directory to avoid overwrites.

Its separate -Mode Backup -OwnerApproved requires specific additional
owner authorization to create **one new directory** under the owner's
LocalAppData, named HermesH445Rollback-20261028. Windows ACLs restrict
directory and file access to the owner SID, SYSTEM and Administrators.
That directory will contain exactly these files, readable ONLY locally:

- launcher.ps1 — an exact copy of the original host launcher script
- scheduled-task.xml — private Task Scheduler action/trigger/principal
- container-inspect.json — PRIVATE Docker inspect including original
  environment values and mount source paths; never paste or commit
- manifest.json — local SHA256 checksums of the captured files and
  immutable Docker identifiers

Do not run Backup until the owner approves this local sensitive
snapshot. The tool never changes Docker, the task, existing project
roots, the relay or the private Win32 device; it does not install a
new agent. Preflight expected receipt includes
H445_BACKUP=PREFLIGHT_PASS, H445_BACKUP_FILES_CREATED=FALSE and
H445_ROLLBACK_VERIFIED=FALSE.

A future successful Backup means only that an ACL-protected source
snapshot exists and its hashes match. It is **not** yet a rehearsed
restoration. The existing BRC token/device identity must remain intact;
the actual launcher/cutover plus rollback procedure must be reviewed
and verified separately before any original-container maintenance.


## 2026-10-28 owner restore-evidence match and next gate

Owner Windows local source backup completed under separate specific approval:
H445_BACKUP=PASS, H445_ACL=PROTECTED, H445_BACKUP_FILE_COUNT=4,
H445_LAUNCHER_HASH=PASS, H445_ORIGINAL_CONTAINER_UNCHANGED=PASS,
H445_ROLLBACK_VERIFIED=FALSE. Owner separately read back the four local
files without exposing their private contents, verified protected
directory access controls and checksums: H445_BACKUP_FILES=PASS,
H445_BACKUP_DIRECTORY_ACL=PROTECTED, H445_BACKUP_CHECKSUMS=PASS.

Owner then independently matched the backup against the live Docker
container and Task Scheduler metadata, without changing either:
H445_BACKUP_ACCESS=PASS, H445_DOCKER_CONFIG_MATCH=PASS,
H445_TASK_CONFIG_MATCH=PASS, H445_RESTORE_EVIDENCE=PASS,
H445_ROLLBACK_EXECUTION=NOT_TESTED,
H445_ORIGINAL_CONTAINER_CHANGED=FALSE.

These results establish that a protected snapshot of the unchanged
original state was captured and is readable. They **do not** establish
that recreation and actual rollback can run successfully. The Docker
mount's source and OS-specific reattach semantics, device bearer
registration, transient host dependencies and BRC process-tree
termination remain distinct verification gates.

New SOURCE ONLY read-only probe:
scripts/h445_windows_restore_readiness.ps1. It is designed to run only
on the owner's Windows Docker host with the already captured local
snapshot; it does not create additional backups, invoke Docker run,
stop, restart, remove, exec or change Task Scheduler. It checks the
private manifest/checksums, saved vs live Config/HostConfig/Mounts,
live task XML and known resource/security contract, reporting only
fixed non-secret receipts. It NEVER prints task XML, local paths,
mount source, environment, credential or container inspect JSON.

After pinned-source integrity verification, invoke locally:

~~~powershell
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $file
'H445_RESTORE_READINESS_EXIT=' + $LASTEXITCODE
~~~

Even SNAPSHOT_CONSISTENT emits
H445_MOUNT_REATTACH=NOT_VERIFIED,
H445_DEVICE_IDENTITY_REATTACH=NOT_VERIFIED and
H445_ROLLBACK_EXECUTION=NOT_TESTED. Failure is HOLD with exit 2.
The probe is not a substitute for an operator-approved
recovery plan, bounded maintenance window, or live ChatGPT/Codex
acceptance. Original Windows native read-only presence remains paused.


## 2026-10-28 --init cutover feasibility and reversible maintenance contract

The source-only operator `scripts/h445_windows_init_cutover_preflight.ps1`
is a **READ ONLY** Windows-owner gate. It uses the existing protected four-file
snapshot, validates its ACL, manifest checksums, immutable image and launcher
hash, and compares live Docker `Config`, `HostConfig`, `Mounts`, and
Task Scheduler XML against the original. The `Config.Env` comparison
preserves sensitive BRC registration material **by equality only**; no Env,
host paths, launcher source, task action or token is printed.

A PowerShell AST structural check requires exactly one recognized direct
`docker run` command site and no literal `--init` argument at that
site. Passing this check does NOT establish that dynamic/splatted Docker
options can be safely patched, that the original container has no init,
or that the future host launch will work. Other launch forms fail closed
with `LAUNCHER_AST_REQUIRES_MANUAL_REVIEW`. Never attempt a textual
search-and-replace or run a private launcher solely from these findings.

After reviewing the immutable Git blob of the source (on Windows owner
PowerShell), run without elevated privileges:

~~~powershell
$operator = 'D:\Pet-projects\hermes\scripts\h445_windows_init_cutover_preflight.ps1'
& powershell.exe -NoProfile -NonInteractive -File $operator
'H445_INIT_PLAN_EXIT=' + $LASTEXITCODE
~~~

Only a sanitized receipt may be shared. A PASS says snapshot/config equality
and static call-site structure were observed. It emits
`H445_CUTOVER_AUTHORIZED=FALSE`,
`H445_DEVICE_IDENTITY_REATTACH=NOT_VERIFIED`,
`H445_ROLLBACK_EXECUTION=NOT_TESTED`. Exit 2 is a hard HOLD.
The operator never creates, stops, renames or replaces a container,
does not edit scheduled tasks or backup files, and is not a rollback.

### Reviewed, separately authorized single-container maintenance sequence

This is an **operator review checklist, not a runnable command sequence**.
All stages require a new explicit scope-limited owner approval. Until then
the original Docker container and Scheduled Task remain unchanged.

1. Confirm the existing snapshot with both read-only gates, original image
   locally available, full immutable old Docker ID, old device ID observed
   via BRC, exact task launcher hash and one-mount topology. Record the
   other two sandbox IDs and statuses without treating heartbeat as exec.
2. Review the private original launcher locally on the Windows owner host:
   identify the actual Docker run argument construction, network, image,
   volumes, env/registration sources, labels, UID, cap-drop, no-new-privileges,
   read-only filesystem if configured, PIDs=96, memory=512MiB, CPU, restart,
   entrypoint and Task Scheduler action. Confirm the only intentional
   candidate change is addition of Docker `--init`, without privileged
   mounts, Internet, identity reset or altered token storage. Keep the
   original launcher, task XML and inspect snapshot protected and intact.
3. Prepare an independently audited candidate launcher **only locally**,
   with a semantic comparison against the old effective Docker arguments.
   Do not edit or activate the scheduled task while the original remains
   running. If the launcher contains destructive cleanup, autoremoval or
   hidden branching, HOLD for a dedicated manual recovery plan.
4. During an explicitly approved maintenance window, quiesce exactly the
   Windows sandbox, preserve the OLD container object for rollback (do not
   delete it), ensure old and candidate are never simultaneously attached
   as the same BRC device, then start the candidate from the pinned image
   with the original validated configuration plus `--init`. A conflicting
   Docker name must be resolved with a documented reversible rename; verify
   effective HostConfig, Mounts and Config locally before client acceptance.
5. Prove Docker Init=true from the actual NEW container inspect and verify
   saved-vs-new equality for relevant effective settings except deliberately
   changed Init. Independently prove that ChatGPT and Codex observe the
   same original BRC device ID, authentication and connection, and that both
   can execute bounded file+process tools. Verify resource limits, nonroot,
   negative access to protected paths, process subtree termination, PID
   headroom, and that the Hermes/YFC VPS sandboxes are unaffected.
6. On any failed identity, safety or execution gate: **rollback before
   further work**. Stop/remove only the NEW candidate, revert the task/
   launcher to the byte-identical private backup, restore the OLD
   container's original Docker name and run state, and independently
   reverify the original BRC device ID and security contract. The ability
   to restart the old saturated-PID container is NOT yet proven; therefore
   do not begin maintenance until this failure mode and a recovery path
   have been explicitly accepted. Do not claim rollback PASS from hashes.
7. If acceptance passes, retain rollback evidence through a subsequent
   separately approved Windows reboot/login and scheduled task auto-reconnect
   test. Only after the result is verified may the obsolete old container be
   considered for removal under another approval.

Current status: snapshot equality PASS (owner evidence); disposable
no-network/no-mount `--init` trial PASS; actual launcher rewrite feasibility,
mount reattachment, device-ID reattachment, original-container rollback
execution, cutover and reboot E2E all **NOT VERIFIED**. #445/#454 remain OPEN.


## Owner read-only launcher AST HOLD diagnostics (2026-10-28)

The first local preflight of `scripts/h445_windows_init_cutover_preflight.ps1`
from merge `e5ef9a6` passed exact source Git blob integrity but returned
`H445_REASON=LAUNCHER_AST_REQUIRES_MANUAL_REVIEW`, exit 2.
This gate only means that the private launcher does not match the first
narrow PowerShell AST model (or a literal init token was found); it is NOT
evidence that the launcher is broken or that the old container changed.

The source-only next revision emits five bounded enumerations on that HOLD:
`H445_AST_EXPLICIT_RUN_SITES`, `H445_AST_DOCKER_LIKE_CALLS`,
`H445_AST_DOCKER_INDIRECT_CALLS`,
`H445_AST_DOCKER_SPLATTED_CALLS`, and
`H445_AST_LITERAL_INIT_TOKENS`. Each value is exclusively
`ZERO`, `ONE` or `MULTIPLE`; never a private identifier, argument,
path, source excerpt, token, registration URL or environment value.
Static AST is only advisory because the actual command and flags can be
assembled dynamically, in other functions, or through a wrapper.

The operator still checks the ACL-protected four-file local backup,
manifest hashes and pinned Windows launcher, live original container,
immutable image, `Config/HostConfig/Mounts` and scheduled task equality.
It cannot authorize or perform any host/container change. If a dynamic
or unrecognized Docker invocation remains, **keep HOLD** and design a
separate owner-local review with no private data leaving Windows.
No automated search/replace of `--init` and no private launcher upload.

For owner rerun: download the specific reviewed main commit via HTTPS,
check the exact Git blob, and run the file in ordinary owner PowerShell
as in the prior read-only procedure. Share only `H445_*` receipt lines.
Do not paste the private launcher or backed-up Docker inspect.
The original container must remain running and unchanged.


## 2026-10-29 owner AST inventory after multiple Docker calls

The owner re-ran the pinned read-only init feasibility gate on Windows.
Exact blob integrity PASS. The source-only AST counters returned:
explicit Docker run sites MULTIPLE; Docker-like calls MULTIPLE;
other/indirect Docker calls MULTIPLE; splatted calls ZERO; literal
`--init` tokens ZERO. Result: `H445_INIT_PLAN=HOLD`,
`H445_REASON=LAUNCHER_AST_REQUIRES_MANUAL_REVIEW`, exit 2,
`H445_CUTOVER_AUTHORIZED=FALSE`, rollback NOT_TESTED.

Important: the older `DockerIndirectCalls` bucket also includes
ordinary non-run Docker commands; it does NOT establish multiple
indirect launches. The available evidence does not identify which
`docker run` site actually creates the original device, or whether
the flags are supplied through runtime variables. Never apply a
blind textual `--init` replacement across every site.

New source-only READ ONLY helper:
`scripts/h445_windows_launcher_sites_inventory.ps1`.
It reads ONLY the already-existing four-file protected LOCAL Windows
backup, verifies directory ACL and manifest/checksums including the
exact original launcher SHA. It parses that copy via PowerShell AST
without invoking its code or accessing Docker. It prints only a bounded
count (max 12) and fixed `YES`/`NO`/context classifications for each
direct `docker run` site: function vs top-level, enclosing conditional,
literal `--name`, mount, environment, network, `--init`,
`--rm`, dynamic variable argument and splatting. Any discrepancy
fails closed. No command arguments, environment values, task XML,
launcher source text, private paths or tokens are printed or uploaded.

After verifying the immutable source Git blob, run in the ordinary
owner Windows PowerShell:

~~~powershell
& powershell.exe -NoProfile -NonInteractive -File $file
'H445_LAUNCHER_SITES_EXIT=' + $LASTEXITCODE
~~~

Only paste the sanitized `H445_*` receipt lines. A successful
inventory is static source evidence **only**, not execution-path
verification. Exact dynamic Docker arguments, pairing preservation,
original rollback execution and single-container `--init` maintenance
are still held behind separate owner approval. Do not stop the original.
