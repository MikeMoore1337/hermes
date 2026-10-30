# H454: verified PowerShell 5.1 preflight and prepared launcher repair

This is recovery preparation for [#454](https://github.com/MikeMoore1337/hermes/issues/454),
not an approved cutover. The original container and stopped v2 are preserved.

## Confirmed failure and fix

On the owner Windows host, PowerShell 5.1 `Get-Command git.exe` and
`Get-Command py.exe` returned multiple `ApplicationInfo` objects. Reading
`.Source` produced an `Object[]`; converting it to a process filename did
not produce an existing executable. `Process.Start` failed with Win32 code 2.
The interpreter also needs launcher-independent arguments.

`scripts/h454_windows_native_preflight.ps1` selects one application, validates
its actual `.Path`, and resolves the real Python 3.14 executable through
`sys.executable`. The process receives `-I -B -`, without launcher-only
`-3.14`. Its fixed UTF-8 stdin probe uses `StandardInput.BaseStream`, supported
by PowerShell 5.1/.NET Framework. Diagnostics expose fixed enums and a nested
Win32 numeric code, never exception messages or executable/credential paths.

Run the preflight directly from a reviewed checkout; it has no Docker,
credential, network, Task Scheduler or container mutation:

    powershell.exe -NoProfile -NonInteractive -File scripts/h454_windows_native_preflight.ps1

Windows CI tests actual PS5.1 child-process execution, UTF-8 and missing-file
failure. Synthetic command discovery exercises duplicate PATH entries and
invalid results. Linux runs only portable source/launcher tests; it is not
evidence of Windows runtime execution.

## Launcher preparation, without installation

`scripts/h454_windows_launcher_patch.py` accepts only the SHA256-pinned
existing private launcher. It writes a **new** `.ps1` with exclusive create:

- both existing Docker create sites gain `--init`, 128 PIDs and an explicitly
  enabled OOM killer; immutable image, memory, mounts and staging are retained;
- the Run path holds an exclusive `runtime.lock` through startup, staging,
  monitoring and cleanup. A cutover must acquire the same lock;
- source and existing output cannot be overwritten; symlink/junction paths
  are refused. No task, container or live launcher is modified or executed.

The candidate contains private configuration copied from the source. Keep it
local and untracked; never paste it or its original configuration in GitHub.
Preparation is not an OS isolation boundary or installation authority.

## Actual host evidence, 2026-10-29

- Independent v2 candidate contract: PASS; init, both tmpfs, immutable image
  and remaining Docker configuration match. v2 is still CREATED/STOPPED.
- Direct Python + real PS5.1 stdin: PASS. The corrected local operator also
  passes its pinned-source contract and independent candidate parity.
- The original remains running and ready. A read-only process sample found
  PID1 `MainThread`, 51 zombies and `pids.current=71` / `pids.max=128`.
  This is a sample, not a stable capacity guarantee.
- The original private launcher still has no init and uses 96 PIDs. The
  prepared copy has a valid PowerShell AST; it has **not** been installed.
- Original scheduled task is Ready with a logon trigger; a Ready task alone
  does not guarantee safe cutover or future recovery.
- The retained October 28 rollback snapshot differs from the live original
  in `HostConfig.PidsLimit`; Config and Mounts match. Keep the old snapshot,
  but capture a fresh protected snapshot before relying on full parity.
- Current SSH listener PID matches local saved state and the process is SSH.
  Its command-line metadata is unavailable in this execution context. The
  strict local cutover gate therefore remains HOLD; do not bypass identity
  checks, stop the original, stage credentials or run `-Apply`.

## Remaining maintenance gate

Before requesting the single disruptive maintenance approval, verify the
existing tunnel executable/forwarding identity in the permitted owner
Windows context, capture and verify a fresh protected rollback snapshot,
pin both prepared files and independently review their exact diff. The
approved operation must explicitly cover task coordination, installation of
the prepared launcher, one active device, candidate start + DPAPI staging,
MCP smoke and fallback to the retained original with **fresh credential
staging after every original restart**. Never use bare `docker start` as
rollback. Preserve the original container, original launcher and task export.

Login/reboot recovery, lasting PID1 reaping, actual rollback, native original
folder grants and new Control Center onboarding remain separate unverified
acceptance. Keep #454 OPEN. No environment keys or paid API are added.

## Container-preserving launcher preparation, 2026-10-30

The installed launcher's Run path removes the existing managed container
before recreating it. `scripts/h454_windows_launcher_preserve.py` prepares a
separate copy from the exact installed launcher hash; it does not install or
execute that copy. The prepared Run path validates pinned image and container profiles,
retains the existing container ID across a stop/start, and uses the local Docker
Desktop pipe. If the container is missing, it creates it stopped, validates the
result and only then starts it. Profile or identity drift fails closed. A
profile hash is an input to preparation, not proof that the profile is safe.

On the owner host, the current running container was compared read-only with
the protected pre-rollout snapshot plus the approved search-image labels. Its
profile hash and image ID were captured in an ACL-protected, untracked candidate. PS5.1
read-only checks found the actual container and correctly handled an absent
name; a retained stopped container also matched its pre-stop profile. Fixture
tests cover preservation, creation, drift, name races and real PS5.1 native
stderr handling without Docker mutations. The private candidate is not an
installed launcher or a runtime acceptance result.

The complete Run path, real missing-container creation, credential restaging,
SSH recovery, Task Run, login/reboot and rollback remain NOT VERIFIED. A later
installation or disruptive recovery test needs its own concrete owner gate and
rollback plan; no original Windows folder permissions are changed. A later
image change also needs a newly prepared and separately approved launcher.

## Later owner-authorized read-only recheck, 2026-10-30

PR #676 merged as `f6e64acd40fb413bb1c4d8945b5fd284bc0d02f8` after all
five head checks passed. Exact-main repository and Windows/Linux matrix
checks passed; [source production deployment](https://github.com/MikeMoore1337/hermes/actions/runs/40955932347)
succeeded. This delivers the repository/release snapshot, not a BRC image,
launcher installation or runtime activation.

The owner then approved one hash-pinned **read-only UAC** preflight.
It returned `H454_PS51_STDIN_SELFTEST=PASS`, `H454_PARITY_RECHECK=PASS`,
`H454_TUNNEL_PREFLIGHT=PASS`, `H454_NON_MUTATING_PREFLIGHT=PASS` and
`H454_READY_TO_APPLY=PASS`, with `H454_ORIGINAL_CONTAINER_CHANGED=FALSE`
and `H454_CUTOVER=NOT_PERFORMED`. Ordinary-context missing command-line
metadata was an access limitation, not a proven wrong tunnel.

A new protected five-file rollback snapshot now matches the current
original Config/HostConfig/Mounts. The older snapshot is retained.
Independent rollback preparation checks are synthetic only: stop candidate,
start original, stage original credentials again, verify original; a staging
failure must remain HOLD. Actual rollback and DPAPI staging are NOT TESTED.
Stopping BRC, installing the prepared launcher and changing the task still
require the separate concrete maintenance approval. No reboot or native
original-folder permission is implied by the read-only UAC approval.

## Approved Windows delivery, 2026-10-30

The owner approved the bounded Apply/Install window and conditional rollback.
The init candidate is now active with existing credential staging and the
same device identity; the original is retained stopped. Real MCP UTF-8
file/process checks passed. Two orphan children reported PPID=1 and were
reaped; zombies=0 on samples at 35 and 199 seconds. Fixtures were removed.
This is bounded reaping evidence, not a lasting burn-in guarantee.

The prepared launcher was installed atomically; its exact hash and original
backup were verified. Task XML/settings and device-state bytes remain
unchanged, SSH unchanged, no reboot or native grant. Actual rollback was not
needed and did not run. [Delivery receipt](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6515625089).

Source main `01b9573b36ed3c192ad0a761de0b9480e6d07815` was deployed with
3074 server tests; the active agent is still the older immutable image.
The later [minimal edit-error image preparation](h454-agent-edit-image.md)
does not activate that code fix or change this completed window's scope.

## Tunnel preflight before container stop, 2026-10-30

The existing scheduled task reports `RunLevel=Limited`. In the current user
context, the saved tunnel PID and its loopback listener were observable, but
the SSH command line and executable path were not. The installed Run path
stops its container before attempting to stop or restart that tunnel. Actual
Task Run has not been tested, so this observation is a recovery risk rather
than a claim about a completed task execution.

The source-only launcher preparer now adds a tunnel preflight before the
container stop. It checks the saved PID, local listener ownership, the
expected SSH executable and original target/forward checks, and whether the
process predates the saved state. Missing or mismatched identity fails closed;
an absent saved process and an unoccupied listener can proceed. PS5.1 fixtures
exercise valid, absent, inaccessible, changed and reused-PID cases. A real
read-only check in the current user context returned the expected identity
HOLD and confirmed that the existing container was still running.

This candidate is not installed. The preflight is not an atomic guarantee
against a later PID change, and complete SSH recovery, credential restaging,
Task Run, login/reboot and rollback remain NOT VERIFIED. A separate owner gate
and a tested rollback remain necessary before any disruptive window.
