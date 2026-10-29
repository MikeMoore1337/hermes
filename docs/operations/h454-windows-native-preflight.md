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
