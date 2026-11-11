# Hermes #454 - first-time native Windows MSI (disabled-only candidate)

**Never run this unsigned candidate on the owner's computer.** The PR
workflow builds the MSI and performs genuine install/uninstall tests only on
a disposable Windows 2025 GitHub Actions runner; it uploads no binary.

This is a minimal x64 per-machine Windows Installer package using pinned
WiX Toolset 6.0.0. The source package is based on the reviewed
HermesCommanderNativeService .NET 10 EXE, which **always fails closed** with
NOT_PROVISIONED=454. It has no original Windows file access, outbound agent
or process execution.

- Fixed service key: HermesCommanderNative.
- Installation account: NT SERVICE\HermesCommanderNative (virtual identity,
  NOT LocalSystem or the owner's interactive Windows account).
- Start mode: disabled. No ServiceControl Start action, no scheduled task,
  no auto-start or additional native files.
- Installs one binary into Program Files / Hermes Commander Native.
- Explicit RegistrySearch + Launch prevents adoption of an existing
  HermesCommanderNative service on first install. This candidate has no
  upgrade/migration procedure; one must be reviewed separately.
- Uninstall stops/removes only the service and the installed EXE.
  No existing BRC/WSS state, vault, original projects or owner keys touched.
- Source SHA check in CI is a metadata guard and not a publisher signature.
  The MSI and EXE remain unsigned, so GitHub Actions must not publish
  their artifacts for execution on the owner PC.

## Production readiness remains HOLD

The official Windows Installer service installation APIs support a
disabled ServiceInstall start state and MSI rollback. However this
source-only fixture is not a signed, visually approved graphical installer.

A real installation still requires: appropriate trusted Authenticode
signatures of the MSI AND service EXE; verified artifact provenance; a
separate owner review of service path/hash/identity and UAC; Windows
virtual service SID and DACL tests, protected ProgramData and DPAPI profile;
fresh owner-authenticated native pairing and revocation via the existing
Hermes MCP; and 2-client x 3-original-host acceptance.

The existing user-approved WinForms picture is a **scope preview**, not
approval of this MSI or host changes. No signing certificate or private
SSH/account credentials are included in the repo. A possible free
SignPath Foundation OSS signing route requires separately verified
eligibility; the repository currently has no declared GitHub license.
No license or external SignPath account is changed by this PR.

Status: SOURCE_ONLY, NATIVE_HOST_PASS=NOT_RUN,
PRODUCTION_NATIVE_DEPLOY=NOT_RUN, RUNTIME_NO_GO. Issue #454 OPEN.

## Existing service collision negative test

After a successful install/uninstall smoke on a **disposable runner**,
CI registers a synthetic, disabled SCM service under the same key but
pointing to a foreign Windows inbox executable. MSI must fail with
exit code 1603 and the explicit LaunchCondition diagnostic, leave the
existing service registration unchanged and avoid installing Hermes
files. The fixture deletes only its own foreign SCM record in a
finally block. No collision test is executed on owner devices.

## Disposable virtual-service startup refusal

On the GitHub-hosted Windows 2025 runner, after installing the disabled
MSI, CI temporarily changes only that disposable service to manual start
and requests one SCM start. The actual MSI-installed
`NT SERVICE\\HermesCommanderNative` identity must reach
`STOPPED` with Win32 exit `1066` and service-specific code `454`.
The fixture resets `Disabled` and uninstalls the MSI in `finally`.
This proves the unprovisioned Windows service **does not become RUNNING**
under its intended account on disposable CI. It does **not** prove that
NTFS ACLs, service SID type, DPAPI user context or native access on the
owner's real PC are configured or safe.


## Bundled original Windows read-only worker

The disabled MSI now installs exactly TWO binaries under the same
Program Files component: the existing .NET SCM service EXE and a
`HermesCommanderNativeWorker.exe` frozen from the source-reviewed one-shot
Python/Win32 read-only worker (PyInstaller 6.22.3, websockets 17.2).
The hosted Windows CI builds the worker, verifies that it refuses
execution under the disposable non-service Windows SID, checks both
files are installed and uninstalled with the MSI, and verifies no
pre-existing service registration is overwritten.

**The current SCM stub does not yet start the worker**, and this MSI remains
unsigned, not uploaded to owner machines and disabled by default. A separate
reviewed service-to-worker lifecycle, protected signed publisher and owner
token/ACL provisioning are required before any live original-host activity.
