# H454 Stage 2A - genuine Windows SCM executable (OFFLINE)

**Scope: SCM lifecycle only. Source candidate, not a signed installer or active native host agent.**

`deploy/h454/native-windows-service/` contains a self-contained .NET 10
Windows x64 Service Control Manager executable using documented native
Win32 service APIs. It has **no third-party packages**, network client,
filesystem operations, token storage, process/shell, registry, UAC, service
installation APIs, owner-directory access, or MCP registration.

- Service key: `HermesCommanderNative`. Proposed future identity:
  `NT SERVICE\\HermesCommanderNative`; this code does NOT create it.
- The binary exposes only `--self-test <exact 40-hex source SHA>` and
  `--service`; direct invocation of `--service` without SCM refuses.
- Under SCM it reports START_PENDING and then deliberately STOPPED with
  `NATIVE_NOT_PROVISIONED=454`, never RUNNING, because no owner-approved
  identity, ACL, DPAPI state, native pairing or relay routing exists yet.
- Build must be pinned to the GitHub SHA. SHA is **source version metadata**,
  not a code signature or owner installation approval.
- Windows Actions compiles the real EXE, validates correct/wrong SHA and
  direct-service refusal, then creates a **disabled** disposable SCM service
  under LocalService only on Microsoft's temporary hosted Windows runner,
  verifies Disabled/Stopped, changes **only this disposable CI fixture** to
  manual start, starts it once and requires a real SCM refusal with
  `ERROR_SERVICE_SPECIFIC_ERROR=1066` and `NATIVE_NOT_PROVISIONED=454`.
  It then resets Disabled and deletes the service in a finally block.
  No owner Windows system is contacted. LocalService on a CI fixture is
  not the proposed owner-PC service SID.
- The workflow deliberately publishes no unsigned service EXE artifact.
  No Windows runner permission can change the user's original PC.

## Required before any user-PC installation

1. An actually reviewed GUI installer with immutable binary/source
   provenance and appropriate Authenticode signing. Do not bypass
   SmartScreen or claim the SHA-256 receipt is a trusted publisher.
2. The installer must create the disabled service under an approved,
   non-admin `NT SERVICE\\HermesCommanderNative` virtual identity;
   verify exact service executable and service DACL, source location,
   ProgramData ACL, Windows SID, profile/DPAPI CurrentUser identity,
   service privileges and rollback. LocalService is **not** acceptable
   for the actual owner-PC deployment.
3. Fresh owner-authenticated pairing with existing Hermes MCP, actual
   server-side revocation and a working confidential relay transport.
   The original paused/revoked Win32 identity must remain revoked.
4. Only then consider a separately reviewed runtime implementation
   integrating Win32 handle-bound READ, DPAPI, owner/OS trust gates and
   bounded existing WSS. A service that enters RUNNING without these
   controls is a security regression. Original-host writes/processes
   require separate one-use authorization and OS sandboxing.

This source can merge without granting any new host access. On all three
owner machines: `NATIVE_HOST_PASS=NOT_RUN`,
`PRODUCTION_NATIVE_DEPLOY=NOT_RUN`, `RUNTIME_NO_GO`. Keep #454 OPEN.

## Real OS service admission (source, still disabled)

The Windows SCM binary now calls NativeHostAdmission before it can
ever proceed beyond START_PENDING. The actual Windows logon token user
SID must match NT SERVICE\\HermesCommanderNative. A LocalService or SYSTEM
process running under the same service key is refused with 1066/455.
The owner and protected ACL of the private ProgramData/HermesCommanderNative
directory and two private manifest/device files are inspected through
Windows FileSystemAclExtensions. Broad/inherited rules and junction or
reparse targets are refused. Each of the five owner-approved original
project root DIRECTORY handles must be kernel-readable but not openable
with FILE_ADD_FILE. No content reads, account changes or write operations
are performed by these checks.

Even if all these OS checks succeed, the service reports 1066/456
(NATIVE_RUNTIME_NOT_READY) because a full authenticated BRC device
worker, DPAPI service identity and live revocation integration still
must pass separate gates. No source-only check activates a service.
On disposable Windows CI the LocalService fixture proves refusal 455;
the actual virtual-account MSI CI must still refuse 454 when no private
state exists. Real original PC and VPS checks remain NOT_RUN.


## Corrected private NTFS DACL admission (2026-11-10)

Security audit identified a critical missing negative condition: an explicit
private state service ACE containing ReadData AND WriteData could previously
satisfy the weaker ReadData-only test. NativeHostAdmission now refuses
any service SID ACE granting write, append, create, delete, ownership,
permissions changes or execute rights, even if the same ACE also contains
ReadData. SYSTEM and Administrators remain trusted for maintenance only.
The DACL must be protected from inheritance, allowlisted exactly by SID and
owned by SYSTEM/Administrators.

The existing Win32 original-root preflight also checks denial of
FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_WRITE_ATTRIBUTES, DELETE,
WRITE_DAC and WRITE_OWNER kernel access-open requests, rather than
testing only creating a file in the directory. All are OPEN_EXISTING
metadata-rights probes, never file writes or content reads.

A dedicated C# fixture on an ephemeral GitHub Windows runner constructs
actual in-memory Windows DirectorySecurity/NTAccount descriptors and
asserts Read-only ALLOW plus write/create/execute/ACL/owner/inherited/world
DENY cases. This is genuine Windows ACL API behavior, but still not real
owner-PC service/children permissions acceptance. No host installation,
PowerShell ACL modification, BRC/WSS activation or signer release occurs.


## SCM launches the owner-paired worker only after real OS and signed receipt gates

The SCM service contains a supervised Windows worker lifecycle. It does not
enable, start, pair or install itself. A separately approved manual start
must pass all of these checks BEFORE it launches the bundled worker:

1. Actual Windows service process user SID matches
   `NT SERVICE\HermesCommanderNative`. ProgramData/HermesCommanderNative
   must have protected non-inherited ACL and three read-only state files:
   `manifest.json`, `device.json`, `signed-release.json`.
2. Kernel OPEN_EXISTING checks deny write/create/delete/owner rights on
   all five explicitly approved original project root directories, on
   the installed worker binary and on the Program Files install folder.
3. The protected signed-release receipt, originally emitted only after
   SignPath triple-Authenticode verification, pins the exact running
   service SHA-256 and frozen worker SHA-256 to the source commit.
   Its signature-valid flags are NOT live PKI checks. A trusted owner
   install must independently validate actual signatures and install
   the receipt with the correct service read-only ACL. The service cannot
   create or modify it.
4. SCM launches one fixed `HermesCommanderNativeWorker.exe` from Program
   Files via ProcessStartInfo (no shell, custom executable path or caller
   supplied token/URL/argv), with a minimal environment. The worker
   inherits the nonadministrator service identity, checks DPAPI
   CurrentUser and current owner-bound BRC revocation and uses existing
   Win32 handle-bound native READ only.
5. Only a validated authenticated BRC WSS `welcome` triggers the
   exact `H454_NATIVE_BRC_SESSION_READY=YES` child stdout marker.
   SCM reports SERVICE_RUNNING only after that marker and rechecking
   SID, ACL and root access. STOP/SHUTDOWN terminate and reap the child.
   No unpaired/offline/revoked/fake reply can imply RUNNING.

Hosted Windows CI compiles the real service and a standalone C#
signed-release receipt rejection harness. The MSI remains disabled and
unsigned until owner-approved signing. No owner-original host acceptance
has been performed. A positive real native READY requires protected
owner credentials and a functioning relay, never a synthetic CI PASS.
