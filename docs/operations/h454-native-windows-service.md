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
