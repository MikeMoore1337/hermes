# Hermes #454 - source candidate for disabled Linux host installation

**No production host installation has been performed.** The new
`scripts/h454_native_linux_install_off.py` is an owner-console operator for
a future individually approved first-time installation on **either**
Hermes VPS or YFC VPS. It is not a resident agent, SSH operator, key issuer,
owner-authenticated Control Center approval, working original-host MCP route,
or automatic deployment from GitHub Actions.

## Verified scope

1. Accept an exact current approved `main` SHA and independently approved
   Linux bundle SHA-256, protected local install manifest and GitHub archive
   plus checksum receipt from the previously merged source bundle builder.
   Revalidate source TAR with the existing bounded USTAR verifier and
   exact ten immutable source files, without using tar.extractall.
2. Render the existing hardened `PrivateNetwork=yes`, `Type=oneshot`
   **offline preflight** unit, with **no [Install] section** and no start,
   login, device registration, original-file content access or WSS connection.
3. A future *explicitly approved* root interactive console invocation may
   install the verified source files read-only under
   `/opt/hermes-commander-native/releases/main-<SHA>`, write the unit
   `/etc/systemd/system/hermes-commander-native-preflight.service`, and
   create a root-owned mode-0600 receipt under
   `/opt/hermes-commander-native/receipts`. Existing files/services must
   remain untouched; creation is exclusive and failures roll back only newly
   created artifacts. `systemctl daemon-reload` occurs, but **never**
   `start`, `enable`, `useradd` or a generic shell.
4. For rollback, require the **exact same verified** source, unit, receipt
   and inactive status before removing only the unit/release. Retain the
   original protected receipt for audit. Never remove service accounts,
   original code, production data, BRC/WSS state or unrelated services.

## Required host preconditions - owner action LATER

- Trusted host inventory establishes real original-Linux roots and existing
  users/services. Nothing may be inferred from Docker sandbox paths.
- A privileged OS operator separately provisions the fixed non-login
  `hermes-commander-native` account and root-owned safe
  `/opt/hermes-commander-native/{releases,receipts}` directories.
  The disabled installer refuses an absent or privileged account.
- The bundle has **NO publisher signature**, so its checksum alone is not
  provenance. Before any root execution, independently authenticate the
  exact GitHub Actions artifact and the owner-approved digest. Never
  execute a downloaded archive merely because its receipt matches.
- The owner sees a **separate** concrete host change preview and explicitly
  authorizes the exact target, SHA, digest, service SID/UID, unit, root
  paths and rollback. The CLI's root-TTY challenge is an additional
  local confirmation, **not** a remote owner-authentication mechanism.
- Existing source-deploy SSH cannot install systemd services. A separately
  restricted per-host SSH/bootstrap operator is still needed for the
  preferred GitHub Actions method; don't reuse `HERMES_DEPLOY_KEY`.
- `device.json` and real pairing are not created by OFF installation.
  The unit is not enabled or started; the future native agent will require
  separately reviewed egress confinement, real revocation and original-host
  negative checks.

## Test evidence

`python3 -B -m unittest -v tests.test_h454_native_linux_install_off`

Tests perform actual exclusive file creation/rollback in disposable
temporary directories, include wrong SHA/target/manifest and outside-root
symlink/overwrite denials, and verify no process/service installation on
the owner's hosts. CI tests are not privileged production acceptance.

Until the owner has separately authorized and completed installation,
the statuses are `NATIVE_LINUX_HOST_INSTALL=NOT_RUN`,
`NATIVE_DEVICE_PAIRED=NO`, `ORIGINAL_HOST_E2E=NOT_RUN`.
**Issue #454 remains OPEN.**
