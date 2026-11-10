# Hermes #454 - current native device bearer status and revocation

This is an optional **source-only** addition to the existing pinned BRC
relay. It adds one bearer-authenticated GET /device/native-status route in
the same Express process and SQLite store; no new MCP server, container
or network listener is created by the repository code.

For each of the three original native identities, the relay verifies
the exact current device-token hash, stored unique admin owner, name,
platform, new H454 device ID namespace, and paused state. Only the
current non-revoked device bearer returns a tiny no-store reply:

  schema: h454-native-device-status-v1
  device_id: exact fresh original-host identity
  active: true
  owner_bound: true

A missing, rotated, paused, deleted, sandbox, foreign-owner or invalid
bearer is refused with a fixed 403. Query-string tokens are forbidden.
Response is not a permission to run shell or write original files.

The Python client device_fabric/native_brc_status.py uses verified HTTPS
to the pinned origin or an exact loopback URL only with an independent
authenticated SSH tunnel proof callback. It forbids proxy fallback,
HTTP redirects, noncanonical response fields and uncontrolled URLs.
The source exports status_provider(...) and revoked_provider(...)
callbacks to plug into the existing windows_native_reenrollment.run_once
and h454_native_linux_runtime.run_once. Offline fixtures demonstrate
positive current-token read and fail-closed revocation.

**The actual relay route is NOT DEPLOYED by these files.** It must be
shipped with the already pinned BRC cutover only after exact owner
authorization, backup/rollback, private TLS or verified tunnel routes,
and live owner-device pairing. Until then, the status provider refuses
any unreachable endpoint and native services must not activate.
A self-asserted callback is not evidence of OS or server identity.

Current original Windows SCM/ MSI remains an inert NOT_PROVISIONED
fixture until the existing Python handle-bound native read adapter,
actual service SID, NTFS ACL, DPAPI bearer and this authoritative
revocation provider are integrated in a signed release.
Hermes VPS and YFC VPS remain Docker-only until their independent
native systemd services, SSH staging/root installation and egress proof.

Issue #454 OPEN, RUNTIME_NO_GO, no owner-host E2E, no production changes.
