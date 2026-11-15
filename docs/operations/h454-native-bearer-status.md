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

## Private TLS status bridge - source candidate (2026-11-15)

The existing BRC relay was independently observed on its internal Docker bridge:
health HTTP 200, anonymous native-status HTTP 403 and anonymous WebSocket
upgrade HTTP 401. The public hostname returned 404 to anonymous requests.
This is not proof of authenticated public access and does not justify
exposing the public WebSocket route.

The private WSS sidecar previously returned 404 for EVERY HTTP request.
The source-only WSS proxy now adds exactly one protected
GET /device/native-status endpoint to the existing private TLS sidecar:

- Existing source-IP and pinned private TLS peer restrictions remain.
  No public listener, enrollment, administration, or generic HTTP proxy.
- Exactly one valid Authorization Bearer brc_dev_ token is required.
  Duplicate credentials, cookies, bodies, changed methods, paths and
  query parameters fail closed before reaching the BRC relay.
- Only /device/native-status is forwarded to the existing loopback BRC,
  where authoritative current owner-bound token status is checked.
- The only forwarded success is canonical schema v1, verified native ID
  and strict owner_bound/active true booleans (max 512 bytes).
  Invalid JSON, redirects, oversized replies and errors fail closed.
  All responses are no-store.
- A synthetic loopback Node.js E2E tests success, rejected/revoked tokens,
  denied admin/enrollment routes and malformed requests. No real token used.

NOT DEPLOYED: this source change does not modify root-owned production WSS
proxy bytes, BRC/WSS containers or Cloudflare routes. A joint deployment
requires its own exact owner approval, preserved checkpoints and runtime
verification. Native Linux still uses public WSS/status endpoints and
public egress policy. Private CA/hostname-pinned client transport, OS
sandbox validation and owner device enrollment remain pending. Issue #454
cannot close on the strength of this source change.

Current original Windows SCM/ MSI remains an inert NOT_PROVISIONED
fixture until the existing Python handle-bound native read adapter,
actual service SID, NTFS ACL, DPAPI bearer and this authoritative
revocation provider are integrated in a signed release.
Hermes VPS and YFC VPS remain Docker-only until their independent
native systemd services, SSH staging/root installation and egress proof.

Issue #454 OPEN, RUNTIME_NO_GO, no owner-host E2E, no production changes.
