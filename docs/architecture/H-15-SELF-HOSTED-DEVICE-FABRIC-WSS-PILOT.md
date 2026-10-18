# Hermes Self-hosted Device Fabric (#297): WSS presence-only pilot

2026-10-18. This extends the [offline spike](H-15-SELF-HOSTED-DEVICE-FABRIC-OFFLINE-POC.md). **No production service, public endpoint, agent autostart, remote shell, user-data access or H-01 tool permission has been activated.**

## Deliverables

- `device_fabric/presence.py`: TLS-only WebSocket presence relay, deliberately restricted to `127.0.0.1`/`::1`. Max message 4 KiB; disabled WebSocket compression; bounded heartbeat/idle; duplicate connections rejected; execution requests denied and never queued.
- `DeviceRegistry`: owner-provisioned SQLite, 0600 database; one-time owner pairing code (expires within 10 min); strong per-device token stored only as SHA-256 hash (token is 256-bit random); owner revoke; last-seen and Online/Offline/revoked, with stale protection for crashed sessions. Local-only write operations; no HTTP pairing, no public control API. Audit event history capped at 1000 entries containing only event/name/time, no contents.
- `device_fabric/read_only_agent.py`: inert library function for an **outbound-only** heartbeat client. Requires `wss://`, OS certificate validation / trusted custom CA and explicit caller-supplied device credentials. No CLI autostart, filesystem, terminal or replay queue.
- `DeviceStatusMCP`: protocol handler exposing only `list_devices` and `get_device_status` via the existing read-only JSON-RPC abstraction. It is not a deployed stdio or network connector yet.
- New isolated, path-filtered `.github/workflows/device-fabric-wss.yml` installs pinned `websockets==16.0` in a CI-only venv (not in host Python/production), runs **eight** real TLS WebSocket tests on an ephemeral loopback listener using ephemeral OpenSSL certificates. Existing offline eight tests also remain.

## Reproduction (non-production machine only)

From the checkout, with OpenSSL and Python installed:

    python -m venv .venv-device-fabric
    .venv-device-fabric/bin/python -m pip install websockets==16.0
    .venv-device-fabric/bin/python -m unittest discover -s tests -p 'test_device_fabric_presence.py' -v

On Windows the venv Python path is `.venv-device-fabric\Scripts\python.exe`. No device registration or real network tunnel is performed by tests.

Test coverage includes: two different emulated outbound clients, mutual session identity, self-signed test CA pinning, refusal of non-validating TLS by the client, refusal of non-loopback binds, one-time/persisted pairing, token revocation during a session, impersonation and duplicate session rejection, heartbeat and offline/reconnect, timeout/stale state, oversized frame rejection, no delayed command replay, and MCP denylist.

## What is **not** implemented

- Public, authenticated WSS via a Caddy owner-approved route and OS-level service isolation; no Caddy/host firewall changes. Opening a real ingress or installing an agent requires explicit approval.
- Multi-process shared live session and guaranteed single-session ownership across *multiple* relay instances (single-process pilot only).
- Actual Windows/Linux device pairing/onboarding CLI, secret-file handling, auto-restart, persistence across restarts of a running agent; #276 remains separate.
- Full owner-only GET API and Control Center panel for the new source; existing Desktop Commander #275 remains independent.
- Any real filesystem/process/write/shell tools, broad H-01 #33 MCP permissions, or access to YFC/Second Brain.

Quota: the self-hosted transport itself has no per-call third-party subscription quota; it still consumes system/Internet resources. Other providers' usage caps are unaffected.

## Next owner gates

1. Approve a specific dedicated service identity and a loopback-only running pilot on Hermes VPS, with separate certificate and paired test identity (no live Windows access). Verify process limits and rollback.
2. Approve a WSS route or VPN endpoint, and pair one Windows agent and one Linux agent **individually**; confirm device identity and offline/stale behavior. No remote command tools.
3. After visually approving the owner-only Control Center integration, consider narrow allowlisted read/list operations. Enabling writes or command execution is a separate owner gate. Never grant H-01 general shell/MCP rights as a side effect.

The current PR may be merged and delivered as a **source-only production release snapshot**, preserving all existing active services and timers.
