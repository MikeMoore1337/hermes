# Hermes #454 Stage 2A - new native owner-bound device pairing

## Existing transport; no duplicate MCP server

The existing hardened BRC relay supports device-code OAuth-style pairing:
`POST /device/start` -> pending short owner code,
`POST /device/poll` -> only after authenticated owner authorization,
then `Authorization: Bearer ...` on its WebSocket agent transport.
The new source consists of:

- `device_fabric/native_brc_enrollment.py`: tightly bounded client
  that requests one code, polls only with the opaque device_code, exact
  owner-approved **name** and platform, and **never supplies its own
  device_id**. Once approved it receives a device ID and bearer solely
  in process memory. Names correspond to Windows original, Hermes VPS
  original and YFC VPS original; old revoked Windows identity is denied.
- `scripts/h454_native_owner_pair.py`: exact-target owner operator for
  the existing BRC `device_codes` table on the pinned Hermes VPS.
  Interactive root TTY, verified host/db, privilege drop to
  `hermes-brc-relay`, fresh user-code entry, typed exact confirmation.
  One atomic compare-and-set binds a cryptographically fresh device ID to
  one pending code and the existing unique admin owner. Neither a token
  nor a new device row is made by this operator. The existing relay's
  `/device/poll` creates the device row and returns the bearer privately.

## Security

- **No credentials in GitHub, ChatGPT, command line arguments or logs.**
  A short user code is entered only at the owner-root private terminal.
- The old `h454-win-01335a1f6e6705b4` stays revoked/paused.
  A duplicate target or another pending same-target request refuses.
  Sandbox devices, BRC/WSS DB account state and other pending requests
  must remain unchanged.
- Client must authenticate the relay connection via verified HTTPS or
  an independently verified private SSH forward. A loopback address
  by itself does **not** prove the SSH peer identity. The original public
  WSS path was not accepted as a working host endpoint.
- The pinned upstream BRC `/device/poll` currently lets a client pass
  `device_id` even if the approved row contains a different value.
  **Before live pairing, the relay must enforce the owner-bound ID** and
  reject a mismatched caller-supplied device_id/name/platform. Until
  the separately reviewed source patch and paired BRC/WSS cutover are
  installed, this is a development candidate, NOT live authorization.
- An approved device-code request is not yet proof of the Windows/Linux
  OS service identity, original-root permissions or actual owner consent
  to a specific file/process mutation. Native reads and effects have
  additional independent OS/device gates.

## Rollout (separate owner approvals only)

1. Verify the exact source release and a live host inventory (Windows SID
   and both original Linux roots). Do not guess Docker sandbox paths.
2. Owner installs OS-restricted native service, and approves exact
   pairing endpoint and verified SSH host identity or TLS certificate.
3. Native client obtains a fresh code privately. Owner explicitly
   approves on the trusted original Hermes VPS using the approved
   `scripts.h454_native_owner_pair --target windows|hermes-vps|yfc-vps`
   procedure from an interactive root console. Never paste codes here.
4. The client polls with **no device_id field**, obtains its
   owner-bound fresh ID and bearer in memory, and persists the
   credential in protected local service-owned state (Windows DPAPI,
   Linux mode-0600 under service UID). Then explicitly permit READ-only
   activation under OS confinement.
5. Verify old ID denial, new registration, live native file reads,
   protected-path denials, revocation and 2 clients x 3 original hosts.

No deployment, device registration, root changes or production cutover
occur when merging these source files. Issue #454 stays OPEN.
