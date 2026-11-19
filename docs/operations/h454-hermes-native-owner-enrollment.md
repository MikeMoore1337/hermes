# H454 Stage 2A - original Hermes VPS owner-bound READ enrollment

**SOURCE ONLY. NO PAIRING, HOST INSTALL, SERVICE START OR ENABLE BY MERGE.**

This candidate follows original-host admission checks supplied by the
owner on November 19, 2026:

- Active unchanged BRC container ID
  `c10587c6bdb51bcbdd4ccea65d5020a6a18deefaa13fb9f9d04eca4661b848d0`,
  image `sha256:3488e1ff44bb0843ecbc62a1951277ccbf118d1f3ba899b7636a66aa84d55e06`,
  internal `hermes-brc-internal` bridge, IPv4 `172.29.251.2`,
  HTTP 3000 *inside* Docker and no host-published ports.
- Original BRC `/health` returned 200 from original root host without a
  bearer, but its `/device/start` and `/device/poll` were **NOT** invoked.
- Actual compiled BRC `app.js` was inspected from the live container:
  `native_pairing_scope_denied`, owner-bound native ID guard, and
  `/device/native-status` guard are present. Structural evidence is not
  an end-to-end approved-device assertion.
- Status-only private WSS proxy running and TLS anonymous 403 independently
  verified, with old WSS rollback checkpoint retained.
- Original restricted Linux native release
  `30db4fbab46626985b078d574dbe0b839872840e`: 0600 service-owned
  READ_ONLY/DISABLED manifest, dedicated UID 972/GID 968; source/dependency
  directories present; private root-owned CA digest and relay IP aligned;
  `hermes-commander-native.service` disabled/inactive; **device.json ABSENT**.

## Why a root-host-only enrollment operator

Existing `device_fabric.native_brc_enrollment.verified_http_post` accepts
only independently authenticated public HTTPS or proven SSH loopback forward.
It does not accept unverified HTTP to the internal BRC bridge. The private
WSS sidecar is an authorization-status-only bridge, not enrollment proxy.

Instead of publishing a new port, changing Cloudflare/Caddy, weakening
`verified_http_post`, or exposing tokens on host-to-bridge HTTP, the
original-host-only operator
`scripts/h454_native_hermes_enrollment.py` plans and (only with a **new
separate owner approval**) pairs one READ_ONLY Hermes VPS device via an
ephemeral, unprivileged `docker exec` and Node HTTP POST **to
127.0.0.1:3000 inside the exact pinned running relay container**.

No bearer or pairing code appears in shell or Docker exec argv, logs,
GitHub or root operator stdout. Bounded Node script and JSON input travel
through Docker exec **stdin**, and replies are returned over captured stdout
to the operator memory, not printed. This starts short-lived non-root Node
processes inside the production relay **only if separately authorized**,
but does not start any new listener, update the image or introduce an MCP.

## Exact preflight and execution

`plan` is read-only and root-only. It checks installed original-owner Git
blobs, exact native source/release identity, native manifest parser,
private trust CA/pins, Docker CID/image/netns/internal bridge with no other
bridge peers, no BRC host port publishing, live `GET /health` 200 without a
bearer, compiled native protection, 0600 service-owned manifest, 0644 exact
systemd unit, no existing or interrupted credential file, and a
disabled/inactive native service. It prints only sanitized status,
manifest SHA256 and booleans, never project roots.

`enroll --execute` is **NOT APPROVED** by green CI or a successful plan.
After fresh explicit owner permission for one original-Hermes-VPS device
pairing, stage an exact source Git blob in an unused root-only 0600 file.
The operator must run as actual root with owner-source
`82a51cc0d718e16e6d0be8869436359a06fc94b7` as `PYTHONPATH` and
require **two real owner-root TTY challenges**:

1. Exact target and native manifest SHA256 *before any POST*.
2. Exact expiring BRC user code before the only owner-approved DB update.

A pending device code is created by existing BRC `/device/start`. After
owner confirmation, a forked child drops to the dedicated BRC
`hermes-brc-relay` UID/GID, then uses existing
`h454_native_owner_pair.pending` + `approve` for a single atomic
compare-and-set of the unexpired `device_codes` row. This binds one fresh
`h454-linux-hermes-<32 hex>` ID to the unique admin owner. It does not
mint a bearer or create a device row.

The existing BRC `/device/poll` is called with **no caller-supplied
device_id**. BRC issues its current bearer only after owner approval,
returned in memory. The operator validates the exact native config
schema and writes a canonical service-owned `device.json` as UID 972,
GID 968, mode 0600, one link. It stages via `O_NOFOLLOW|O_EXCL`,
fsyncs, hardlinks with no overwrite, verifies inode, removes temporary
link and fsyncs. It does not print original project roots, tokens, CA
private keys, code values, or file content.

**The systemd native service remains disabled/inactive.**
Owner-paired bearer 200, revocation, restricted first systemd activation,
original-file read and any YFC/Windows host actions are separate approvals.

If owner approval, network, SQLite CAS, poll, file write or postcheck fails,
the operator outputs `H454_HERMES_NATIVE_ENROLLMENT_HOLD` and
**never automatically retries**. A pending code or an issued but
unpersisted device may require reviewed reconciliation or revocation.
An interrupted file stage remains available for forensic review and
blocks future plans. Do not blindly remove it or reuse a code.
No Docker container is stopped/restarted; no keys or image are changed.

## Current acceptance

- Python local/mock tests: await exact-head GitHub CI.
- Original Hermes owner-root: BRC internal bridge and native trust PASS,
  this new operator's `plan` **NOT_RUN**.
- Owner-paired device: NOT_RUN; no credential issued/stored.
- Native first start / bearer status and revocation: NOT_RUN.
- YFC and Windows native installation/activation: NOT_RUN.
- ChatGPT+Codex 2-client x 3-original-host READ E2E: NOT_RUN.

Source-only work does not justify claiming native installation or pairing.
Original BRC/WSS production and old rollback checkpoint stay unchanged.
[Hermes #454](https://github.com/MikeMoore1337/hermes/issues/454) stays OPEN.
