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
- November 19 original-root network diagnosis: an existing permanent H15
  Hermes VPS sandbox `hermes-h15-hermes-agent` is a second bridge endpoint,
  `172.29.251.3/28`, scope `h15-permanent-hermes-v1`, image
  `sha256:1d5b144c8b145dd18dca58e13eaefadc06b615c20c278d3be06ba44d8da0db11`.
  This is separate from the namespace-sharing WSS proxy and must not be
  disconnected just to satisfy the enrollment plan.
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

## Immutable owner-release permission compatibility

The production source deploy script `deploy/hermes-main-deploy.sh` first
creates the root-owned source release directory as `0755`, then uses
`chmod -R a-w "$release"` after publishing. The resulting exact directory
mode is **`0555`**, not `0755`. The first owner original-VPS
`plan` in PR #907 returned `H454_HERMES_NATIVE_ENROLLMENT_HOLD`.
A read-only root-console diagnostic narrowed it to
`H454_DIAG_STAGE=SOURCE`, `H454_DIAG_REASON=UNSAFE_DIRECTORY`.

The corrected operator requires exact `0555` for the pinned, immutable
**original owner source release**, retaining UID root, no symlinks and
root-owned/non-group-writable ancestors. The **separate native 30db
source release** still requires exact root-owned `0755` and immutable
Git-blob content. This is NOT a request to chmod original production
directories; doing so would weaken the deployed source's protection.

`plan` now reports only one fixed `failed_stage` enum on a
read-only admission failure: `SOURCE`, `SERVICE`, `RUNTIME`, or
`COMPILED_BRC`. No Python exception messages, private file content,
owner paths or tokens are returned. No automatic retry or any device
registration is authorized by this source patch.

## Exact preflight and execution

`plan` is read-only and root-only. It checks installed original-owner Git
blobs, exact native source/release identity, native manifest parser,
private trust CA/pins, Docker CID/image/netns/internal bridge with no unrecognized bridge peers (relay alone or the exact existing
H15 sandbox with pinned name/image/scope/IP and restricted Docker profile),
no BRC host port publishing, live `GET /health` 200 without a
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

## Second bridge endpoint - guarded source correction

The original-root read-only `plan` returned `failed_stage=RUNTIME`.
A bounded diagnosis found `FOREIGN_BRIDGE_PEER_OR_ADDRESS`: all other
relay/network and WSS namespace checks passed, but the internal bridge has
two endpoints rather than the operator's assumed one. The second endpoint is
the existing H15 Hermes sandbox, not an unknown newly approved agent.

The enrollment operator now admits the relay by itself or the exact existing
H15 peer with a single pinned image, scope, name, IPv4/28 endpoint, running
state, correct bridge and minimum Docker restrictions (read-only rootfs, all
caps dropped, no-new-privileges, non-privileged, no host-published ports or
Docker socket mount). It rejects any third bridge endpoint, changed image,
scope, network identity, or weakened isolation. Peer inspection is read-only.
The exact profile is still subject to original-host `plan` attestation;
an unverified field causes a HOLD, not an automatic container change.

The original `_908.py` and existing WSS rollback/archive evidence must be
preserved. Stage a separately named, Git-blob-verified new operator on the
original root host and execute `plan` only. A successful plan does not
authorize `enroll --execute`, service activation or token issuance.

## Post-consent original VPS HOLD (November 20)

Owner independently completed exact `_909.py plan` on the original
Hermes VPS with `H454_HERMES_NATIVE_ENROLL_PLAN_PASS` and then approved
ONE pairing attempt. Both original-root TTY confirmations occurred;
the second included the fresh expiring user-code, which is not recorded
in the repository. The operator returned only
`H454_HERMES_NATIVE_ENROLLMENT_HOLD`, with no failed-stage label.

Subsequent owner-read-only reconciliation:
`DEVICE_FILE=ABSENT`, `PENDING_FILE=ABSENT`,
`NATIVE_SERVICE=INACTIVE_DISABLED`, `TARGET_DEVICE_ROWS=0`,
`TARGET_CODE_ROWS_RETURNED=0`. A separate service-UID read-only
verification found `HOST_DB_PREFLIGHT=PASS`, `SQLITE_WAL=PASS`,
`ADMIN_OWNER_UNIQUE=PASS`, `NATIVE_DEVICE_ID_ROWS=0`,
`NATIVE_BOUND_CODE_ROWS=0`. No tokens or DB changes were made by
these diagnostics. Absence of expired codes later cannot establish
the exact failing stage. The earlier owner consent is consumed:
**no automatic retry or cleanup**.

### Source contract correction and bounded failure telemetry

The pinned upstream BRC `/device/poll` builds its returned `ws_url`
from `cfg.publicUrl.replace(/^http/, 'ws') + '/ws'`. The existing
immutable relay deployment sets `PUBLIC_URL=https://mcp.mikemoore.top`
(used for OAuth/MCP). The native read-only worker instead requires
`wss://hermes.mikemoore.top/ws` and connects over separately pinned
private CA/SNI to the sidecar. The old operator incorrectly expected
the native WSS address in the *BRC enrollment response*, which would
cause an orphaned device if all preceding stages succeeded.

The corrected source binds and verifies the BRC `PUBLIC_URL` from
the exact running relay `docker inspect`, accepts only the derived
`wss://mcp.mikemoore.top/ws` in the *BRC control-plane reply*, then
writes the independently fixed native WSS URL into the protected service
config. No attacker-supplied URL, redirect, discovery or host port
is accepted. A mismatched runtime origin now fails in the nonmutating
`plan` before any new code is issued.

For every post-consent failure, the operator reports a single constant
`failed_stage` such as `OWNER_CAS`, `TOKEN_POLL` or
`DEVICE_WRITE`, without printing exceptions, bearer, user-code,
SQL row, project root or Docker payload. Any HOLD is still
`no_auto_retry=true` and may require separate owner-approved
reconciliation. Tests are isolated and source-only. This change
does not establish that the old failure reached the URL check.

Use a **new, unused** root-only operator filename with exact merged Git
blob and repeat `plan` only after code review and exact-head CI.
New pairing/credential creation needs an independent explicit owner
approval; none is implied by this fix or earlier attempt.

## Current acceptance

- Python local/mock tests: exact-head CI required for post-HOLD fix.
- Original Hermes owner-root: old `_909.py plan` **PASS**,
  owner-pairing attempt **HOLD**; revised operator `plan` NOT_RUN.
- Owner-paired device: NOT_RUN; no credential issued/stored.
- Native first start / bearer status and revocation: NOT_RUN.
- YFC and Windows native installation/activation: NOT_RUN.
- ChatGPT+Codex 2-client x 3-original-host READ E2E: NOT_RUN.

Source-only work does not justify claiming native installation or pairing.
Original BRC/WSS production and old rollback checkpoint stay unchanged.
[Hermes #454](https://github.com/MikeMoore1337/hermes/issues/454) stays OPEN.
