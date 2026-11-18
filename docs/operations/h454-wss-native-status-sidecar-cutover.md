# H454 - source-only candidate: WSS native-status sidecar-only replacement

## Intent and current gate

The native Hermes VPS source and its two systemd units were installed disabled
at 30db4fba (owner root-console receipt). PR #896 implemented a protected
/device/native-status path in the TLS sidecar, but the *running* original
WSS container still mounts the old proxy.mjs source. The relay itself already
exposes the owner-bearer status route and must remain running.

The exact plan-only preflight is now pinned to the historical native3
receipt-aware source blob `cc5d723eb1d67f2447a5d50123d53de3f44f96ec`,
staged only at `/root/h454_wss_native_status_preflight_903.py` after a
verified source-only merge and original-host read-only admission. The
original Nov-13 `native3-original-pins.json` is accepted only when its
SHA256, original checkpoint IDs/images, TLS trust and active-pair lineage
match the fixed owner attestation. Any genuine pending marker or unrecognized
historical record still blocks cutover. The previous `_902.py` is preserved.

The candidate operator is scripts/h454_wss_native_status_sidecar_cutover.py.
It reuses the existing **exact original** pinned Stage 1 relay/WSS utilities
from owner-source 82a51cc0 and the **plan-only** preflight merged in PR #900.
It attempts to retain the existing relay container ID, unchanged private
network, read-only workspace registry, SQLite state and tokens. The only
planned live switch is the sidecar source, sidecar container and associated
protected root-owned pins, with a retained old sidecar and old source/pin bytes.

This component remains **RUNTIME_NO_GO** even if its tested source is merged.
Do not run its cutover/rollback/recovery commands against the original VPS
until separate original-host operator staging, the exact owner-scoped release
approval, and a rehearsed incident recovery are accepted. A source-only merge
does not enable new services, restart a WSS container or issue device credentials.

On 2026-11-18, the owner DID run the previously merged **read-only**
preflight from the original root console, using exact Git blob
`cc5d723eb1d67f2447a5d50123d53de3f44f96ec`. It returned
`H454_WSS_NATIVE_STATUS_PREPARE_PLAN_PASS` with
`completed_native3_history_verified=true`,
`native_services_inactive=true`, `native_paired=false`,
`brc_wss_mutation=false`, `cutover_approval=NOT_GRANTED`. The old WSS proxy
still runs; the candidate source was staged in a separate private root file.
This host plan does **not** prove any authenticated bearer status or device
reconnect after a WSS switch. See Issue #454 comment 6972355845.

## Provisional command contract (NOT RELEASED)

- plan: read-only, loads exact source-verified
  /root/h454_wss_native_status_preflight_903.py and tests the current host
  against the original relay, TLS, source, dormant native unit and file hashes.
- cutover --execute: requires **a separate specific owner-approved original
  root TTY** and an exact typed challenge. Its intended scope is a new sealed
  backup, original WSS sidecar checkpoint, atomic source and pin replacement,
  single new sidecar on the *same* relay network namespace, an anonymous
  403 on the private bearer-status route, and unchanged BRC and inactive
  native systemd units.
- rollback --execute: intended to restore the exact old sidecar, source and
  pins. Never overwrite foreign Docker container names, keys or backups.

A cutover can fail after Docker stop/rename/create. The current implementation
intentionally refuses to delete an ambiguous container and retains a pending
marker, but **automatic rollback and crash-phase recovery are not yet
sufficiently tested**. Therefore it must not be promoted from Draft or used in
production. Existing source-only PRs, plan PASS and green CI do not authorize
WSS restarts, pairing, native activation or OS permission changes.

## Acceptance before merge / production discussion

- Exact-source code review, concurrency/locking tests and a synthetic
  fault matrix covering stop, update, rename, source swap, create, pin swap,
  start, TLS/status check and reconciler failures.
- Fully verified original pair identity, root-owned backup/replay protection,
  no remote secret values in logs, source SHA/blob pins and non-root negative.
- Verified automatic restoration or a reviewed, tested explicit recovery
  operator for every known partial phase. No lost WSS service on failure.
- Original-root no-mutation plan PASS; still require an **independent**
  code/security review and a separately accepted, **exact-host owner
  authorization** before production cutover. BRC MUST NOT be restarted.
- Exact-head CI includes a complete synthetic successful sidecar-only path,
  a negative failure matrix and retained old proxy proof. Synthetic CI
  does not constitute live failure injection or recovery acceptance.
- After cutover, live ChatGPT/Codex device reconnect and genuine owner
  bearer/revocation tests, then separately approve native service activation.

The window is not authorized by the disabled-only Hermes VPS install. Other
hosts (YFC VPS/Windows) are NOT part of this transaction.

Refs #454, #896, #900.
