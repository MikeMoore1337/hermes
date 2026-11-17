# H454 - source-only candidate: WSS native-status sidecar-only replacement

## Intent and current gate

The native Hermes VPS source and its two systemd units were installed disabled
at 30db4fba (owner root-console receipt). PR #896 implemented a protected
/device/native-status path in the TLS sidecar, but the *running* original
WSS container still mounts the old proxy.mjs source. The relay itself already
exposes the owner-bearer status route and must remain running.

The candidate operator is scripts/h454_wss_native_status_sidecar_cutover.py.
It reuses the existing **exact original** pinned Stage 1 relay/WSS utilities
from owner-source 82a51cc0 and the **plan-only** preflight merged in PR #900.
It attempts to retain the existing relay container ID, unchanged private
network, read-only workspace registry, SQLite state and tokens. The only
planned live switch is the sidecar source, sidecar container and associated
protected root-owned pins, with a retained old sidecar and old source/pin bytes.

This PR is **DRAFT / RUNTIME_NO_GO** until an independent negative fault matrix,
ambiguous Docker-result recovery, post-switch WSS/client acceptance, and
owner-approved exact-original-host plan have passed. DO NOT run cutover,
rollback, or a command copied from this PR against the original VPS.

## Provisional command contract (NOT RELEASED)

- plan: read-only, loads exact source-verified
  /root/h454_wss_native_status_preflight.py and tests the current host
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
- Actual no-mutation owner-root plan, independent owner approval for the
  exact runtime change, and tested restoration. BRC MUST NOT be restarted.
- After cutover, live ChatGPT/Codex device reconnect and genuine owner
  bearer/revocation tests, then separately approve native service activation.

The window is not authorized by the disabled-only Hermes VPS install. Other
hosts (YFC VPS/Windows) are NOT part of this transaction.

Refs #454, #896, #900.
