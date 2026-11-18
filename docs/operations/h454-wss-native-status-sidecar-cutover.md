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

## Preventing the existing WSS reconciler race

The installed `h454_wss_relay_reconcile.py` acquires a file lock on
`pins.json`, but the sidecar switch replaces that file with `os.replace`,
which creates a **new inode**. Locking only the previous inode does not prevent
a separate running reconciler from observing new pins before the replacement
sidecar has started. This could cause a conflicting Docker start or leave
stale `reconcile.pending` state.

The cutover now writes an exclusively created root-owned,
exact-receipt-bound `prepare.pending` **while still holding the original pins
lock and before any Docker stop**. The existing, installed reconciler already
refuses ANY `prepare.pending`, including when it locks the new pins inode.
The marker remains until either the new sidecar has passed its TLS/status and
native-inactive checks or the old sidecar has been restored. It is removed
before the transaction invokes the normal reconciler for final verification.

Rollback and owner-approved recovery establish the same guard before any
container change; recovery accepts a pre-existing guard only if its exact
bytes match the retained original pins/CID/source receipt. Foreign markers,
dangling symlinks, mismatched bytes or Docker ambiguity remain hard refusals.
A crash during the transaction leaves evidence intact and requires the
separate TTY-approved `recover` path or a manual incident review. Do not
delete `prepare.pending` merely to re-run preflight.

The regression suite checks the *actual installed reconciler source* contains
its `prepare.pending` refusal, that the guard precedes every simulated
Docker mutation, that it is released before final reconcile, and that
foreign/malformed markers are never adopted. This is synthetic CI, not a
live-concurrent-production test.

## Original-owner production incident: restored old proxy, failed phase unknown

2026-11-18 owner-approved **first and only WSS cutover attempt** returned
`CUTOVER_FAILED_ORIGINAL_PROXY_RESTORED`. Subsequent original-host
`docker inspect` confirmed the exact original BRC and WSS IDs/images
running, the newly named rollback checkpoint absent, and native services
still inactive. The owner executed further read-only forensics:

- `ORIGINAL_PINS_RESTORED=PASS`: exact old pins bytes match root-only backup
  and protected original snapshot.
- `ORIGINAL_PROXY_RESTORED=PASS`: old script matches the original backed-up
  bytes and pinned SHA256.
- `native-status-upgrade.pending`, `prepare.pending`,
  `reconcile.pending` and all known temporary source/pins absent.
- `native-status-upgrade-evidence` (root 0700) and
  `native-status-original-pins.json` (root 0600) **preserved**.
- Bounded Docker event query yielded 0 matching events; this is not proof
  of zero Docker operations or sufficient event retention.

The original source caught an inner Docker/TLS/systemd exception,
verified restoration and reconciler readiness, then returned only the generic
`CUTOVER_FAILED_ORIGINAL_PROXY_RESTORED` code. The exact failed operation
**cannot be deduced** from this evidence. Do not claim a specific root cause,
delete retained evidence or rerun `cutover --execute`.

The subsequent code-only patch introduces **allowlisted, fixed phase names**
such as `STOP_OLD`, `CREATE_NEW`, `VERIFY_NEW_TLS`, `RECONCILE_NEW`
in a restored-failure CLI result. A phase appears only after the old proxy
has been successfully restored; no raw exceptions, Docker stderr, certificate
bytes or bearer tokens are printed. All existing fail-closed recovery
semantics remain. Synthetic fault injection validates each emitted phase.

This diagnostic patch is **not** applied to the completed production incident
and cannot reconstruct the previously lost failure phase. It must not be
deployed or used for another WSS attempt under the consumed approval.
Current preserved evidence also deliberately blocks another `plan`.
Any evidence-preserving re-arm, new source/operator deployment and cutover
need independent review and a **fresh, narrowly scoped owner permission**.

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
