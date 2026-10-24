# #455 — owner-approved, credential-free BRC observation rollout

**Owner scope (2026-10-24):** activate a bounded, read-only Hermes BRC
device/workspace observer, with a retained checkpoint and no new OAuth bearer,
public endpoint, device permission, original Windows file access or paid API.
Approval does **not** cover generic Windows host execution, reboot or arbitrary
new project mounts.

## Trust design

- The **running relay's own DeviceHub** supplies live connected/lastSeen state;
  paired devices come from the existing owner-bound BRC SQLite registry. The
  observer rejects other owners, unapproved device names, extra identities,
  forged platforms and duplicate IDs.
- A new, pinned BRC candidate adds an observer, **disabled by default**.
  It activates only when existing relay UID 65534 sees the exact owner-controlled
  regular file `/state/.hermes-brc-observer-enable` (0600, contents
  `enabled\n`, no symlink, relay-owned 0700 parent). No new mount is needed.
  On start and every 30 seconds, it writes a fresh sanitized snapshot to the
  existing volume's `/state/hermes-brc-observation.json` via atomic fsync.
- A separate systemd oneshot/timer runs as **User=hermes-brc-relay,
  Group=hermes-control**. It has no network or credentials, reads only the
  relay's private normalized snapshot, runs the existing `read_snapshot`
  schema/TTL validation, and atomically publishes
  `/var/lib/hermes-brc-observer/status.json` mode 0640, in a dedicated
  relay-owned, hermes-control-group 0750 directory. The approved existing
  Control Center service belongs to group `hermes-control` and can read it.
- Control Center's existing authenticated `GET /api/providers/hermes-brc`
  reads the sanitized status; missing/stale data still yields HTTP 503.
  Never expose the raw relay DB/state or a browser-callable MCP tool route.
  No extra `/state` bind or public TCP socket.

## Release preflight (NO activation)

1. PR source CI and pinned candidate OCI CI must be SUCCESS for exact head SHA.
   Confirm successful source deployment of the merged main SHA. Verify immutable
   candidate OCI image ID, bundle SHA-256 and manifest/release provenance
   through `h15_brc_upgrade_preflight` on the owner VPS.
2. On **actual** `vps1777112993`, read-only verify:
   - `hermes-brc-relay` uid/gid, nologin, private
     `/var/lib/hermes-brc-relay` mode 0700 and owner, actual Docker
     `hermes-brc-relay` status/image/mounts, its three online sandbox devices,
     and the currently stopped `hermes-brc-relay-h454-rollback` /
     `-history` checkpoints.
   - `hermes-control` group and Control Center service identity/group,
     `/opt/hermes-control-center/current` deployed source and non-stale BRC
     API behavior. Never display environment variables, tokens, database rows,
     cookies or private Windows paths.
   - New checkpoint `hermes-brc-relay-h455-rollback` MUST be absent; do
     not delete/reuse historical checkpoints.
3. Only after exact-gate SUCCESS create the owner-approved
   `/var/lib/hermes-brc-observer` directory as UID hermes-brc-relay,
   GID hermes-control, mode 0750. Preserve existing files on conflict.
   Inside relay private state create only `.hermes-brc-observer-enable`
   as relay UID/GID, regular 0600, contents exactly `enabled\n`.
   Do not add this key to `relay.env` or copy credentials anywhere.
4. Perform the existing transactional image plan, disposable SQLite restore
   rehearsal and owner approval JSON schema. Invoke
   `python3 -B -m scripts.h455_brc_observer_cutover cutover ... --execute`
   with exact, freshly verified image/bundle/source pins. It uses the **new**
   `-h455-rollback` checkpoint instead of the already retained `-h454`.
   Existing operator stops, renames, starts and health checks; on any failure
   it attempts to restore the old relay and retains DB backups.
5. Verify relay OCI UID, mount-count exactly one, unchanged network/ports,
   three agents reconnected, old and new rollback checkpoints retained, and
   sanitized source snapshot written by relay. An unavailable source snapshot
   blocks the bridge activation and the old Control Center UI stays unchanged.
6. Install only the two reviewed units
   `deploy/hermes-brc-observer-bridge.service` and
   `deploy/hermes-brc-observer-bridge.timer` and enable the timer through
   the owner root console. Unit user is relay, group is hermes-control,
   no network, read-only filesystem except sanitized output directory.
   Run one-shot `systemctl start hermes-brc-observer-bridge.service`, then
   `systemctl is-active --quiet ...timer`; verify output owner, group,
   mode and `read_snapshot` freshness. Do not change the old Desktop
   Commander widget until real owner browser visual acceptance.
7. Confirm existing GitHub OAuth owner session (no secret disclosure) can
   `GET /api/providers/hermes-brc` with HTTP 200 and only approved public
   fields (3 devices, 4 workspaces). An unauthenticated request must be denied
   by the existing perimeter. Negative: stale file returns HTTP 503;
   native win32 is still paused/offline and absent from public 3-device view.

## Safe rollback

1. Stop/disable **only** the new observer timer; remove only the exact opt-in
   marker after asserting device state unchanged, never touch relay.env/SQLite.
2. The published snapshot naturally expires in <=5 minutes and the
   existing endpoint returns 503; the legacy UI remains available.
3. If relay health fails, use the exact preserved
   `hermes-brc-relay-h455-rollback` checkpoint under the existing owner
   upgrade/restore procedure. Do not blindly rename, delete or reset a
   checkpoint, restore stale DB or restart other agents.
4. Verify three sandbox agents online and native original Windows reader
   still paused/offline (bearer revoked). Report any unverified real runtime
   behavior as NOT_VERIFIED, not PASS.

**No code/CI success alone means active production telemetry.**
Owner's independent browser acceptance and separate public-repo onboarding
are required to close #455. Windows reboot/login recovery is #445 and
requires the owner maintenance window.
