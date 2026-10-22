# Hermes BRC: Control Center observer contract (#455, linked #454)

## Scope and activation

`control_center/brc_snapshot.py` is a **pure, read-only, fail-closed**
normalizer for owner-authorized Hermes MCP `list_devices` and
`list_workspaces` JSON objects. It performs **no network calls, credential
reads, filesystem writes, device actions or model/provider calls**. No route,
poller, dashboard component, onboarding wizard, agent, systemd timer or host
mount is activated by this change.

Only a separately approved/authenticated collector may supply the raw
MCP results. **Never reuse a ChatGPT OAuth session in a server process**.
Do not map an untrusted browser request directly to `start_process`
or MCP `tools/call`; no browser RCE or arbitrary deviceId selection.
Keep legacy Desktop Commander sources explicitly separate.

## Normalized output

Input: one device listing of exactly the three explicitly approved
Hermes sandbox identities with bounded opaque IDs, true boolean
presence fields, and `lastSeen` integer Unix milliseconds; one owner
catalog of exactly four known public workspace identities with exact
origin, branch and `/workspace/projects/<repository>` roots.

Output: `schema=1`, `source=hermes_brc_mcp`,
`observed_at`, aggregate `status`, canonical device **names**
(with `online/offline/paused/stale` and bounded last-seen age),
and canonical workspace names/roots/branches. Device IDs and arbitrary
untrusted fields never appear in display output.
Five-minute presence TTL; timestamps over one minute in the future
are refused. `command_execution=not_verified` and
`execution_verified=false` always; `git_verified=false` regardless
of server catalog presence. `onboarding_enabled=false`,
`native_host_access=false`. These are **observation labels, not
authorization grants**.

Malformed/duplicate/foreign device, path traversal, switched origin,
device mismatch, incorrect scope/branch or any claimed Git verification
causes a safe `SnapshotRejected` reason code. Future frontend/backend
integration must honor existing owner authentication, state freshness,
no-store caching, optional data-source failure and access boundaries;
do not use this module as an OS-level security boundary.

## Follow-on gates

1. UX/UI Design Orchestra + Impeccable three materially distinct sketches
   and desktop/mobile previews; obtain owner's visual acceptance before
   implementing Control Center views.
2. Independently authorize and implement an owner-scoped metadata
   collector/endpoint with timeouts, sanitized snapshots and safe storage.
3. Only then implement read-only Control Center devices/workspaces health;
   keep the existing Desktop Commander widget for rollback until live QA.
4. Explicit onboarding flow for a **new public sandbox repo** must not
   overwrite existing folders, must verify real Git origin/branch, and
   must not auto-mount native Windows host folders. Changes to relay
   workspace registry/tool catalog require their own controlled delivery.
5. Owner must separately approve **exact original Windows directories
   and allowed operations**. No whole-drive, `.ssh`, secrets, private
   Second Brain vault or YFC production paths. Do not perform a Windows
   reboot/reconnect destructive trial without an agreed maintenance window.
6. Real Codex client 2-VPS sandbox file/process acceptance must be
   independently evidenced; do not call simulated CI tests Codex E2E.

Test offline: `python3 -m unittest -v tests.test_brc_snapshot`.
This PR does not make the Control Center's BRC widget live.
