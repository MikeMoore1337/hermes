# Hermes Infrastructure Monitor - Issue #294

## Implemented in the draft

The Atlas Control Center gets **two separate cards**, VPS Hermes and VPS YFC.
Independent history controls and status per host prevent mixed metrics.
No resident AI agent, new provider inference, Docker socket or public write endpoint.

- Linux collector: python3 -m control_center.infrastructure --host hermes.
- Fixed allowlist of hosts: hermes, yfc (not inferred from Desktop Commander).
- CPU from /proc/stat deltas (not load average), RAM from MemAvailable,
  swap, root filesystem statvfs, uptime and per-interface raw network counters.
- Atomic local JSON per host in /var/lib/hermes-control-center/infrastructure.
- SQLite history retained for 30 days, default timer cadence 60 seconds.
- GET /api/infrastructure/hosts and GET /api/infrastructure/history
  (host and days in 1/7/30 are strictly allowlisted).
- Existing GitHub owner-only OAuth protects both endpoints.
- Data older than 3 minutes is stale; timestamp more than 30 seconds ahead is rejected.
- Invalid, spoofed and oversize snapshots are unknown; missing snapshots not_connected.
- Standalone infrastructure.js and infrastructure.css assets are mirrored from
  control_center/frontend/public to control_center/web for reproducible Vite builds.

## Deployment gates - NOT ACTIVATED

This PR neither provisions YFC access nor enables a monitor in production.
A host shown online by Desktop Commander does not establish permission to run
remote shell commands, nor a real source of CPU/RAM measurements.

1. Verify exact approved release, PR CI and owner-reviewed desktop/mobile images.
2. On Hermes VPS, install deploy/hermes-infrastructure-collector.service and
   .timer after an operator review; run a single smoke, verify the root-owned
   hermes-control readable snapshot and enable timer only after measurements pass.
3. For YFC, install a separately pinned least-privilege collector after access
   approval, then design and validate restricted SSH pull or scoped outbound-only
   push. Never simulate YFC data by running --host yfc on the Hermes server.
4. Record production CPU/RAM overhead and two-host API/visual evidence.
5. Add service-level health, network interval deltas, alert rules and history
   aggregation in subsequent #294 stages.

No shared credentials, SSH connection, remote ingestion, YFC installation,
model calls or automated notifications are introduced here. The YFC card must
remain NOT_CONNECTED until a trusted remote snapshot transport is live.

## Offline checks

- python3 -m unittest tests.test_infrastructure_monitor -v
- python3 -m unittest tests.test_control_center tests.test_control_center_assets -v
- cd control_center/frontend && npm ci --ignore-scripts --no-fund --no-audit
- npm run test && npm run build
- git diff --exit-code -- control_center/web

Unit tests cover CPU counter resets, zero/missing metrics, memory validation,
timestamp freshness, host spoofing, corrupt/oversized snapshots, SQLite reads,
history query validation and owner-only API. UI still requires manual responsive
review before merge.

## Rollback

Disable and stop hermes-infrastructure-collector.timer, remove the two systemd
units, run systemctl daemon-reload, then restore the previous immutable Control
Center release using the standard runbook. Preserve history for forensics unless
explicitly approved for deletion. No YFC rollback is required before activation.
