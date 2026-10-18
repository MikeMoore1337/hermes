# Hermes Infrastructure Monitor - Issue #294

## Implemented in the draft

The Atlas Control Center gets **two separate cards**, VPS Hermes and VPS YFC.
Independent history controls and status per host prevent mixed metrics.
No resident AI agent, new provider inference, Docker socket or public write endpoint.

- Linux collector: python3 -m control_center.infrastructure --host hermes.
- Fixed allowlist of hosts: hermes, yfc (not inferred from Desktop Commander).
- CPU from /proc/stat deltas (not load average), RAM from MemAvailable,
  swap, root filesystem statvfs, inode use, core count, uptime and per-interface
  network throughput from sampled byte counter deltas. Network interface reset
  produces no inferred negative rate.
- Atomic local JSON per host in /var/lib/hermes-control-center/infrastructure.
- SQLite history retained for 30 days, default timer cadence 60 seconds.
  Read API aggregates to 5-minute, hourly or 4-hour buckets depending on
  the requested 1/7/30-day period; no raw 44,000-row JSON response.
- GET /api/infrastructure/hosts and GET /api/infrastructure/history
  (host and days in 1/7/30 are strictly allowlisted).
- Existing GitHub owner-only OAuth protects both endpoints.
- Data older than 3 minutes is stale; timestamp more than 30 seconds ahead is rejected.
- Older-than-3-minute samples are stale, older-than-15-minute samples are
  offline; invalid, spoofed and oversized snapshots are unknown; never-seen
  snapshots are not_connected. Old numeric values remain labelled historical.
- Standalone infrastructure.js and infrastructure.css assets are mirrored from
  control_center/frontend/public to control_center/web for reproducible Vite builds.

## Deployment gates - NOT ACTIVATED

This PR neither provisions YFC access nor enables a monitor in production.
A host shown online by Desktop Commander does not establish permission to run
remote shell commands, nor a real source of CPU/RAM measurements.

1. Verify exact approved release, PR CI and owner-reviewed desktop/mobile images.
2. On Hermes VPS, install deploy/hermes-infrastructure-collector.service and
   .timer after operator review; run a single smoke, verify the root-owned,
   hermes-control group-readable snapshot and enable timer only after proof.
3. YFC transport is now **designed as restricted SSH pull** rather than an
   unrestricted HTTP endpoint. On YFC, install a pinned minimal Python package
   containing control_center.infrastructure and __init__.py at
   /opt/hermes-yfc-metrics/current, root-owned and not writable by the
   dedicated login user. Verify that running
   python3 -m control_center.infrastructure --host yfc --stdout
   returns one sanitized JSON snapshot **without local disk modification**.
4. Place deploy/hermes-yfc-metrics-emit.sh under the root-owned
   /usr/local/libexec/hermes-yfc-metrics-emit, mode 0755. Provision a dedicated
   unprivileged hermes-infra-read user and authorized_keys entry with
   restrict,command="/usr/local/libexec/hermes-yfc-metrics-emit".
   Prefer source-IP restriction after verifying actual network routing.
   Do not permit PTY, agent forwarding, tunnel, writable remote operations.
5. After owner approval, on Hermes provision an independent, root-owned SSH
   key at /etc/hermes/yfc-infrastructure-readonly (0600); pin the YFC server
   host key to /etc/hermes/yfc-infrastructure-known-hosts and a root-owned
   /etc/hermes/yfc-infrastructure-pull.json (0600) of the form
   {"host":"<operator-approved-yfc-host>","port":22}. Do not use host key
   TOFU, StrictHostKeyChecking=no or passwords. Verify actual host ownership
   and mapping before writing this file.
6. Install deploy/hermes-infrastructure-yfc-pull.service and .timer on Hermes,
   run one bounded live smoke, prove fixed command and refusal of an invalid
   remote host/snapshot. Only then enable the timer. Nothing here requires the
   existing Desktop Commander service or the owner's Windows machine.
4. Record production CPU/RAM overhead and two-host API/visual evidence.
5. Add service-level health, network interval deltas, alert rules and history
   aggregation in subsequent #294 stages.

Code for a fixed-command, non-interactive SSH pull **is** included but the
connection, host key, SSH key, network access, remote installation and activation
are NOT performed. No shared AI credentials, HTTP ingestion, model calls or
automated notifications are introduced here. Remote success must be measured
live before changing the YFC card to ONLINE. The YFC card must
remain NOT_CONNECTED until a trusted remote snapshot transport is live.

## Offline checks

- python3 -m unittest tests.test_infrastructure_monitor -v
- python3 -m unittest tests.test_control_center tests.test_control_center_assets -v
- cd control_center/frontend && npm ci --ignore-scripts --no-fund --no-audit
- npm run test && npm run build
- git diff --exit-code -- control_center/web

Unit tests cover CPU counter resets, guest double-count, network delta/reset,
inodes, timestamps, sample ordering, host spoofing, corrupt/oversized snapshots,
SQLite reads, history query validation, SSH configuration injection, refused
remote payloads, timeout and owner-only API. CI uses synthetic data only. UI still requires manual responsive
review before merge.

## Rollback

Disable and stop hermes-infrastructure-collector.timer, remove the two systemd
units, run systemctl daemon-reload, then restore the previous immutable Control
Center release using the standard runbook. Preserve history for forensics unless
explicitly approved for deletion. On YFC, separately revoke its read-only SSH key and remove pinned collector
only if the remote stage has been activated. No YFC rollback is required before
activation.

## Mandatory gaps before closing #294

- Real transport handshake and sample on both VPS; public SSH connectivity not assumed.
- CPU/RAM impact measurements on both machines and network egress confirmation.
- Alerting based on sustained thresholds through existing Ops Alerts (not added yet).
- Service-specific application checks without unbounded Docker or journal access.
- Current alert history, disk inode and network UI completeness review.


## Stage 2 - Hermes local activation via an existing timer

Owner approved the Atlas infrastructure cards on 18 October 2026.
Stage 2 reuses **hermes-control-center-snapshot.timer** that is already
running in production. Every invocation of `python3 -m control_center.snapshot`
now writes the original systemd overview **first**, then makes one
read-only Linux resource sample for the Hermes host. Failure to read
`/proc` or append history is reported by a constant error category;
it does not change the systemd overview, Cloudflare quota enforcement,
H-01 #33 systemd units, or any running YFC service.

No new `systemd` unit is enabled by the normal release, and no
remote device connection is required to activate the local Hermes card.
Deploying a pinned release through the existing GitHub Actions pipeline
is enough **provided the existing timer remains running and the systemd
sandbox permits the collector**. It is never evidence of activation on
its own. After the production deploy, check:

- The exact SHA in the deployment receipt and current UI symlink.
- Timer active and service Result=success on the release.
- Snapshot `/var/lib/hermes-control-center/infrastructure/hermes.json`
  has host=hermes, observed_at updated within 3 minutes, and real
  CPU/RAM/disk measurements with valid units.
- API under the owner's authenticated session returns
  online for `hermes` and not_connected for `yfc`
  until the separate YFC SSH link passes its own admission.
- No errors printed as INFRASTRUCTURE_SNAPSHOT=unavailable in a
  recent run; otherwise mark LOCAL_PROBE_FAILED, do not fake GREEN.
- Source isolation and read-only API remain intact.

If validation fails, reverting the snapshot hook in a new release
returns to the original timer behavior. The optional standalone
`deploy/hermes-infrastructure-collector.*` service files remain
**disabled** to avoid duplicate samples and additional scheduled load.
YFC transport is still explicitly blocked pending host identity,
SSH key setup, proof of an authenticated transfer, and load/health
evidence. Telegram alerting is still a follow-up.
