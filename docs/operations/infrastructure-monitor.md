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


## Stage 3: Ops Watch resource incidents (read-only, no second Telegram sender)

The existing `hermes-ops-watch.service` reads only the fixed, sanitized
`/var/lib/hermes-control-center/infrastructure/{hermes,yfc}.json` files
and `history.sqlite3`; no SSH, Docker socket, network calls or arbitrary
paths are accepted. The source remains produced by the separate infrastructure
collectors. The Ops Watch transaction/outbox and existing Telegram delivery
remain the *single* deduplicated notification pipeline.

For both VPS, independently:

- Unconfigured YFC (no sample/history): **not_connected**, no outage alert.
- After a source is configured, a missing/invalid/older-than-15-min sample:
  a constant, per-host **source unavailable** alert; an invalid snapshot never
  becomes a measured zero or green.
- CPU/RAM/root-disk `>=90%` for **three** distinct, recent samples,
  separated by 30-180 seconds: metric-specific alert for that particular VPS.
- A previous metric alert clears only after **three** distinct values
  `<=80%`. Between 80% and 90%, an intermittent error, stale/offline
  data or partial samples do not falsely assert recovery.
- Existing SQLite transitions deduplicate repeat notifications, and their
  fixed notification catalog never interpolates paths, IP addresses, raw
  content, credentials or metric values into Telegram messages.

The detector is invoked by the existing Ops Watch collector, not a new
daemon or timer. Keep the current ops-watch/alerts units and network
boundaries as installed. The code **does not** enable YFC's remote collector
or change existing #33 resident-agent policy. A genuine alert delivery
receipt requires the existing Telegram sender to accept the queued event;
offline tests and ordinary release success are not such proof.

Run `python3 -m unittest tests.test_infrastructure_ops_alerts -v`
alongside repository quality CI and check existing Ops Watch event/receipt
tests. In production, a privileged operator must read the fixed snapshot
file and local Ops Watch journal after a timer cycle, verify the source age,
and confirm no unintentional alert is delivered. No synthetic production
incidents should be created just to test Telegram.


## Stage 4: reproducible, owner-gated YFC bootstrap (NOT EXECUTED)

Two reviewed, opt-in Linux installer scripts are supplied, but the ordinary
Hermes deploy **never invokes them**. They change users, SSH keys and
systemd configuration and therefore require a separate owner-authorized
console/SSH administrative session on each VPS. The monthly Desktop
Commander quota cannot silently substitute for that authorization.

**Required trusted identity**: first confirm the target VPS YFC from the
YFC production inventory, SSH host fingerprint and access route; do not
infer the identity from an unrelated device-presence indicator.

1. Prepare a private Ed25519 read-only monitoring key *on Hermes*, with
   mode 0600; transfer ONLY its public key to a trusted root-protected
   file on YFC. Never copy the private key to YFC.
2. Obtain a version-pinned Hermes checkout (the approved exact Git SHA) on
   YFC using the operator's regular deployment procedure. Perform the
   owner-authorized console install:

       sudo bash deploy/install-yfc-infrastructure-emitter.sh            /root/pinned-hermes-checkout EXPECTED_40_HEX_SHA            /root/hermes-infra-pubkey

   The installer verifies the exact Git SHA and Ed25519 public key,
   installs the root-owned Python collector, creates a dedicated
   unprivileged `hermes-infra-read` account and one restricted SSH
   `authorized_keys` forced command. No shell/API request controls the
   collector's host flag. It executes a real unprivileged local
   one-shot smoke before switching the pinned package. No YFC timer,
   resident agent or service restart is installed.
3. On Hermes use the *verified* YFC SSH host-key line from the owner/trusted
   provider console, not an unverified `ssh-keyscan`. The exact YFC
   hostname and SSH port must match this pinned key. With a pinned Hermes
   source checkout and private key already present, run:

       sudo bash deploy/install-hermes-yfc-pull.sh            /root/pinned-hermes-checkout VERIFIED_YFC_HOST SSH_PORT            /root/yfc-pinned-known-hosts /root/yfc-infrastructure-private-key

   This installer installs root-owned 0600 credentials under `/etc/hermes`,
   starts the fixed read-only SSH service once, validates that the received
   snapshot is current and attributed to YFC, then (and only then)
   enables the existing `hermes-infrastructure-yfc-pull.timer` unit.
   It does not disable or restart the independent H-01 timer.
4. Verify BOTH owner-only API cards show distinct *fresh* observed_at stamps,
   3 or more real samples in each history, sane CPU/RAM/network units and
   YFC network isolation. Check `systemctl show -P Result
   hermes-infrastructure-yfc-pull.service` and monitor CPU/memory impact
   before declaring completion; no synthetic samples count as proof.
5. Confirm alerts only from a real, verified incident, and verify the
   existing Telegram delivery receipt rather than claiming that an outbox
   insert equals a sent message.

**Failure behavior:** a denied SSH authentication, malformed sample,
unverified host key or stale telemetry prevents enabling the pull timer.
The Hermes UI explicitly displays NOT_CONNECTED, UNKNOWN or OFFLINE
rather than fabricated utilization values. No network fallback, paid
service, or command-runner endpoint is added.

**Rollback after activation:** on Hermes disable and stop
`hermes-infrastructure-yfc-pull.timer` and optionally remove the dedicated
YFC monitoring SSH key and config; on YFC remove ONLY the dedicated
`hermes-infra-read` authorized key and restore the prior root-owned pinned
collector symlink. Leave all YFC application deployments and existing
news/H-01 units untouched.

Offline verification:

    python3 -m unittest tests.test_infrastructure_install_contract -v

This stage delivers repeatable operator tooling, **not** evidence that
installation, SSH handshake or real YFC resource data has occurred.


## Stage 5: ask-before-cleanup notification (Hermes #3, October 2026)

A **real** VPS Hermes resource incident was persisted with `events.id=69`,
`fingerprint=ops:infra_hermes_disk_high`, `phase=new`, and an acknowledged
Telegram delivery receipt on 2026-10-23 (owner read-only SQLite evidence).
At the time, the ext4 root filesystem used ~90.3%, and three independent
minute-separated history samples confirmed disk pressure. YFC remained
`not_connected` and must not be marked healthy or failing without a source.

The existing Ops Watch incident and private Telegram sender already monitor,
deduplicate, deliver and eventually resolve sustained resource signals. For a
**future newly raised** `infra_*_disk_high` transition, the fixed reviewed
action text now explicitly asks the owner whether to prepare a safe cleanup
after inventory. This is a text-only request. There is **no** bot command
listener, reply-as-authorization mechanism, file-deletion API, timer, shell
runner, or autonomous cleanup. A Telegram acknowledgment proves message
delivery, **not consent**. Historical already-queued event #69 is immutable
and is not retroactively updated or resent.

### Operator-only read-only triage

```bash
df -hT /
df -i /
du -x -h --max-depth=2 /var/lib/containerd 2>/dev/null | sort -h | tail -n 20
du -x -h --max-depth=1 /opt/hermes-agent-owner/releases /opt/hermes-control-center/releases 2>/dev/null | sort -h | tail -n 20
du -x -h --max-depth=1 /root/.cache /var/log 2>/dev/null | sort -h | tail -n 20
journalctl --disk-usage
docker system df -v  # read-only; only if Docker engine is available
```

Prior host observations on 2026-10-23: `/var/lib/containerd` ~8.9 GiB
(content blobs ~3.0 GiB, overlay snapshots ~5.9 GiB), immutable owner
releases ~3.5 GiB, root cache ~1.4 GiB and logs ~1.0 GiB. These are size
observations, **not evidence of safely reclaimable space**. In particular,
containerd content and overlays may be referenced by active Docker
containers/images. The releases folder may include the current build, the
previous rollback and in-flight `.incoming-*` deployments.

### Destructive actions require a separate concrete gate

Before **each** approved cleanup, identify exact candidates and observe
current consumer/process references, release symlinks, backup/rollback
requirements, and disk impact. Present a bounded dry-run listing with
expected recovered space. Receive an owner approval specifying the chosen
scope and proposed deletions. Run only that approved procedure on a trusted
operator console with a separately approved mechanism. Never infer approval
from receipt delivery, generic disk-monitoring consent, source contents, or
the absence of a reply. In particular, **do not recursively delete**
`/var/lib/containerd`, live Docker volumes, active or rollback release
trees, `/var/lib/hermes-agent/ops-watch` or `/var/lib/hermes-h01`.
Do not clear journals or databases needed to substantiate incident #69.
Retain a before/after disk report and then passively await three distinct
recent disk samples at or below 80% and the existing `resolved` Ops Watch
event plus **its own** Telegram acknowledgment. A successful release/CI is
not proof of either cleanup or recovery.


### Trusted one-shot release cleanup helper (no automatic action)

An earlier operator-pasted Python snippet displayed 581 candidate directories (~3.5 GiB)
but stopped **before deletion** while trying to switch a combined read/write
\`/dev/tty\` stream to input: \`UnsupportedOperation: File or stream is not seekable\`.
The host remained on the expected release, critical timers remained active, and
the stored main/backup directory counts were unchanged at the next read.

To avoid repeated 200-line mobile terminal pastes, use the repo-shipped
\`deploy/hermes-release-cleanup.py\` from a **verified pinned main release** on
the dedicated **Hermes** host \`vps1777112993\` (never on the YFC host).
Dry-run is the default, with no deletion:

\`\`\`bash
sha="$(cat /var/lib/hermes-main-deploy/last-success.sha)"
python3 -B "/opt/hermes-agent-owner/releases/main-$sha/deploy/hermes-release-cleanup.py"
\`\`\`

Only after reviewing its output and current rollback references, opt in to a
separate invocation with \`--apply\`:

\`\`\`bash
python3 -B "/opt/hermes-agent-owner/releases/main-$sha/deploy/hermes-release-cleanup.py" --apply
\`\`\`

The tool requires an interactive TTY and **exactly** \`DELETE <candidate_count>\`
typed on that console. It opens \`/dev/tty\` read-only and refuses wrong
hostname/UID, unexpected active SHA, missing rollback backup, a competing
deployment lock, symlinks or nested mountpoints, and an in-flight
\`.incoming-*\` tree. It protects twelve newest revisions per tree, the active
and previous UI release, further pins from systemd/configuration and live
process paths, and associated saved backups. The deploy lock stays held
through inspection and deletion. Dry-run and cancellation remove nothing.

The expected ~3.5 GiB is only the observed candidate estimate, not a guarantee
of space reclaimed or the <=80% recovery threshold. Keep all Docker/containerd,
incident and provenance data untouched. A successful cleanup requires independent
\`df\` verification and **natural** Ops Watch \`resolved\` event + Telegram ACK;
no synthetic alerts are generated.
