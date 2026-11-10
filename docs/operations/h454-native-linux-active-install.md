# Hermes #454 - Root-console installation of a DISABLED live Linux unit

Status: SOURCE-ONLY until separately authorized original VPS operation.

The previous PR #881 introduced an actual owner-bound Linux original READ
worker and a hardened systemd unit renderer. This operator installs the
**unit definition only** - no start, enable, pairing, Docker, SSH or
production BRC/WSS change. It is not a replacement for native host setup
and cannot be called through the restricted unprivileged SSH staging user.

## Two-stage installation

First, separately verify a GitHub SHA-scoped source archive and install its
13 bounded Python READ source files with the existing H454 disabled
preflight operator (install-off). This root-console operation creates a
root-owned original release directory under
/opt/hermes-commander-native/releases/main-<sha>, the offline
hermes-commander-native-preflight.service, and a protected 0600 receipt.

Only after that has completed and the owner has approved exact source SHA,
bundle/manifest digest, original project root paths and verified relay/DNS
egress IPv4 /32 addresses, the new
scripts/h454_native_linux_active_install.py may:

- Re-verify the preflight source release and every exact source byte against
  the owner-reviewed archive/receipt.
- Independently render the actual service unit with pinned SHA, approved
  egress addresses and read-only original roots.
- Require a privileged owner-root interactive TTY confirmation consisting of
  H454, target, SHA and exact active-unit SHA-256. No stdin/heredoc
  impersonation, prompts via ChatGPT, unsigned arbitrary shell actions.
- Create ONLY a new root-owned systemd service file
  /etc/systemd/system/hermes-commander-native.service and a private 0600
  receipt named <target>-<SHA>-active.json; no overwrite, no symlink,
  exclusive creation. Run systemctl daemon-reload and confirm the new
  service is simultaneously DISABLED and INACTIVE.
- On any failure, remove only files created by this attempt and restore
  systemd manager state. Keep preflight release, BRC, original project
  roots and unrelated systemd services untouched.
- For rollback, verify the reviewed unit content byte-for-byte and receipt
  SHA, assert systemd disabled/inactive, remove the unit, reload systemd
  and preserve protected audit receipt. No root source files deleted.

The generated unit includes [Install] for **future explicitly authorized**
systemd enable/start after the next gates pass. This source change never
enables, starts, schedules, pairs or checks out live original projects.

## Still required before enabling the native agent

- Real host inspection and separately approved dedicated nonroot UID/GID,
  disabled file source install, original owner-approved Linux project roots,
  required TCP/TLS DNS and WSS routes, egress firewall config and
  root-controlled systemd hardening.
- Independently authenticated existing BRC device-code pairing for each
  new native Linux device and protected service-owned device.json/manifest.
- Exact installed Python interpreter/websockets.sync.client dependency and
  release artifact origin/signature/provenance assurance.
- Verification on each original VPS of effective systemd cgroup, Linux
  capabilities, syscall restrictions, network egress, read-only root fd,
  revocation and original-file access from ChatGPT and Codex.
- Backups and a per-host emergency rollback plan. No automatic use of a
  broad pre-existing source-deploy SSH key, no production BRC/WSS replacement
  without explicit exact authorization.

Until then: LINUX_NATIVE_UNIT_SOURCE=READY,
LINUX_NATIVE_HOST_INSTALL=NOT_RUN, LINUX_NATIVE_HOST_ACCEPTANCE=NOT_RUN,
PRODUCTION_CHANGE=NO. Hermes #454 remains OPEN.
