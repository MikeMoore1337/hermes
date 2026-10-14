#!/usr/bin/env bash
# Install ONLY the read-only collector on the already-approved Hermes VPS.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "root required" >&2; exit 1; fi
ROOT=/opt/hermes-agent-owner
STATE=/var/lib/hermes-agent
if [ ! -d "$STATE" ] || [ -L "$STATE" ]; then
  echo "H-01 private data directory missing" >&2; exit 1
fi
if [ "$(stat -c %a "$STATE")" != 700 ]; then
  echo "Unexpected agent state permissions" >&2; exit 1
fi
if [ ! -f /var/lib/hermes/state.json ]; then
  echo "Existing news data not found" >&2; exit 1
fi
install -d -m 0700 -o root -g root "$STATE/ops-watch"
install -m 0644 "$ROOT/deploy/hermes-ops-watch.service" /etc/systemd/system/hermes-ops-watch.service
install -m 0644 "$ROOT/deploy/hermes-ops-watch.timer" /etc/systemd/system/hermes-ops-watch.timer
systemctl daemon-reload
systemctl start hermes-ops-watch.service
systemctl is-failed --quiet hermes-ops-watch.service && exit 2
systemctl enable --now hermes-ops-watch.timer
echo "Ops Watch local-only timer enabled. No Telegram delivery."
