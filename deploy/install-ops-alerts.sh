#!/usr/bin/env bash
# Install only the owner-approved, separately sandboxed Ops Watch sender.
# No changes to the existing networkless collector, YFC units or news timers.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  printf 'root_required\n' >&2
  exit 1
fi
ROOT=/opt/hermes-agent-owner
DATA=/var/lib/hermes-agent/ops-watch
CONFIG=/etc/hermes-agent/ops-watch.env
if [ ! -d "$ROOT/ops_watch" ] || [ ! -d "$DATA" ] || [ -L "$DATA" ] ||
   [ ! -f "$DATA/incidents.sqlite3" ] || [ -L "$CONFIG" ]; then
  printf 'ops_prerequisite_missing_or_unsafe\n' >&2
  exit 2
fi
if [ "$(stat -c '%a:%U:%G' "$DATA")" != "700:root:root" ] ||
   [ "$(stat -c '%a:%U:%G' "$CONFIG")" != "600:root:root" ]; then
  printf 'ops_prerequisite_permissions_invalid\n' >&2
  exit 2
fi
if ! systemctl is-active --quiet hermes-ops-watch.timer; then
  printf 'networkless_ops_collector_not_active\n' >&2
  exit 2
fi
# Existing auth is accessed only through an O_NOFOLLOW fd in Python.
(cd "$ROOT" && /usr/bin/python3 -c \
  'from ops_watch.telegram_e2e import read_credentials; read_credentials()')
# Verify that the one-event sender is dry by default. Must not send.
(cd "$ROOT" && /usr/bin/python3 -m ops_watch.telegram_dispatch)
systemd-analyze verify "$ROOT/deploy/hermes-ops-alerts.service" \
  "$ROOT/deploy/hermes-ops-alerts.timer"
install -m 0644 -o root -g root "$ROOT/deploy/hermes-ops-alerts.service" \
  /etc/systemd/system/hermes-ops-alerts.service
install -m 0644 -o root -g root "$ROOT/deploy/hermes-ops-alerts.timer" \
  /etc/systemd/system/hermes-ops-alerts.timer
systemctl daemon-reload
# No queued event => no HTTP request. Any queued actual incident is sent
# at most once in this initial explicitly owner-approved activation.
systemctl start hermes-ops-alerts.service
systemctl enable --now hermes-ops-alerts.timer
systemctl is-active --quiet hermes-ops-alerts.timer
printf 'ops_alert_sender_enabled_one_event_per_10min\n'
