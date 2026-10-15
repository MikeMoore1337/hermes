#!/usr/bin/env bash
# Install only standalone read-only GitHub CI sampler after separately reviewed CI.
# Uses existing token, does not alter YFC news/editorial/Ops Telegram services.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo 'root_required' >&2
  exit 2
fi
APP=/opt/hermes-agent-owner
TOKEN=/etc/hermes-agent/github-actions-read.token
if [ "$(stat -c '%a:%U:%G' "$TOKEN" 2>/dev/null || :)" != "600:root:root" ] ||
   [ -L "$TOKEN" ] ||
   [ ! -f "$APP/qa_advisor/watch_once.py" ] ||
   [ ! -f "$APP/qa_advisor/signal_store.py" ] ||
   [ ! -f "$APP/ops_watch/collector.py" ]; then
  echo 'qa_prerequisite_missing_or_unsafe' >&2
  exit 2
fi
for timer in hermes-discovery.timer hermes-ops-watch.timer hermes-ops-alerts.timer; do
  if ! systemctl is-active --quiet "$timer"; then
    echo 'existing_news_or_ops_timer_inactive' >&2
    exit 2
  fi
done
cd "$APP"
python3 -m qa_advisor.watch_once # NOT_EXECUTED, never HTTP or token
systemd-analyze verify "$APP/deploy/hermes-qa-watch.service" "$APP/deploy/hermes-qa-watch.timer"
install -o root -g root -m 0644 "$APP/deploy/hermes-qa-watch.service" /etc/systemd/system/hermes-qa-watch.service
install -o root -g root -m 0644 "$APP/deploy/hermes-qa-watch.timer" /etc/systemd/system/hermes-qa-watch.timer
systemctl daemon-reload
# First exact read-only GET must work before enabling unattended scheduling.
systemctl start hermes-qa-watch.service
if [ "$(systemctl show hermes-qa-watch.service -p Result --value)" != "success" ]; then
  echo 'qa_first_read_failed' >&2
  exit 2
fi
systemctl enable --now hermes-qa-watch.timer
systemctl is-active --quiet hermes-qa-watch.timer
echo 'qa_readonly_sampler_enabled_15m'
