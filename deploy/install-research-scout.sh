#!/usr/bin/env bash
# Safe isolated public-only Research Scout: NO YFC edits or publication.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo 'root_required' >&2
  exit 2
fi
APP=/opt/hermes-agent-owner
for unit in hermes-discovery.timer hermes-ops-watch.timer hermes-ops-alerts.timer hermes-qa-watch.timer; do
  if ! systemctl is-active --quiet "$unit"; then
    echo 'existing_critical_timer_not_active' >&2
    exit 2
  fi
done
for path in research_scout/europe_pmc.py research_scout/crossref.py research_scout/daily_digest.py; do
  if [ ! -f "$APP/$path" ] || [ -L "$APP/$path" ]; then
    echo 'missing_reviewed_source' >&2
    exit 2
  fi
done
cd "$APP"
python3 -m research_scout.daily_digest  # No credentials / network / writes
systemd-analyze verify "$APP/deploy/hermes-research-scout.service" \
  "$APP/deploy/hermes-research-scout.timer"
install -o root -g root -m 0644 "$APP/deploy/hermes-research-scout.service" \
  /etc/systemd/system/hermes-research-scout.service
install -o root -g root -m 0644 "$APP/deploy/hermes-research-scout.timer" \
  /etc/systemd/system/hermes-research-scout.timer
systemctl daemon-reload
# One explicitly authorized, bounded test before an unattended daily schedule.
systemctl start hermes-research-scout.service
if [ "$(systemctl show hermes-research-scout.service -p Result --value)" != "success" ]; then
  echo 'research_first_run_failed' >&2
  exit 2
fi
systemctl enable --now hermes-research-scout.timer
systemctl is-active --quiet hermes-research-scout.timer
echo 'research_public_metadata_timer_enabled_daily'
