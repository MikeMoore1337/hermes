#!/usr/bin/env bash
# Operator-gated Hermes VPS install. Never auto-runs on deploy.
# Host-key pinning, YFC identity verification, and private key transfer happen
# OUTSIDE this script with the owner. Never trust an unverified host-key discovery.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/bin
umask 077
die() { printf 'YFC_PULL_INSTALL=refused reason=%s\n' "$1" >&2; exit 1; }
if [[ $# != 5 ]]; then
  echo "Usage: sudo bash deploy/install-hermes-yfc-pull.sh CHECKOUT_DIR YFC_HOST PORT PINNED_KNOWN_HOSTS PRIVATE_KEY" >&2
  exit 2
fi
[[ "$EUID" == 0 ]] || die root_required
source_dir=$(realpath -e -- "$1") || die source_missing
host=$2
port=$3
known=$(realpath -e -- "$4") || die host_key_missing
key=$(realpath -e -- "$5") || die private_key_missing

[[ -f "$source_dir/deploy/hermes-infrastructure-yfc-pull.service" &&
   -f "$source_dir/deploy/hermes-infrastructure-yfc-pull.timer" ]] ||
  die missing_units
[[ "$host" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ && "$host" != *..* ]] ||
  die bad_host
[[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]] ||
  die bad_port
[[ ! -L "$4" && ! -L "$5" && -f "$known" && -f "$key" ]] ||
  die bad_credential_files
[[ "$(wc -c < "$known")" -le 4096 && "$(wc -c < "$key")" -le 8192 ]] ||
  die credential_oversize
/usr/bin/ssh-keygen -y -f "$key" >/dev/null 2>&1 || die private_key_invalid

name="$host"
if [[ "$port" != 22 ]]; then name="[$host]:$port"; fi
/usr/bin/ssh-keygen -F "$name" -f "$known" >/dev/null 2>&1 ||
  die host_key_not_pinned
[[ -d /opt/hermes-control-center/current/control_center &&
   -f /opt/hermes-control-center/current/control_center/infrastructure_pull.py ]] ||
  die control_center_not_deployed

install -d -o root -g root -m 0700 /etc/hermes
install -o root -g root -m 0600 "$key" /etc/hermes/yfc-infrastructure-readonly
install -o root -g root -m 0600 "$known" /etc/hermes/yfc-infrastructure-known-hosts
/usr/bin/python3 - "$host" "$port" > /etc/hermes/yfc-infrastructure-pull.json <<'PY'
import json, sys
print(json.dumps({"host": sys.argv[1], "port": int(sys.argv[2])},
                 ensure_ascii=True, separators=(",", ":")))
PY
chmod 0600 /etc/hermes/yfc-infrastructure-pull.json
chown root:root /etc/hermes/yfc-infrastructure-pull.json

install -o root -g root -m 0644 \
  "$source_dir/deploy/hermes-infrastructure-yfc-pull.service" \
  /etc/systemd/system/hermes-infrastructure-yfc-pull.service
install -o root -g root -m 0644 \
  "$source_dir/deploy/hermes-infrastructure-yfc-pull.timer" \
  /etc/systemd/system/hermes-infrastructure-yfc-pull.timer

systemctl daemon-reload
systemctl start hermes-infrastructure-yfc-pull.service ||
  die pinned_ssh_pull_smoke_failed
[[ "$(systemctl show -P Result hermes-infrastructure-yfc-pull.service)" == success ]] ||
  die pull_service_failed
# Confirm the trusted collector actually persisted a fresh YFC observation.
cd /opt/hermes-control-center/current
/usr/bin/python3 - <<'PY' || die yfc_snapshot_not_verified
from control_center.infrastructure import hosts
data = {item["host"]: item for item in hosts()["hosts"]}
assert data["yfc"]["status"] == "online", "no fresh YFC metrics"
assert 0 <= data["yfc"]["metrics"]["ram_used_percent"] <= 100
assert 0 <= data["yfc"]["metrics"]["disk_used_percent"] <= 100
PY

systemctl enable --now hermes-infrastructure-yfc-pull.timer
systemctl is-active --quiet hermes-infrastructure-yfc-pull.timer ||
  die pull_timer_not_active
echo "YFC_PULL_INSTALL=active"
echo "SOURCE=authenticated_read_only_yfc"
echo "INTERVAL=approximately_60_seconds"
echo "STATUS=requires_owner_monitoring_ui_and_telegram_verification"
