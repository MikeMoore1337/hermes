#!/usr/bin/env bash
# Hermes #275: owner-run, isolated MCP onboarding. Does NOT touch resident H-01.
set -euo pipefail
if [[ $# -ne 1 ]]; then echo "Usage: sudo bash deploy/h15-desktop-commander-setup.sh prepare|local|auth|verify|enable|status" >&2; exit 2; fi
MODE="$1"
STATE=/var/lib/hermes-desktop-commander
USER_NAME=hermes-desktop
GROUP_NAME=hermes-control
RELEASE=/opt/hermes-control-center/current
LOCAL_BIN="$STATE/node_modules/.bin/desktop-commander"
REMOTE_BIN="$STATE/node_modules/.bin/mcp-remote-client"
REMOTE_URL=https://mcp.desktopcommander.app/mcp

require_root() {
  if [[ $(id -u) != 0 ]]; then echo 'Run using sudo; Node/MCP will be unprivileged.' >&2; exit 2; fi
}
require_release() {
  if [[ ! -f "$RELEASE/control_center/desktop_commander.py" ]]; then
    echo 'Deployed Control Center release is missing.' >&2; exit 2
  fi
}
as_identity() {
  runuser -u "$USER_NAME" -- env HOME="$STATE" \
    MCP_REMOTE_CONFIG_DIR="$STATE/.mcp-auth" PYTHONPATH="$RELEASE" "$@"
}
validate_node_version() {
  local version="${1:-}" major minor
  if [[ ! "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    echo "Unable to parse Node.js version: $version" >&2
    return 2
  fi
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  if (( major < 22 || (major == 22 && minor < 12) )); then
    echo "Desktop Commander requires Node.js >=22.12.0 (detected v$version)." >&2
    return 2
  fi
}
require_supported_node() {
  local version
  version=$(as_identity node -p 'process.versions.node') || {
    echo "Node.js is not executable by hermes-desktop." >&2
    return 2
  }
  validate_node_version "$version"
}
require_setup() {
  require_release
  if ! id "$USER_NAME" >/dev/null 2>&1 || [[ ! -x "$LOCAL_BIN" ]] || [[ ! -x "$REMOTE_BIN" ]]; then
    echo 'Run prepare first.' >&2; exit 2
  fi
  require_supported_node
}
prepare() {
  require_release
  if ! getent group "$GROUP_NAME" >/dev/null; then
    echo 'Expected hermes-control group is absent. Refusing change.' >&2; exit 2
  fi
  if id "$USER_NAME" >/dev/null 2>&1; then
    if [[ $(id -gn "$USER_NAME") != "$GROUP_NAME" ]]; then
      echo 'Unexpected primary group on hermes-desktop.' >&2; exit 2
    fi
  else
    useradd --system --gid "$GROUP_NAME" --home-dir "$STATE" \
      --shell /usr/sbin/nologin --no-create-home "$USER_NAME"
  fi
  install -d -m 0750 -o "$USER_NAME" -g "$GROUP_NAME" "$STATE"
  install -d -m 0700 -o "$USER_NAME" -g "$GROUP_NAME" "$STATE/.mcp-auth"
  if ! command -v node >/dev/null || ! command -v npm >/dev/null; then
    echo 'Node and npm are missing; no global changes made.' >&2; exit 2
  fi
  require_supported_node
  # Download both pinned clients under a non-root user, never at service startup.
  as_identity npm --prefix "$STATE" install --engine-strict --no-save --ignore-scripts \
    --no-audit --no-fund --no-update-notifier \
    '@wonderwhy-er/desktop-commander@0.2.52' 'mcp-remote@0.13.5'
  if [[ ! -x "$LOCAL_BIN" || ! -x "$REMOTE_BIN" ]]; then
    echo 'Pinned executables missing after installation.' >&2; exit 3
  fi
  install -m 0644 "$(dirname "$0")/hermes-desktop-commander.service" /etc/systemd/system/
  install -m 0644 "$(dirname "$0")/hermes-desktop-commander.timer" /etc/systemd/system/
  systemd-analyze verify /etc/systemd/system/hermes-desktop-commander.service \
    /etc/systemd/system/hermes-desktop-commander.timer
  systemctl daemon-reload
  echo PREPARED=YES
  echo TIMER_ACTIVATED=NO
}
probe_local() {
  require_setup
  # initialize + tools/list only. No device command, remote credit or model call.
  as_identity /usr/bin/python3 -m control_center.desktop_commander --probe-local
  echo LOCAL_MCP_TOOLS_LIST=PASS
}
authorize() {
  require_setup
  echo 'Interactive OAuth under hermes-desktop. Open URL in your browser.'
  echo 'Do not share callback URLs, authorization codes or cookies in chat.'
  as_identity "$REMOTE_BIN" "$REMOTE_URL"
}
verify() {
  require_setup
  # Success requires genuine MCP who_am_i/list_devices responses.
  as_identity env HERMES_DC_OWNER_AUTHORIZED=1 /usr/bin/python3 \
    -m control_center.desktop_commander --remote --output "$STATE/status.json"
  as_identity /usr/bin/python3 -c '
from control_center.desktop_commander import read_snapshot
from control_center.desktop_commander_history import read
from pathlib import Path
p=Path("/var/lib/hermes-desktop-commander/status.json")
s=read_snapshot(p)
h=read(p.with_name("history.sqlite3"))
print("REMOTE_SNAPSHOT_STATUS=" + s["status"])
print("CLOUD_QUOTA_REMAINING_PERCENT=" + str(s["quota_remaining_percent"]))
print("DEVICES_OBSERVED=" + str(len(s["devices"])))
print("HISTORY_POINTS=" + str(len(h["points"])))
'
}
enable() {
  require_setup
  as_identity /usr/bin/python3 -c '
from control_center.desktop_commander import read_snapshot
from pathlib import Path
s=read_snapshot(Path("/var/lib/hermes-desktop-commander/status.json"))
if s["status"] not in ("monitored", "exhausted"):
    raise SystemExit("Refuse timer activation without a fresh real metadata sample")
'
  systemctl enable --now hermes-desktop-commander.timer
  # A pre-existing enabled timer may have already elapsed its OnBootSec
  # trigger and remain active without any next event. Re-arm the schedule.
  systemctl restart hermes-desktop-commander.timer
  local next active
  active=$(systemctl show --value -p ActiveState hermes-desktop-commander.timer)
  next=$(systemctl show --value -p NextElapseUSecMonotonic hermes-desktop-commander.timer)
  if [[ "$active" != active || -z "$next" || "$next" == n/a || "$next" == 0 ]]; then
    echo "TELEMETRY_TIMER=FAILED_NO_NEXT_RUN" >&2
    return 1
  fi
  systemctl is-enabled hermes-desktop-commander.timer
  echo TELEMETRY_TIMER=ENABLED
  echo TELEMETRY_NEXT="$next"
  echo REMOTE_COMMAND_EXECUTION=NOT_AUTHORIZED
}
status() {
  require_release
  if [[ -e "$STATE/status.json" ]]; then
    /usr/bin/python3 -c '
from control_center.desktop_commander import read_snapshot
from pathlib import Path
try:
    s=read_snapshot(Path("/var/lib/hermes-desktop-commander/status.json"))
    print("REMOTE_SNAPSHOT_STATUS=" + s["status"])
    print("CLOUD_QUOTA_REMAINING_PERCENT=" + str(s["quota_remaining_percent"]))
except Exception:
    print("REMOTE_SNAPSHOT_STATUS=INVALID")
'
  else
    echo REMOTE_SNAPSHOT_STATUS=NOT_CONFIGURED
  fi
  if systemctl is-enabled --quiet hermes-desktop-commander.timer 2>/dev/null; then
    echo TELEMETRY_TIMER=ENABLED
  else
    echo TELEMETRY_TIMER=DISABLED
  fi
}
require_root
case "$MODE" in
  prepare) prepare ;;
  local) probe_local ;;
  auth) authorize ;;
  verify) verify ;;
  enable) enable ;;
  status) status ;;
  *) echo 'Invalid action' >&2; exit 2 ;;
esac
