#!/usr/bin/env bash
# Explicit owner approval required: no automatic enable during Hermes CD.
set -Eeuo pipefail
umask 077

MODE="${1:-}"
[[ $# == 1 && "$MODE" =~ ^(prepare|enable|status|rollback)$ ]] || {
  echo "Usage: sudo bash deploy/h15-device-fabric-yfc-autostart.sh prepare|enable|status|rollback" >&2
  exit 2
}
[[ "$(id -u)" == 0 ]] || { echo "OWNER_ROOT_REQUIRED" >&2; exit 2; }

USER_NAME=hermes-presence-agent
SRC=/root/.hermes-device
DEST=/var/lib/hermes-presence-agent
UNIT=hermes-device-agent.service
TEMPLATE="$(dirname -- "${BASH_SOURCE[0]}")/hermes-device-agent-yfc.service.in"

check_file() {
  [[ -f "$1" && ! -L "$1" ]] || { echo "PRESENCE_PREREQUISITE_MISSING"; exit 3; }
}

case "$MODE" in
prepare)
  [[ ! -e "$DEST" && ! -L "$DEST" ]] || {
    echo "PRESENCE_STATE_EXISTS_MANUAL_REVIEW_REQUIRED"
    exit 3
  }
  [[ ! -e "/etc/systemd/system/$UNIT" ]] || {
    echo "PRESENCE_UNIT_EXISTS_MANUAL_REVIEW_REQUIRED"
    exit 3
  }
  [[ -d "$SRC" && ! -L "$SRC" ]] || { echo "PRESENCE_SOURCE_MISSING"; exit 3; }
  [[ -d "$SRC/device_fabric" && ! -L "$SRC/device_fabric" ]] || exit 3
  [[ -d "$SRC/.venv" && ! -L "$SRC/.venv" ]] || exit 3
  check_file "$SRC/linux-vps.json"
  check_file "$SRC/device_fabric/device_agent.py"
  check_file /root/.ssh/hermes_presence_ed25519
  check_file /root/.ssh/hermes_presence_known_hosts
  check_file "$TEMPLATE"
  "$SRC/.venv/bin/python" -c 'import websockets; assert websockets.__version__ == "16.0"' ||
    { echo "PRESENCE_WEBSOCKETS_MISSING"; exit 3; }
  if id "$USER_NAME" >/dev/null 2>&1; then
    [[ "$(id -gn "$USER_NAME")" == "$USER_NAME" ]] || exit 3
    [[ "$(getent passwd "$USER_NAME" | cut -d: -f7)" == /usr/sbin/nologin ]] || exit 3
  else
    useradd --system --user-group --home-dir "$DEST" --shell /usr/sbin/nologin \
      --no-create-home "$USER_NAME"
  fi
  install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$DEST"
  # Copy the verified installed client, NOT the owner JSON or keys into Git.
  cp -a -- "$SRC/device_fabric" "$DEST/device_fabric"
  cp -a -- "$SRC/.venv" "$DEST/.venv"
  install -m 0600 -o "$USER_NAME" -g "$USER_NAME" \
    "$SRC/linux-vps.json" "$DEST/linux-vps.json"
  install -m 0600 -o "$USER_NAME" -g "$USER_NAME" \
    /root/.ssh/hermes_presence_ed25519 "$DEST/hermes_presence_ed25519"
  install -m 0600 -o "$USER_NAME" -g "$USER_NAME" \
    /root/.ssh/hermes_presence_known_hosts "$DEST/hermes_presence_known_hosts"
  chown -R "$USER_NAME:$USER_NAME" "$DEST"
  chmod 0700 "$DEST"
  chmod 0600 "$DEST/linux-vps.json" "$DEST/hermes_presence_ed25519" "$DEST/hermes_presence_known_hosts"
  runuser -u "$USER_NAME" -- "$DEST/.venv/bin/python" -c \
    'import websockets; assert websockets.__version__ == "16.0"'
  install -m 0644 "$TEMPLATE" "/etc/systemd/system/$UNIT"
  systemd-analyze verify "/etc/systemd/system/$UNIT"
  systemctl daemon-reload
  echo "YFC_PERSISTENCE=PREPARED"
  echo "AUTOSTART=NOT_ENABLED"
  ;;
enable)
  [[ -f "/etc/systemd/system/$UNIT" && -f "$DEST/linux-vps.json" ]] || {
    echo "YFC_PERSISTENCE=NOT_PREPARED"; exit 3;
  }
  systemctl enable --now "$UNIT"
  echo "YFC_PERSISTENCE=ENABLED"
  ;;
status)
  systemctl show "$UNIT" -p LoadState -p ActiveState -p UnitFileState -p Result --no-pager
  ;;
rollback)
  systemctl disable --now "$UNIT" 2>/dev/null || true
  if [[ -f "/etc/systemd/system/$UNIT" ]]; then
    rm -f "/etc/systemd/system/$UNIT"
    systemctl daemon-reload
  fi
  echo "YFC_PERSISTENCE=DISABLED"
  echo "STATE_AND_ENROLLMENT=PRESERVED"
  ;;
esac
