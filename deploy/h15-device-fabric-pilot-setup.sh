#!/usr/bin/env bash
# Owner-approved H-15 #297 loopback-only test relay, not a remote shell service.
set -Eeuo pipefail
MODE="${1:-}"
if [[ $# != 1 || ! "$MODE" =~ ^(prepare|enable|smoke|status|rollback)$ ]]; then
  echo "Usage: sudo bash deploy/h15-device-fabric-pilot-setup.sh prepare|enable|smoke|status|rollback" >&2
  exit 2
fi
[[ $(id -u) == 0 ]] || { echo "Requires root for scoped local service setup" >&2; exit 2; }
STATE=/var/lib/hermes-device-fabric
USER_NAME=hermes-device-fabric
UNIT=hermes-device-fabric-pilot.service
PORT=38177
RELEASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ "$RELEASE" == /opt/hermes-agent-owner/releases/main-* ]] ||
  { echo "Use an approved deployed Hermes release, not a checkout." >&2; exit 2; }
[[ -f "$RELEASE/device_fabric/service.py" && -f "$RELEASE/device_fabric/owner_smoke.py" ]] ||
  { echo "Required device fabric modules not in release" >&2; exit 2; }
DB="$STATE/devices.sqlite3"
TOKEN="$STATE/pilot-token"
CERT="$STATE/tls/cert.pem"
KEY="$STATE/tls/key.pem"

as_identity() {
  runuser -u "$USER_NAME" -- env HOME="$STATE" PYTHONPATH="$RELEASE" PYTHONDONTWRITEBYTECODE=1 "$@"
}
check_prepared() {
  id "$USER_NAME" >/dev/null 2>&1 &&
    [[ -x "$STATE/venv/bin/python" && -f "$DB" && -s "$TOKEN" && -s "$CERT" && -s "$KEY" ]] &&
    [[ -f "/etc/systemd/system/$UNIT" ]] ||
      { echo "PILOT_NOT_PREPARED; run prepare" >&2; return 2; }
}
prepare() {
  if id "$USER_NAME" >/dev/null 2>&1; then
    [[ "$(id -gn "$USER_NAME")" == "$USER_NAME" ]] ||
      { echo "Unexpected service user primary group" >&2; return 2; }
  else
    useradd --system --user-group --home-dir "$STATE" --shell /usr/sbin/nologin --no-create-home "$USER_NAME"
  fi
  install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$STATE" "$STATE/tls"
  # Debian/Ubuntu may ship /usr/bin/python3 without pythonX.Y-venv.
  # Check before touching the venv; never auto-modify system packages.
  if ! as_identity /usr/bin/python3 -c 'import ensurepip, venv' >/dev/null 2>&1; then
    local py_pkg
    py_pkg=$(/usr/bin/python3 -c 'import sys; print("python%d.%d-venv" % sys.version_info[:2])')
    echo "PILOT_PREPARE_BLOCKED=PYTHON_VENV_UNAVAILABLE" >&2
    echo "Owner action required: sudo apt-get install --no-install-recommends $py_pkg" >&2
    echo "No remote device service was enabled." >&2
    return 3
  fi
  # A failed ensurepip leaves venv/bin/python executable but without pip.
  # Clear ONLY this dedicated venv (not the registry, TLS files or pilot token).
  # Reject symlinks/other file types to prevent unintended filesystem writes.
  if [[ -L "$STATE/venv" || ( -e "$STATE/venv" && ! -d "$STATE/venv" ) ]]; then
    echo "PILOT_PREPARE_BLOCKED=INVALID_VENV_PATH" >&2
    return 3
  fi
  if [[ -d "$STATE/venv" ]]; then
    if [[ ! -x "$STATE/venv/bin/python" ]] ||
       ! as_identity "$STATE/venv/bin/python" -m pip --version >/dev/null 2>&1; then
      echo "PILOT_VENV=REPAIR_INCOMPLETE" >&2
      as_identity /usr/bin/python3 -m venv --clear "$STATE/venv"
    fi
  else
    as_identity /usr/bin/python3 -m venv "$STATE/venv"
  fi
  if ! as_identity "$STATE/venv/bin/python" -m pip --version >/dev/null 2>&1; then
    echo "PILOT_PREPARE_BLOCKED=VENV_PIP_UNAVAILABLE" >&2
    return 3
  fi
  # Optional external dependency is installed once, pinned, as an unprivileged identity.
  as_identity "$STATE/venv/bin/python" -m pip --isolated install --no-input --disable-pip-version-check \
    --only-binary=:all: --no-deps 'websockets==16.0'
  as_identity "$STATE/venv/bin/python" -c \
    'import websockets; assert websockets.__version__ == "16.0"'
  if [[ ! -s "$CERT" || ! -s "$KEY" ]]; then
    [[ ! -e "$CERT" && ! -e "$KEY" ]] ||
      { echo "Incomplete TLS material; abort" >&2; return 2; }
    as_identity openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
      -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
      -keyout "$KEY" -out "$CERT" 2>/dev/null
  fi
  as_identity "$STATE/venv/bin/python" -m device_fabric.owner_smoke provision \
    --db "$DB" --token-file "$TOKEN"
  sed "s|@SOURCE@|$RELEASE|g" "$RELEASE/deploy/hermes-device-fabric-pilot.service.in" \
    > "/etc/systemd/system/$UNIT"
  chmod 0644 "/etc/systemd/system/$UNIT"
  systemd-analyze verify "/etc/systemd/system/$UNIT"
  systemctl daemon-reload
  echo "PILOT_PREPARED=YES"
  echo "LISTENER=127.0.0.1:$PORT"
  echo "PUBLIC_INGRESS=DISABLED"
  echo "REMOTE_COMMAND_EXECUTION=NOT_IMPLEMENTED"
  echo "PILOT_SERVICE_NOT_STARTED_BY_PREPARE=YES"
}
enable() {
  check_prepared
  # Never start it while a different process occupies the test port.
  if ! systemctl is-active --quiet "$UNIT" && ss -ltn "( sport = :$PORT )" | grep -q LISTEN; then
    echo "PILOT_PORT_IN_USE" >&2
    return 2
  fi
  systemctl enable --now "$UNIT"
  systemctl is-active --quiet "$UNIT"
  systemctl is-enabled "$UNIT"
  echo "PILOT_SERVICE=ACTIVE"
  echo "LISTENER=127.0.0.1:$PORT"
}
smoke() {
  check_prepared
  systemctl is-active --quiet "$UNIT" ||
    { echo "PILOT_SERVICE=INACTIVE" >&2; return 3; }
  as_identity "$STATE/venv/bin/python" -m device_fabric.owner_smoke probe \
    --db "$DB" --token-file "$TOKEN" --cert "$CERT" --port "$PORT"
}
status() {
  if systemctl cat "$UNIT" >/dev/null 2>&1; then
    systemctl show "$UNIT" -p ActiveState -p SubState -p Result -p ExecMainStatus
    systemctl is-enabled "$UNIT" || true
  else
    echo "PILOT_SERVICE=NOT_INSTALLED"
  fi
  if [[ -r "$DB" && -x "$STATE/venv/bin/python" ]] && id "$USER_NAME" >/dev/null 2>&1; then
    as_identity "$STATE/venv/bin/python" -m device_fabric.owner_smoke status \
      --db "$DB" --token-file "$TOKEN"
  fi
  echo "REMOTE_COMMAND_EXECUTION=NOT_IMPLEMENTED"
}
rollback() {
  systemctl disable --now "$UNIT" 2>/dev/null || true
  if [[ -f "/etc/systemd/system/$UNIT" ]]; then
    rm -f "/etc/systemd/system/$UNIT"
    systemctl daemon-reload
  fi
  # Keep only local test DB and credentials for diagnosis/reuse; no secrets printed.
  echo "PILOT_SERVICE_ROLLBACK=COMPLETE"
  echo "REGISTRY_PRESERVED=YES"
}
"$MODE"
