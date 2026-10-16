#!/bin/sh
# Install only the bounded read-only control-center application; never touch AI agent services.
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Run as root" >&2; exit 1; }
[ "$#" -eq 1 ] || { echo "Usage: install-control-center.sh /path/to/pinned-hermes-release" >&2; exit 2; }
source_dir=$(realpath "$1")
[ -f "$source_dir/control_center/server.py" ] || { echo "Missing server" >&2; exit 2; }
[ -f "$source_dir/control_center/snapshot.py" ] || { echo "Missing collector" >&2; exit 2; }
[ -f "$source_dir/control_center/web/app.js" ] || { echo "Missing UI" >&2; exit 2; }
# Explicitly prohibit using a writable worktree as the installation source.
[ ! -d "$source_dir/.git" ] || { echo "Refuse working git checkout as release" >&2; exit 2; }
id hermes-control >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin hermes-control
install -d -o root -g root -m 0755 /opt/hermes-control-center/releases
install -d -o root -g hermes-control -m 0750 /var/lib/hermes-control-center
stamp=$(date -u +%Y%m%dT%H%M%SZ)
release="/opt/hermes-control-center/releases/$stamp"
install -d -o root -g root -m 0755 "$release/control_center/web"
install -m 0644 "$source_dir/control_center/"*.py "$release/control_center/"
install -m 0644 "$source_dir/control_center/web/"* "$release/control_center/web/"
ln -s "$release" "/opt/hermes-control-center/current.new"
mv -Tf "/opt/hermes-control-center/current.new" "/opt/hermes-control-center/current"
install -m 0644 "$source_dir/deploy/hermes-control-center.service" /etc/systemd/system/
install -m 0644 "$source_dir/deploy/hermes-control-center-snapshot.service" /etc/systemd/system/
install -m 0644 "$source_dir/deploy/hermes-control-center-snapshot.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now hermes-control-center-snapshot.timer
systemctl start hermes-control-center-snapshot.service
systemctl enable --now hermes-control-center.service
curl -fsS --connect-timeout 2 http://127.0.0.1:9133/healthz
printf '\nRelease: %s\nPublic Caddy routing and DNS were NOT modified.\n' "$release"
