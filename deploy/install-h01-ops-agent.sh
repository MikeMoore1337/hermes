#!/usr/bin/env bash
# Owner-authorized H-01 #33: install ONLY the bounded read-only Ops AI timer.
# Must be invoked manually on the existing Hermes VPS after exact-SHA CD.
set -euo pipefail
umask 077
BASE=/opt/hermes-agent-owner
PIN=/etc/hermes-agent/h01-image.env
STATE=/var/lib/hermes-h01
SERVICE=hermes-h01-ops-agent.service
TIMER=hermes-h01-ops-agent.timer
[[ "$EUID" == 0 ]] || { echo "H01_DENIED: root_required" >&2; exit 2; }
[[ "${HERMES_H01_OWNER_APPROVED:-}" == 1 ]] ||
  { echo "H01_DENIED: owner_gate_closed" >&2; exit 2; }
[[ "${HERMES_AGENT_RUNTIME_IMAGE:-}" =~ ^sha256:[a-f0-9]{64}$ ]] ||
  { echo "H01_DENIED: invalid_image_id" >&2; exit 2; }
image="$HERMES_AGENT_RUNTIME_IMAGE"
actual="$(docker image inspect "$image" --format '{{.Id}}|{{.Architecture}}|{{index .Config.Labels "hermes.base.commit"}}|{{index .Config.Labels "hermes.native.tool.policy"}}')"
[[ "$actual" == "$image|amd64|d923a5eb487a17c0a68801bba9ef0f56c81040a8|bounded-v0222" ]] ||
  { echo "H01_DENIED: patch_identity_mismatch" >&2; exit 2; }
sha="$(cat /var/lib/hermes-main-deploy/last-success.sha)"
[[ "$sha" =~ ^[a-f0-9]{40}$ ]] || exit 2
release="$BASE/releases/main-$sha"
[[ -f "$release/.deployment-receipt.txt" ]] || exit 2
grep -Fxq "SHA=$sha" "$release/.deployment-receipt.txt" || exit 2
for f in "$SERVICE" "$TIMER"; do
  [[ -r "$release/deploy/$f" ]] || exit 2
  if [[ -e "/etc/systemd/system/$f" ]]; then
    cmp -s "$release/deploy/$f" "/etc/systemd/system/$f" ||
      { echo "H01_DENIED: unit_conflict:$f" >&2; exit 2; }
  fi
done
/usr/bin/python3 "$BASE/scripts/ensure_cloudflare_egress.py" --check >/dev/null
systemctl is-active --quiet hermes-cloudflare-network-guard.service
/usr/bin/python3 "$BASE/scripts/host_capacity.py" --reserve-mib 640 --margin-mib 256 >/dev/null
test "$(stat -c %a /var/lib/hermes-agent/.env)" = 600
install -d -m 0700 -o root -g root "$STATE"
install -d -m 0700 -o root -g root /etc/hermes-agent
if [[ -e "$PIN" ]]; then
  [[ "$(cat "$PIN")" == "HERMES_AGENT_RUNTIME_IMAGE=$image" ]] ||
    { echo "H01_DENIED: image_pin_conflict" >&2; exit 2; }
else
  printf 'HERMES_AGENT_RUNTIME_IMAGE=%s\n' "$image" | install -m 0600 /dev/stdin "$PIN"
fi
for f in "$SERVICE" "$TIMER"; do
  if [[ ! -e "/etc/systemd/system/$f" ]]; then
    install -m 0644 "$release/deploy/$f" "/etc/systemd/system/$f"
  fi
done
systemd-analyze verify "/etc/systemd/system/$SERVICE" "/etc/systemd/system/$TIMER"
systemctl daemon-reload
# The narrow relay is bound to the internal Docker bridge, not a public port.
systemctl enable --now hermes-cloudflare-proxy.service
# Prove first run without scheduling another model call on an empty journal.
systemctl start "$SERVICE"
systemctl is-active --quiet hermes-control-center.service
systemctl is-active --quiet hermes-ops-watch.timer
systemctl is-active --quiet hermes-discovery.timer
systemctl enable --now "$TIMER"
systemctl is-active --quiet "$TIMER"
echo "H01_LIMITED_RESIDENT_OPS_ACTIVE=yes"
echo "H01_RESIDENT_IMAGE=$image"
echo "H01_SOURCE_SHA=$sha"
