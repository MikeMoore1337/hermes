#!/usr/bin/env bash
# No-provider, no-network preview. This script is not a production gateway.
set -euo pipefail

# No default image: only an operator-selected, inspected patched derivative.
NAME='hermes-agent-sandbox'
STATE='/var/lib/hermes-agent'
ROOT='/opt/hermes-agent-owner'
# shellcheck source=deploy/require-patched-agent-image.sh
source "$ROOT/deploy/require-patched-agent-image.sh"
require_patched_agent_image

if [ "$(id -u)" -ne 0 ]; then
  echo "Docker launcher requires reviewed administrator context" >&2
  exit 1
fi
if [ ! -d "$STATE" ] || [ -L "$STATE" ]; then
  echo "Agent data directory missing or unsafe" >&2
  exit 1
fi
UID_HERMES="$(id -u hermes-agent)"
GID_HERMES="$(id -g hermes-agent)"
if [ "$(stat -c %u "$STATE")" != "$UID_HERMES" ] || [ "$(stat -c %g "$STATE")" != "$GID_HERMES" ] || [ "$(stat -c %a "$STATE")" != 700 ]; then
  echo "Agent data owner/mode mismatch" >&2
  exit 1
fi

python3 "$ROOT/scripts/host_capacity.py" --reserve-mib 640 --margin-mib 256
docker image inspect "$IMAGE" >/dev/null
if docker container inspect "$NAME" >/dev/null 2>&1; then
  echo "Refusing to overlap another Hermes sandbox" >&2
  exit 1
fi

exec docker run --rm --name "$NAME" --init \
  --pull=never --platform linux/amd64 \
  --network none --read-only \
  --user "$UID_HERMES:$GID_HERMES" \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 96 --cpus 0.5 \
  --memory 640m --memory-swap 896m \
  --tmpfs /tmp:rw,nosuid,nodev,size=32m \
  --tmpfs /run:rw,nosuid,nodev,size=16m \
  --mount type=bind,src="$STATE",dst=/opt/data \
  --env HERMES_HOME=/opt/data \
  --entrypoint /opt/hermes/bin/hermes \
  "$IMAGE" gateway run
