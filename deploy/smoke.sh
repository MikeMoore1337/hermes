#!/usr/bin/env bash
# One-shot, no-provider, no-network smoke. Never starts a daemon or publishes.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="nousresearch/hermes-agent@sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22"
python3 "$ROOT/scripts/host_capacity.py" --reserve-mib 128 --margin-mib 32
command -v docker >/dev/null
# Pull is deliberately a separate, operator-controlled step.
docker image inspect "$IMAGE" >/dev/null
ARCH="$(docker image inspect "$IMAGE" --format '{{.Os}}/{{.Architecture}}')"
if [ "$ARCH" != "linux/amd64" ]; then
  echo "Unexpected Docker image platform: $ARCH" >&2
  exit 1
fi
timeout --signal=TERM --kill-after=3s 45s docker run \
  --rm --pull=never --platform linux/amd64 \
  --network none --read-only \
  --user 10000:10000 \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --cpus 0.25 \
  --memory 128m --memory-swap 256m \
  --tmpfs /opt/data:rw,nosuid,nodev,size=32m,uid=10000,gid=10000 \
  --tmpfs /tmp:rw,nosuid,nodev,size=16m \
  --entrypoint /bin/sh \
  "$IMAGE" -c 'command -v hermes && hermes --version'
# Smoke success checks only CLI availability, not model/tool execution.
