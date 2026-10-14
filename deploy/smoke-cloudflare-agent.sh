#!/usr/bin/env bash
# One bounded real Hermes turn with todo-only tools; no gateway, scheduler or publishing.
set -euo pipefail
ROOT=/opt/hermes-agent-owner
STATE=/var/lib/hermes-agent
IMAGE='nousresearch/hermes-agent@sha256:32d095e84190ae7266afbb361579e6921f2c633e899f5eacfb88111b9c851a22'
if [ "$(id -u)" -ne 0 ]; then echo "root required" >&2; exit 1; fi
test "$(stat -c %a "$STATE/.env")" = 600
test "$(stat -c %U "$STATE/.env")" = hermes-agent
systemctl is-active --quiet hermes-cloudflare-proxy.service
nft list table inet hermes_agent_isolation >/dev/null
docker network inspect hermes-agent-isolated >/dev/null
python3 "$ROOT/scripts/host_capacity.py" --reserve-mib 640 --margin-mib 256
if docker inspect hermes-agent-test >/dev/null 2>&1; then
  echo "Another agent test exists" >&2
  exit 1
fi
timeout --signal=TERM --kill-after=5s 75s docker run --rm --name hermes-agent-test \
  --pull=never --platform linux/amd64 \
  --network hermes-agent-isolated --ip 172.29.250.2 \
  --read-only --user "$(id -u hermes-agent):$(id -g hermes-agent)" \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 96 --cpus 0.15 --memory 640m --memory-swap 896m \
  --tmpfs /tmp:rw,nosuid,nodev,size=32m \
  --tmpfs /run:rw,nosuid,nodev,size=16m \
  --mount type=bind,src="$STATE",dst=/opt/data \
  --env-file "$STATE/.env" --env HERMES_HOME=/opt/data \
  --env HTTPS_PROXY=http://172.29.250.1:18573 \
  --env HTTP_PROXY=http://172.29.250.1:18573 \
  --env NO_PROXY=localhost,127.0.0.1 \
  --entrypoint /opt/hermes/bin/hermes "$IMAGE" \
  chat -q "Answer with one word: OK" --oneshot -Q -t todo
