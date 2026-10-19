#!/usr/bin/env bash
# H-15 #371 — OFFLINE staging only. No agents, network, ports or persistent DB.
# Use ONLY a reviewed image sha256 ID already loaded on the target host.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
NAME=hermes-brc-stage-h15
LABEL_KEY=com.hermes.scope
LABEL_VALUE=h15-brc-offline-stage
UPSTREAM_SHA=cbe511702dd0147650353c29ac6ab1decd8afda1
fail() { echo "H15_STAGE_REFUSED=$1" >&2; exit 2; }
need_root() { [[ "$EUID" == 0 ]] || fail ROOT_REQUIRED; }
our_container() {
  local label
  label="$(docker inspect --type container --format "{{index .Config.Labels \"$LABEL_KEY\"}}" "$NAME" 2>/dev/null)" ||
    fail STAGE_CONTAINER_MISSING
  [[ "$label" == "$LABEL_VALUE" ]] || fail FOREIGN_CONTAINER_NOT_OWNED
}
preflight() {
  local id="$1" env_names mem
  [[ "$id" =~ ^sha256:[a-f0-9]{64}$ ]] || fail IMMUTABLE_IMAGE_ID_REQUIRED
  command -v docker >/dev/null || fail DOCKER_NOT_INSTALLED
  command -v openssl >/dev/null || fail OPENSSL_NOT_INSTALLED
  docker info >/dev/null 2>&1 || fail DOCKER_NOT_AVAILABLE
  [[ "$(docker image inspect --format '{{.Id}}' "$id" 2>/dev/null)" == "$id" ]] ||
    fail IMAGE_NOT_LOADED_LOCALLY
  [[ "$(docker image inspect --format '{{.Config.User}}' "$id")" == 65534:65534 ]] ||
    fail IMAGE_NOT_NONROOT
  [[ "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$id")" == "$UPSTREAM_SHA" ]] ||
    fail WRONG_UPSTREAM_SOURCE
  [[ "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.licenses"}}' "$id")" == MIT ]] ||
    fail MISSING_MIT_LICENSE
  [[ "$(docker image inspect --format '{{json .Config.Cmd}}' "$id")" == '["node","packages/relay/dist/cli.js"]' ]] ||
    fail UNEXPECTED_RUNTIME_COMMAND
  env_names="$(docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$id" | sed 's/=.*//')"
  if printf '%s\n' "$env_names" | grep -Eq '^(BRC_ADMIN_PASSWORD|BRC_SESSION_SECRET|BRC_TOKEN|BRC_DEVICE_ID|GITHUB_TOKEN|GH_TOKEN)$'; then
    fail IMAGE_BAKED_SECRETS
  fi
  if [[ -r /proc/meminfo ]]; then
    mem="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
    [[ "$mem" =~ ^[0-9]+$ && "$mem" -ge 786432 ]] || fail VPS_MEMORY_TOO_LOW
  fi
  echo "H15_STAGE_PREFLIGHT=PASS"
  echo "IMAGE_ID=$id"
}
contract() {
  our_container
  [[ "$(docker inspect --type container --format '{{.HostConfig.NetworkMode}}' "$NAME")" == none &&
     "$(docker inspect --type container --format '{{.HostConfig.ReadonlyRootfs}}' "$NAME")" == true &&
     "$(docker inspect --type container --format '{{.Config.User}}' "$NAME")" == 65534:65534 &&
     "$(docker inspect --type container --format '{{.HostConfig.Privileged}}' "$NAME")" == false &&
     "$(docker inspect --type container --format '{{len .Mounts}}' "$NAME")" == 0 &&
     "$(docker inspect --type container --format '{{.HostConfig.RestartPolicy.Name}}' "$NAME")" == no &&
     "$(docker inspect --type container --format '{{json .HostConfig.CapDrop}}' "$NAME")" == '["ALL"]' &&
     -z "$(docker port "$NAME")" ]] || fail SANDBOX_BOUNDARY_NOT_ENFORCED
  echo "H15_STAGE_NETWORK=NONE"
  echo "H15_STAGE_HOST_MOUNTS=NONE"
  echo "H15_STAGE_PUBLIC_PORTS=NONE"
}
smoke() {
  contract
  [[ "$(docker inspect --type container --format '{{.State.Running}}' "$NAME")" == true ]] ||
    fail STAGE_NOT_RUNNING
  docker exec "$NAME" node --input-type=module -e '
    import fs from "node:fs";
    const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    let health;
    for (let i = 0; i < 40; i++) {
      try {
        const r = await fetch("http://127.0.0.1:3000/health", {
          signal: AbortSignal.timeout(1000)
        });
        if (r.ok) { health = await r.json(); break; }
      } catch {}
      await pause(200);
    }
    if (health?.ok !== true || health.devices !== 0)
      throw Error("RELAY_UNHEALTHY_OR_DEVICE_CONNECTED");
    if (process.getuid() !== 65534 ||
        !fs.existsSync("/state/relay.sqlite") ||
        fs.existsSync("/var/lib/hermes-device-fabric/devices.sqlite3"))
      throw Error("INVALID_RUNTIME_IDENTITY_OR_STATE");
    const reply = await fetch("http://127.0.0.1:3000/mcp", {
      method:"POST",
      headers: { "content-type":"application/json",
        "accept":"application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc:"2.0", id:1, method:"tools/list", params:{} })
    });
    if (reply.status !== 401) throw Error("MCP_NOT_AUTHENTICATED");
    console.log("H15_STAGE_ZERO_DEVICES=PASS");
    console.log("H15_STAGE_UNAUTHENTICATED_MCP=401");
  ' || fail RELAY_SMOKE_FAILED
  echo "H15_STAGE_SMOKE=PASS"
  echo "OWNER_REMOTE_COMMANDS=NOT_ENABLED"
}
mode="$1"
case "$mode" in
  preflight|start)
    [[ $# == 2 ]] || fail EXACT_IMAGE_ID_REQUIRED
    need_root
    preflight "$2"
    if [[ "$mode" == preflight ]]; then
      echo "H15_STAGE_CHANGES=NONE"; exit 0
    fi
    docker inspect --type container "$NAME" >/dev/null 2>&1 && fail STAGE_ALREADY_EXISTS
    admin="$(openssl rand -hex 32)"
    session="$(openssl rand -hex 32)"
    [[ "$admin" =~ ^[a-f0-9]{64}$ && "$session" =~ ^[a-f0-9]{64}$ ]] ||
      fail EPHEMERAL_SECRET_GENERATION_FAILED
    docker run -d --name "$NAME" --label "$LABEL_KEY=$LABEL_VALUE" \
      --network none --read-only --user 65534:65534 --cap-drop ALL \
      --security-opt no-new-privileges --memory 512m --cpus 0.50 \
      --pids-limit 80 --restart no \
      --tmpfs /state:rw,nosuid,nodev,noexec,uid=65534,gid=65534,mode=0700,size=32m \
      --tmpfs /tmp:rw,nosuid,nodev,uid=65534,gid=65534,mode=0700,size=16m \
      -e HOST=127.0.0.1 -e PORT=3000 \
      -e PUBLIC_URL=http://localhost:3000 \
      -e BRC_ADMIN_PASSWORD="$admin" -e BRC_SESSION_SECRET="$session" \
      "$2" >/dev/null || fail DOCKER_START_FAILED
    unset admin session
    if ! smoke; then
      our_container
      docker rm -f "$NAME" >/dev/null 2>&1 || true
      fail STAGING_START_ACCEPTANCE_FAILED
    fi
    echo "H15_STAGE_STARTED=YES"
    echo "H15_STAGE_PUBLIC_MCP=DISABLED"
    ;;
  status|smoke|rollback)
    [[ $# == 1 ]] || fail EXTRA_ARGUMENTS_NOT_ALLOWED
    need_root
    command -v docker >/dev/null || fail DOCKER_NOT_INSTALLED
    if [[ "$mode" == status ]]; then
      if ! docker inspect --type container "$NAME" >/dev/null 2>&1; then
        echo "H15_STAGE_STATUS=NOT_INSTALLED"; exit 0
      fi
      contract
      docker inspect --type container --format 'H15_STAGE_STATUS={{.State.Status}}' "$NAME"
      echo "H15_STAGE_OWNER_DEVICES=NONE"
    elif [[ "$mode" == smoke ]]; then
      smoke
    else
      if docker inspect --type container "$NAME" >/dev/null 2>&1; then
        our_container
        docker rm -f "$NAME" >/dev/null || fail ROLLBACK_FAILED
      fi
      echo "H15_STAGE_ROLLBACK=COMPLETE"
      echo "OTHER_HERMES_SERVICES=UNTOUCHED"
    fi
    ;;
  *) fail USAGE_PREFLIGHT_START_STATUS_SMOKE_ROLLBACK ;;
esac
