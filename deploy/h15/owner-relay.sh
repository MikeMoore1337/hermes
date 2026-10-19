#!/usr/bin/env bash
# H-15 #371/#372: opt-in relay deployment. Never auto-start on merge.
# No Caddy modifications, published ports, or real device enrollment.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

NAME=hermes-brc-relay
LABEL_KEY=com.hermes.scope
LABEL_VALUE=h15-brc-owner-relay
NETWORK=hermes-brc-internal
SUBNET=172.29.251.0/28
RELAY_IP=172.29.251.2
ACCOUNT=hermes-brc-relay
STATE=/var/lib/hermes-brc-relay
SECRETS=/etc/hermes-brc-relay/relay.env
PUBLIC_URL=https://mcp.mikemoore.top
UPSTREAM_SHA=cbe511702dd0147650353c29ac6ab1decd8afda1
EVALUATION_IMAGE=sha256:4f0da80149db3670c3b0d14462e5609225b3718c09872f48e9ba584a4de0a7e6

fail() { echo "H15_BRC_DEPLOY_REFUSED=$1" >&2; exit 2; }
need_root() { [[ "$EUID" -eq 0 ]] || fail ROOT_REQUIRED; }
owned_container() {
  local label
  label="$(docker inspect --type container --format "{{index .Config.Labels \"$LABEL_KEY\"}}" "$NAME" 2>/dev/null)" ||
    fail SERVICE_CONTAINER_NOT_FOUND
  [[ "$label" == "$LABEL_VALUE" ]] || fail FOREIGN_CONTAINER_REFUSED
}
check_env() {
  [[ -f "$SECRETS" && ! -L "$SECRETS" ]] || fail UNSAFE_SECRET_FILE
  [[ "$(stat -c %u:%g "$SECRETS")" == 0:0 &&
     "$(stat -c %a "$SECRETS")" == 600 ]] || fail SECRET_PERMISSIONS
  [[ "$(stat -c %u:%g /etc/hermes-brc-relay)" == 0:0 &&
     "$(stat -c %a /etc/hermes-brc-relay)" == 700 ]] || fail SECRET_DIRECTORY_PERMISSIONS
  python3 - "$SECRETS" <<'PY' || fail SECRET_FORMAT
import re
import sys
from pathlib import Path
data = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    key, sep, value = line.partition("=")
    if not sep or key in data or key not in {"BRC_ADMIN_USER", "BRC_ADMIN_PASSWORD", "BRC_SESSION_SECRET"}:
        raise SystemExit(1)
    data[key] = value
if set(data) != {"BRC_ADMIN_USER", "BRC_ADMIN_PASSWORD", "BRC_SESSION_SECRET"}:
    raise SystemExit(1)
if data["BRC_ADMIN_USER"] != "admin":
    raise SystemExit(1)
if any(re.fullmatch(r"[a-f0-9]{64}", data[k]) is None for k in ("BRC_ADMIN_PASSWORD", "BRC_SESSION_SECRET")):
    raise SystemExit(1)
if data["BRC_ADMIN_PASSWORD"] == data["BRC_SESSION_SECRET"]:
    raise SystemExit(1)
PY
}
check_infrastructure() {
  local uid gid
  command -v docker >/dev/null && command -v python3 >/dev/null &&
    command -v curl >/dev/null || fail DEPENDENCY_MISSING
  docker info >/dev/null 2>&1 || fail DOCKER_UNAVAILABLE
  [[ -d "$STATE" && ! -L "$STATE" ]] || fail UNSAFE_STATE_DIR
  getent passwd "$ACCOUNT" >/dev/null || fail SERVICE_ACCOUNT_MISSING
  [[ "$(getent passwd "$ACCOUNT" | cut -d: -f7)" == /usr/sbin/nologin ]] ||
    fail SERVICE_ACCOUNT_HAS_LOGIN
  uid="$(id -u "$ACCOUNT")"; gid="$(id -g "$ACCOUNT")"
  [[ "$uid" -ne 0 && "$gid" -ne 0 ]] || fail ROOT_IDENTITY_FORBIDDEN
  [[ "$(stat -c %u:%g "$STATE")" == "$uid:$gid" &&
     "$(stat -c %a "$STATE")" == 700 ]] || fail STATE_PERMISSIONS
  check_env
  [[ "$(docker network inspect --format '{{.Internal}}' "$NETWORK" 2>/dev/null)" == true ]] ||
    fail INTERNAL_NETWORK_MISSING
  [[ "$(docker network inspect --format '{{(index .IPAM.Config 0).Subnet}}' "$NETWORK")" == "$SUBNET" ]] ||
    fail UNEXPECTED_NETWORK_SUBNET
  [[ "$(docker network inspect --format '{{index .Labels "com.hermes.scope"}}' "$NETWORK")" == h15-brc-relay ]] ||
    fail FOREIGN_NETWORK_REFUSED
  systemctl is-active --quiet caddy || fail CADDY_NOT_RUNNING
  echo "H15_DEPLOY_HOST_PREFLIGHT=PASS"
  echo "H15_DEPLOY_RUNTIME_UID=$uid:$gid"
}
check_image() {
  local id="$1"
  [[ "$id" =~ ^sha256:[a-f0-9]{64}$ ]] || fail IMMUTABLE_IMAGE_ID_REQUIRED
  [[ "$id" != "$EVALUATION_IMAGE" ]] || fail EVALUATION_IMAGE_NOT_PRODUCTION_APPROVED
  [[ "$(docker image inspect --format '{{.Id}}' "$id" 2>/dev/null)" == "$id" ]] ||
    fail IMAGE_NOT_LOADED_LOCALLY
  [[ "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$id")" == linux/amd64 ]] ||
    fail WRONG_IMAGE_PLATFORM
  [[ "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$id")" == "$UPSTREAM_SHA" ]] ||
    fail WRONG_UPSTREAM_SOURCE
  [[ "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.licenses"}}' "$id")" == MIT ]] ||
    fail MISSING_MIT_LICENSE
  [[ "$(docker image inspect --format '{{json .Config.Cmd}}' "$id")" == '["node","packages/relay/dist/cli.js"]' ]] ||
    fail UNEXPECTED_RUNTIME_COMMAND
  echo "H15_DEPLOY_RELEASE_IMAGE_PREFLIGHT=PASS"
}
public_gate() {
  local status
  status="$(curl --noproxy '*' -sS --connect-timeout 5 --max-time 15 \
    -o /dev/null -w '%{http_code} %{ssl_verify_result}' "$PUBLIC_URL/mcp")" ||
    fail PUBLIC_HTTPS_UNAVAILABLE
  [[ "$status" == "503 0" ]] || fail PUBLIC_MCP_NOT_CLOSED
  echo "PUBLIC_MCP_HTTP=503"
}
probe_local() {
  local url="http://$RELAY_IP:3000" status ready=0
  for _ in $(seq 1 40); do
    if curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 "$url/health" |
      python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["ok"] is True and x["devices"] == 0' \
      >/dev/null 2>&1; then
      ready=1; break
    fi
    sleep 1
  done
  [[ "$ready" == 1 ]] || fail RELAY_HEALTH_FAILED
  echo "RELAY_HEALTH=PASS"
  curl --noproxy '*' -fsS --max-time 5 "$url/.well-known/oauth-authorization-server" |
    python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["issuer"]=="https://mcp.mikemoore.top"; assert "S256" in x["code_challenge_methods_supported"]' ||
    fail OAUTH_METADATA_MISMATCH
  echo "OAUTH_METADATA=PASS"
  status="$(curl --noproxy '*' -sS --max-time 5 -X POST \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    --data '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
    -o /dev/null -w '%{http_code}' "$url/mcp")" ||
    fail MCP_AUTH_PROBE_FAILED
  [[ "$status" == 401 ]] || fail UNAUTHORIZED_MCP_NOT_DENIED
  echo "UNAUTHORIZED_MCP_HTTP=401"
}
[[ $# -ge 1 ]] || fail USAGE_PREFLIGHT_START_STATUS_STOP
mode="$1"
case "$mode" in
  preflight|start)
    [[ $# -eq 2 ]] || fail USAGE_MODE_AND_IMAGE_SHA_REQUIRED
    need_root
    [[ "$2" =~ ^sha256:[a-f0-9]{64}$ ]] || fail IMMUTABLE_IMAGE_ID_REQUIRED
    [[ "$2" != "$EVALUATION_IMAGE" ]] || fail EVALUATION_IMAGE_NOT_PRODUCTION_APPROVED
    check_infrastructure
    check_image "$2"
    ! docker inspect --type container "$NAME" >/dev/null 2>&1 || fail SERVICE_ALREADY_EXISTS
    [[ "$(docker network inspect "$NETWORK" --format '{{len .Containers}}')" == 0 ]] ||
      fail NETWORK_NOT_EMPTY
    public_gate
    if [[ "$mode" == preflight ]]; then
      echo "H15_DEPLOY_CHANGES=NONE"; exit 0
    fi
    [[ "${H15_BRC_OWNER_APPROVED_OAUTH_ONLY:-}" == "YES_OAUTH_ONLY_NO_AGENTS" ]] ||
      fail OWNER_APPROVAL_REQUIRED
    echo "=== START RELAY (UNPAIRED; INTERNAL NETWORK ONLY) ==="
    committed=no
    rollback_new() {
      if [[ "$committed" != yes ]] &&
         [[ "$(docker inspect --type container --format "{{index .Config.Labels \"$LABEL_KEY\"}}" "$NAME" 2>/dev/null || true)" == "$LABEL_VALUE" ]]; then
        docker rm -f "$NAME" >/dev/null 2>&1 || true
      fi
    }
    trap rollback_new EXIT
    docker run -d --name "$NAME" --label "$LABEL_KEY=$LABEL_VALUE" \
      --network "$NETWORK" --ip "$RELAY_IP" \
      --read-only --user "$(id -u "$ACCOUNT"):$(id -g "$ACCOUNT")" \
      --cap-drop ALL --security-opt no-new-privileges \
      --memory 512m --cpus 0.50 --pids-limit 80 --restart unless-stopped \
      --stop-timeout 20 --mount "type=bind,src=$STATE,dst=/state" \
      --tmpfs "/tmp:rw,nosuid,nodev,noexec,uid=$(id -u "$ACCOUNT"),gid=$(id -g "$ACCOUNT"),mode=0700,size=16m" \
      --env-file "$SECRETS" -e HOST=0.0.0.0 -e PORT=3000 \
      -e PUBLIC_URL="$PUBLIC_URL" -e TRUST_PROXY=false "$2" >/dev/null ||
      fail DOCKER_START_FAILED
    owned_container
    [[ -z "$(docker port "$NAME")" ]] || fail UNEXPECTED_PUBLIC_PORTS
    [[ "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$NAME")" == "$NETWORK" ]] ||
      fail UNEXPECTED_NETWORK_MODE
    probe_local
    public_gate
    committed=yes
    trap - EXIT
    echo "H15_DEPLOY_START=PASS"
    echo "PUBLIC_MCP_REVERSE_PROXY=NOT_ENABLED"
    echo "DEVICE_ENROLLMENT=NOT_ENABLED"
    ;;
  status)
    [[ $# -eq 1 ]] || fail EXTRA_ARGUMENTS
    need_root
    if ! docker inspect --type container "$NAME" >/dev/null 2>&1; then
      echo "H15_DEPLOY_STATUS=NOT_INSTALLED"; exit 0
    fi
    owned_container
    docker inspect --format 'H15_DEPLOY_STATUS={{.State.Status}} USER={{.Config.User}} NETWORK={{.HostConfig.NetworkMode}}' "$NAME"
    [[ -z "$(docker port "$NAME")" ]] || fail UNEXPECTED_PUBLIC_PORTS
    echo "PUBLISHED_PORTS=NONE"
    ;;
  stop)
    [[ $# -eq 1 ]] || fail EXTRA_ARGUMENTS
    need_root
    owned_container
    [[ "${H15_BRC_OWNER_APPROVED_STOP:-}" == YES ]] || fail STOP_APPROVAL_REQUIRED
    docker rm -f "$NAME" >/dev/null
    echo "H15_DEPLOY_STOP=PASS"
    echo "PERSISTENT_DB=RETAINED"
    ;;
  *) fail USAGE_PREFLIGHT_START_STATUS_STOP ;;
esac
