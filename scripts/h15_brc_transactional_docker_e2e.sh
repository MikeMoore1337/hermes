#!/usr/bin/env bash
# H15 #454 -- GitHub-hosted ONLY; real disposable Docker upgrade + rollback.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
fail() { echo "H454_DOCKER_CI_REFUSED=$1" >&2; exit 2; }
[[ "$GITHUB_ACTIONS" == true && "$RUNNER_ENVIRONMENT" == github-hosted &&
   "$RUNNER_OS" == Linux && -n "$GITHUB_RUN_ID" ]] ||
  fail NOT_HOSTED_CI
[[ "$(id -u)" != 0 ]] || fail INTERACTIVE_ROOT_NOT_ALLOWED
cd "$GITHUB_WORKSPACE"
bundle="$RUNNER_TEMP/h15-brc-verified-offline-image"
[[ -f "$bundle/brc-relay.docker.tar.zst" ]] || fail BUNDLE_NOT_READY
image_tag="hermes-brc-relay-eval:$(printf '%s' "$GITHUB_SHA" | cut -c1-12)"
new="$(docker image inspect --format '{{.Id}}' "$image_tag")"
archive_sha="$(sha256sum "$bundle/brc-relay.docker.tar.zst" | awk '{print $1}')"
[[ "$new" =~ ^sha256:[a-f0-9]{64}$ && "$archive_sha" =~ ^[a-f0-9]{64}$ ]] ||
  fail BAD_ARTIFACT_PIN
name=hermes-brc-relay
checkpoint=hermes-brc-relay-h454-rollback
net=hermes-brc-internal
agent="h454-agent-$GITHUB_RUN_ID"
workspace="$RUNNER_TEMP/h454-agent-work"
state=/var/lib/hermes-brc-relay
secrets=/etc/hermes-brc-relay
backups=/var/backups/hermes-brc-relay

for path in "$state" "$secrets" "$backups"; do
  sudo test ! -e "$path" || fail FOREIGN_HOST_PATH
done
for item in "$name" "$checkpoint" "$agent"; do
  if docker container inspect "$item" >/dev/null 2>&1; then fail FOREIGN_CONTAINER; fi
done
if docker network inspect "$net" >/dev/null 2>&1; then fail FOREIGN_NETWORK; fi

cleanup() {
  docker rm -f "$agent" "$name" "$checkpoint" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  sudo rm -rf -- "$state" "$secrets" "$backups"
  sudo rm -rf -- "$workspace"
}
trap cleanup EXIT
sudo install -d -m 700 -o 979 -g 975 "$state"
sudo install -d -m 700 -o root -g root "$secrets" "$backups"
mkdir -m 700 "$workspace"
chmod 0777 "$workspace"
password="$(openssl rand -hex 32)"
session="$(openssl rand -hex 32)"
printf 'BRC_ADMIN_USER=admin\nBRC_ADMIN_PASSWORD=%s\nBRC_SESSION_SECRET=%s\n' "$password" "$session" |
  sudo tee "$secrets/relay.env" >/dev/null
sudo chmod 600 "$secrets/relay.env"
unset password session
docker network create --internal --subnet 172.29.251.0/28 \
  --label com.hermes.scope=h15-brc-relay "$net" >/dev/null

# Synthetic old config ID: same vetted code, changed label, no external pull.
printf 'FROM %s\nLABEL com.hermes.ci.previous="yes"\n' "$image_tag" |
  docker build --pull=false -q -t "h454-ci-old:$GITHUB_RUN_ID" - >/dev/null
old="$(docker image inspect --format '{{.Id}}' "h454-ci-old:$GITHUB_RUN_ID")"
[[ "$old" != "$new" ]] || fail SAME_IMAGE

sudo docker run -d --name "$name" --label com.hermes.scope=h15-brc-owner-relay \
  --network "$net" --ip 172.29.251.2 --read-only --user 979:975 \
  --cap-drop ALL --security-opt no-new-privileges --memory 512m --cpus 0.50 \
  --pids-limit 80 --restart unless-stopped --stop-timeout 20 \
  --mount "type=bind,src=$state,dst=/state" \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,uid=979,gid=975,mode=0700,size=16m \
  --env-file "$secrets/relay.env" \
  -e HOST=0.0.0.0 -e PORT=3000 \
  -e PUBLIC_URL=https://mcp.mikemoore.top -e TRUST_PROXY=false "$old" >/dev/null

health() {
  curl --noproxy '*' --max-time 3 -fsS http://172.29.251.2:3000/health |
    python3 -c 'import sys,json;x=json.load(sys.stdin);assert x["ok"] is True and x["devices"]>=int(sys.argv[1])' "$1"
}
ready=0
for i in $(seq 1 60); do
  if health 0 >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.5
done
[[ "$ready" == 1 ]] || fail OLD_HEALTH

# Issue only disposable one-device credentials, never owner secrets.
tokens="$(docker exec -i "$name" node --input-type=module - < "$GITHUB_WORKSPACE/scripts/h15_brc_two_native_provision.mjs")"
token="$(printf '%s' "$tokens" |
  python3 -c 'import sys,json;print(json.load(sys.stdin)["one"])')"
[[ -n "$token" ]] || fail NO_CI_TOKEN
echo "::add-mask::$token"
docker run -d --name "$agent" --network "$net" \
  --read-only --user 65534:65534 --cap-drop ALL \
  --security-opt no-new-privileges --memory 512m --pids-limit 64 \
  --tmpfs /tmp:rw,nosuid,nodev,uid=65534,gid=65534,size=16m \
  -v "$workspace:/workspace:rw" -e HOME=/workspace -e BRC_HOME=/workspace/.brc \
  -e BRC_RELAY=http://172.29.251.2:3000 \
  -e BRC_DEVICE_ID=ci-native-one -e BRC_NAME="H15 Windows permanent sandbox" \
  -e BRC_TOKEN="$token" "$new" \
  node packages/agent/dist/cli.js --allow-dir /workspace >/dev/null
unset token tokens
ready=0
for i in $(seq 1 80); do
  if health 1 >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.5
done
[[ "$ready" == 1 ]] || fail CI_DEVICE_NOT_ONLINE

# Independently exercise owner one-shot stage with the ACTUAL sealed OCI bytes
# and REAL Docker CLI on this disposable GitHub-hosted daemon. Only the GitHub
# download transport is replaced by a local fixture; no owner token is used.
stage_root="$RUNNER_TEMP/h454-owner-stage"
sudo install -d -m 0700 -o root -g root "$stage_root"
sudo python3 - "$bundle" "$stage_root" "$new" "$archive_sha" "$GITHUB_SHA" <<'PY'
import shutil
import sys
from pathlib import Path
from unittest.mock import patch
from scripts import h15_brc_owner_artifact_stage as stage

bundle, target, image, digest, revision = (
    Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
)

def source_from_local_fixture(*args, **kwargs):
    assert args[:2] == ("run", "download")
    assert "--dir" in args
    output = Path(args[args.index("--dir") + 1])
    for entry in bundle.iterdir():
        assert entry.is_file() and not entry.is_symlink()
        shutil.copy2(entry, output / entry.name)
    return ""

selection = {
    "sha": revision, "run_id": 1, "artifact_id": 1,
    "image": image, "archive": digest,
}
with patch.object(stage, "run", side_effect=source_from_local_fixture):
    result = stage.stage(target, selection, load=True)
assert result["status"] == "IMAGE_LOADED_PREFLIGHT_PASS_NO_CUTOVER"
assert result["live_relay_changed"] is False and result["reused"] is False
with patch.object(stage, "run", side_effect=RuntimeError("unexpected network")):
    again = stage.stage(target, selection, load=False)
assert again["reused"] is True and again["live_relay_changed"] is False
PY
[[ "$(docker inspect --format '{{.Image}}' "$name")" == "$old" ]] ||
  fail STAGING_ALTERED_EXISTING_RELAY
health 1 >/dev/null || fail STAGING_ALTERED_EXISTING_DEVICES
echo "H454_REAL_DOCKER_OWNER_STAGING_LOAD_PREFLIGHT=PASS"

sudo python3 -m scripts.h15_brc_transactional_upgrade plan \
  --bundle-dir "$bundle" --image "$new" --archive-sha "$archive_sha" \
  --hermes-sha "$GITHUB_SHA" |
  python3 -c 'import sys,json;x=json.load(sys.stdin);assert x["status"]=="PLAN_ONLY" and x["changed"] is False'
echo "H454_REAL_DOCKER_PREFLIGHT=PASS"

# Force health failure, but execute REAL Docker stop/rename/run/rollback calls.
sudo python3 - "$new" "$old" <<'PY'
import sys
from unittest.mock import patch
from scripts import h15_brc_transactional_upgrade as u
with patch.object(u,"healthy",side_effect=[True,False,True]):
    try:
        u.swap(sys.argv[1],sys.argv[2],1)
    except u.CutoverDenied as exc:
        if str(exc)!="SWITCH_FAILED_OLD_RELAY_RESTORED":
            raise
    else:
        raise RuntimeError("ROLLBACK_NOT_EXERCISED")
PY
[[ "$(docker inspect --format '{{.Image}}' "$name")" == "$old" ]] ||
  fail OLD_IMAGE_NOT_RESTORED
if docker container inspect "$checkpoint" >/dev/null 2>&1; then fail ORPHANED_CHECKPOINT; fi
ready=0
for i in $(seq 1 80); do
  if health 1 >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.5
done
[[ "$ready" == 1 ]] || fail ROLLBACK_DEVICE_NOT_RECONNECTED
echo "H454_REAL_DOCKER_FAILED_UPGRADE_ROLLBACK=PASS"

python3 - "$new" "$old" "$archive_sha" "$GITHUB_SHA" <<'PY' | sudo tee "$secrets/relay-upgrade-approval.json" >/dev/null
import json,sys
print(json.dumps({
    "schema":1,"decision":"OWNER_APPROVED_LIVE_BRC_RELAY_CUTOVER",
    "scope":"EXISTING_PAIRED_DEVICES_NO_HOST_PERMISSION_CHANGE",
    "image_id":sys.argv[1],"previous_image_id":sys.argv[2],
    "archive_sha256":sys.argv[3],"hermes_commit":sys.argv[4]
},sort_keys=True))
PY
sudo chmod 600 "$secrets/relay-upgrade-approval.json"
sudo python3 -m scripts.h15_brc_transactional_upgrade cutover \
  --bundle-dir "$bundle" --image "$new" --archive-sha "$archive_sha" \
  --hermes-sha "$GITHUB_SHA" --execute |
  python3 -c 'import json,sys;x=json.load(sys.stdin);assert x["status"]=="SWITCHED_PENDING_LIVE_CLIENT_E2E" and x["rollback_container_retained"] is True'

[[ "$(docker inspect --format '{{.Image}}' "$name")" == "$new" ]] ||
  fail NEW_IMAGE_NOT_RUNNING
[[ "$(docker inspect --format '{{.Image}}' "$checkpoint")" == "$old" ]] ||
  fail OLD_CHECKPOINT_NOT_PRESERVED
health 1 >/dev/null || fail DEVICE_NOT_ONLINE_AFTER_REAL_UPGRADE
[[ -z "$(docker port "$name")" ]] || fail UNAPPROVED_PUBLIC_PORTS
sudo find "$backups" -maxdepth 1 -type f -name 'relay-*.sqlite3' | grep -q . ||
  fail SQLITE_BACKUP_MISSING
echo "H454_REAL_DOCKER_SQLITE_BACKUP_REHEARSAL=PASS"
echo "H454_REAL_DOCKER_UPGRADE_AND_RECONNECT=PASS"
echo "H454_OWNER_VPS_CHANGED=NO"
