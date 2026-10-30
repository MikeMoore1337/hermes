#!/bin/bash
# CI-only synthetic credentials, disposable Docker container and loopback observer.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "$#" -eq 1
base="$1"
test "$(docker image inspect --format '{{.Config.User}}' "$base")" = '65534:65534'
nonce="${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}-${RANDOM}"
case "$nonce" in *[!0-9-]*|'') exit 2;; esac
tmp="$(mktemp -d "${RUNNER_TEMP:?}/h454-offline.XXXXXX")"
image="h454-offline-fixture:$nonce"
container=''
server_pid=''
cleanup() {
  if test -n "$container"; then
    label="$(docker inspect --format '{{index .Config.Labels "com.hermes.h454.fixture"}}' "$container" 2>/dev/null || true)"
    if test "$label" = "$nonce"; then docker rm --force "$container" >/dev/null 2>&1 || true; fi
  fi
  if test -n "$server_pid" && jobs -pr | grep -Fxq "$server_pid"; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  label="$(docker image inspect --format '{{index .Config.Labels "com.hermes.h454.fixture"}}' "$image" 2>/dev/null || true)"
  if test "$label" = "$nonce"; then docker image rm "$image" >/dev/null 2>&1 || true; fi
  case "$tmp" in "$RUNNER_TEMP"/h454-offline.*) rm -rf -- "$tmp";; *) exit 2;; esac
}
trap cleanup EXIT

cat > "$tmp/h15-entry.sh" <<'ENTRY'
set -eu
end=$(($(date +%s) + 90))
while [ ! -f /run/brc/ready ]; do
    if [ "$(date +%s)" -ge "$end" ]; then echo H15_CREDENTIAL_STAGE_TIMEOUT; exit 2; fi
    sleep 1
done
echo H15_AGENT_STARTING
exec node /app/dist/cli.js --no-browser
ENTRY
cat > "$tmp/h15-stage.sh" <<'STAGE'
set -eu
umask 077
[ "$(id -u)" = '65534' ]
[ ! -e /run/brc/device.json ]
printf '{"allowedDirectories":["/workspace"],"telemetryEnabled":false}\n' > /run/brc/config.json
cat > /run/brc/device.json
chmod 0600 /run/brc/config.json /run/brc/device.json
touch /run/brc/ready
STAGE
test "$(sha256sum "$tmp/h15-entry.sh" | cut -d' ' -f1)" = 0bac7cc698ac3a86fbdebbd418bf5a5913b1a8da8ebac7cde45c41af8ab3c8a2
test "$(sha256sum "$tmp/h15-stage.sh" | cut -d' ' -f1)" = 85de2c07ca8128672135d06055a5de521393a876f93ab4f900b819b8bec5f245
cat > "$tmp/cli.js" <<'AGENT'
const fs=require('node:fs'),http=require('node:http');
const d=JSON.parse(fs.readFileSync('/run/brc/device.json','utf8'));
console.log('H454_SYNTHETIC_CONNECT_ATTEMPT');
const req=http.get(d.relayUrl,{headers:{Authorization:'Bearer '+d.deviceToken}},r=>r.resume());
req.on('error',()=>console.log('H454_SYNTHETIC_CONNECT_FAILED'));
req.setTimeout(2000,()=>req.destroy());
setInterval(()=>{},1000);
AGENT
cat > "$tmp/Dockerfile" <<'DOCKER'
ARG H454_TEST_BASE
FROM ${H454_TEST_BASE}
USER 0:0
RUN mkdir -p /app/dist
COPY h15-entry.sh h15-stage.sh /usr/local/bin/
COPY cli.js /app/dist/cli.js
USER 65534:65534
DOCKER
docker build --quiet --pull=false --network none --build-arg "H454_TEST_BASE=$base" \
  --label "com.hermes.h454.fixture=$nonce" --tag "$image" "$tmp" >/dev/null

cat > "$tmp/observer.cjs" <<'OBSERVER'
const fs=require('node:fs'),http=require('node:http');
const [portFile,events,gateway]=process.argv.slice(2);
const server=http.createServer((req,res)=>{
  fs.appendFileSync(events,req.headers.authorization?'auth\n':'probe\n');
  res.writeHead(401);res.end();
});
server.listen(0,gateway,()=>fs.writeFileSync(portFile,String(server.address().port)));
OBSERVER
gateway="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')"
node -e 'if(require("node:net").isIP(process.argv[1])!==4)process.exit(1)' "$gateway"
node "$tmp/observer.cjs" "$tmp/port" "$tmp/events" "$gateway" &
server_pid=$!
for _ in $(seq 1 50); do test -s "$tmp/port" && break; sleep 0.1; done
test -s "$tmp/port"
port="$(cat "$tmp/port")"
case "$port" in *[!0-9]*|'') exit 2;; esac
token="brc_dev_$(printf 'a%.0s' $(seq 1 43))"
credential="$(printf '{"relayUrl":"http://host.docker.internal:%s","deviceId":"synthetic-device","deviceToken":"%s","name":"fixture","pairedAt":"manual"}' "$port" "$token")"
container="$(docker create --pull never --network bridge --read-only --init --cap-drop ALL \
  --security-opt no-new-privileges --user 65534:65534 --memory 256m --pids-limit 64 \
  --label "com.hermes.h454.fixture=$nonce" --add-host host.docker.internal:host-gateway \
  --tmpfs /run/brc:rw,nosuid,nodev,noexec,uid=65534,gid=65534,mode=0700,size=8m \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,uid=65534,gid=65534,mode=1777,size=16m \
  --entrypoint /bin/sh "$image" /usr/local/bin/h15-entry.sh)"
case "$container" in *[!a-f0-9]*|'') exit 2;; esac
test "${#container}" -eq 64
test "$(docker inspect --format '{{index .Config.Labels "com.hermes.h454.fixture"}}' "$container")" = "$nonce"

for cycle in 1 2; do
  docker start "$container" >/dev/null
  docker exec "$container" /bin/sh -c 'test ! -e /run/brc/ready && test ! -e /run/brc/device.json'
  networks="$(docker inspect --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}' "$container")"
  if test "$cycle" = 1; then
    test "$networks" = bridge
    docker exec "$container" node -e '
      const http=require("node:http"),port=process.argv[1];
      http.get("http://host.docker.internal:"+port,{headers:{Authorization:"Bearer synthetic"}},r=>r.resume())
        .on("error",()=>process.exit(1));' "$port"
    for _ in $(seq 1 30); do test -s "$tmp/events" && break; sleep 0.1; done
    test "$(grep -c '^auth$' "$tmp/events")" = 1
  fi
  case "$networks" in bridge) docker network disconnect bridge "$container";; '') :;; *) exit 2;; esac
  test "$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$container")" = 0
  docker exec "$container" node -e 'if(Object.keys(require("node:os").networkInterfaces()).some(k=>k!=="lo"))process.exit(1)'
  printf '%s' "$credential" | docker exec --interactive "$container" /bin/sh /usr/local/bin/h15-stage.sh
  if printf '%s' "$credential" | docker exec --interactive "$container" /bin/sh /usr/local/bin/h15-stage.sh >/dev/null 2>&1; then exit 2; fi
  docker exec "$container" node -e '
    const fs=require("node:fs"),a=require("node:assert/strict");
    const d=JSON.parse(fs.readFileSync("/run/brc/device.json","utf8"));
    a.equal(d.deviceId,"synthetic-device");a.equal(d.pairedAt,"manual");
    a.equal(d.deviceToken,"brc_dev_"+"a".repeat(43));
    a.equal(fs.statSync("/run/brc/device.json").mode&0o777,0o600);
    a(fs.existsSync("/run/brc/ready"));'
  for _ in $(seq 1 50); do
    count="$(docker logs "$container" 2>&1 | grep -c '^H454_SYNTHETIC_CONNECT_FAILED$' || true)"
    test "$count" -ge "$cycle" && break
    sleep 0.1
  done
  test "$count" -ge "$cycle"
  node -e '
    const http=require("node:http"),host=process.argv[1],port=process.argv[2];
    http.get("http://"+host+":"+port,r=>{if(r.statusCode!==401)process.exit(1);r.resume()})
      .on("error",()=>process.exit(1));' "$gateway" "$port"
  test "$(grep -c '^auth$' "$tmp/events")" = 1
  if test "$cycle" = 1; then docker stop --time 5 "$container" >/dev/null; fi
done
echo 'H454_CI_ISOLATED_OFFLINE_STAGING_ORDER=PASS'
echo 'H454_CI_SYNTHETIC_LISTENER_RECEIVED_NO_STAGED_TOKEN=PASS'
