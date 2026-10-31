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
proxy_image="h454-offline-proxy:$nonce"
relay_image="h454-offline-relay:$nonce"
wss_proxy_image="h454-wss-restart-fixture:$nonce"
container=''
isolated=''
sidecar=''
relay=''
network_id=''
upstream_network=''
server_pid=''
ns_relay=''
ns_proxy=''
ns_probe=''
ns_network=''
cleanup() {
  for fixture in "$ns_proxy" "$ns_probe" "$ns_relay" "$container" "$isolated" "$sidecar" "$relay"; do
    if test -n "$fixture"; then
      label="$(docker inspect --format '{{index .Config.Labels "com.hermes.h454.fixture"}}' "$fixture" 2>/dev/null || true)"
      if test "$label" = "$nonce"; then docker rm --force "$fixture" >/dev/null 2>&1 || true; fi
    fi
  done
  for network in "$ns_network" "$network_id" "$upstream_network"; do
    if test -n "$network"; then
      label="$(docker network inspect --format '{{index .Labels "com.hermes.h454.fixture"}}' "$network" 2>/dev/null || true)"
      if test "$label" = "$nonce"; then docker network rm "$network" >/dev/null 2>&1 || true; fi
    fi
  done
  if test -n "$server_pid" && jobs -pr | grep -Fxq "$server_pid"; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  for fixture_image in "$wss_proxy_image" "$image" "$proxy_image" "$relay_image"; do
    label="$(docker image inspect --format '{{index .Config.Labels "com.hermes.h454.fixture"}}' "$fixture_image" 2>/dev/null || true)"
    if test "$label" = "$nonce"; then docker image rm "$fixture_image" >/dev/null 2>&1 || true; fi
  done
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

# Feasibility only: no TLS sidecar or live Windows behavior is implied.
network_id="$(docker network create --internal --label "com.hermes.h454.fixture=$nonce" "h454-internal-$nonce")"
sidecar="$(docker create --pull never --network "$network_id" --network-alias host.docker.internal \
  --read-only --init --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 \
  --memory 128m --pids-limit 32 --label "com.hermes.h454.fixture=$nonce" --entrypoint node "$image" -e '
    const http=require("node:http");
    http.createServer((q,r)=>{console.log(q.headers.authorization?"H454_SYNTHETIC_AUTH":"H454_SYNTHETIC_PROBE");r.writeHead(401);r.end()})
      .listen(38180,"0.0.0.0",()=>console.log("H454_SYNTHETIC_ALIAS_READY"));')"
docker start "$sidecar" >/dev/null
for _ in $(seq 1 50); do
  docker logs "$sidecar" 2>&1 | grep -q '^H454_SYNTHETIC_ALIAS_READY$' && break
  sleep 0.1
done
docker logs "$sidecar" 2>&1 | grep -q '^H454_SYNTHETIC_ALIAS_READY$'
side_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$sidecar")"
node -e 'if(require("node:net").isIP(process.argv[1])!==4)process.exit(1)' "$side_ip"
isolated="$(docker create --pull never --network bridge --read-only --init --cap-drop ALL \
  --security-opt no-new-privileges --user 65534:65534 --memory 256m --pids-limit 64 \
  --label "com.hermes.h454.fixture=$nonce" \
  --tmpfs /run/brc:rw,nosuid,nodev,noexec,uid=65534,gid=65534,mode=0700,size=8m \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,uid=65534,gid=65534,mode=1777,size=16m \
  --entrypoint /bin/sh "$image" /usr/local/bin/h15-entry.sh)"
docker start "$isolated" >/dev/null
docker exec "$isolated" /bin/sh -c 'test ! -e /run/brc/ready && test ! -e /run/brc/device.json'
docker network disconnect bridge "$isolated"
docker network connect "$network_id" "$isolated"
test "$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$isolated")" = 1
if ! timeout 8s docker exec "$isolated" node -e '
  const dns=require("node:dns"),expected=process.argv[1];
  dns.lookup("host.docker.internal",{all:true,verbatim:true},(e,a)=>
    process.exit(e||!a.length||a.some(x=>x.address!==expected)?1:0));' "$side_ip"; then
  echo 'H454_INTERNAL_ALIAS_FEASIBILITY=HOLD'
  exit 1
fi
docker exec "$isolated" node -e '
  const http=require("node:http"),host=process.argv[1],port=process.argv[2];
  const q=http.get("http://"+host+":"+port,()=>process.exit(1));
  q.on("error",()=>process.exit(0));q.setTimeout(2000,()=>{q.destroy();process.exit(0)});' "$gateway" "$port"
isolated_credential="$(printf '{"relayUrl":"http://host.docker.internal:38180","deviceId":"synthetic-device","deviceToken":"%s","name":"fixture","pairedAt":"manual"}' "$token")"
printf '%s' "$isolated_credential" | docker exec --interactive "$isolated" /bin/sh /usr/local/bin/h15-stage.sh
for _ in $(seq 1 50); do
  docker logs "$sidecar" 2>&1 | grep -q '^H454_SYNTHETIC_AUTH$' && break
  sleep 0.1
done
docker logs "$sidecar" 2>&1 | grep -q '^H454_SYNTHETIC_AUTH$'
test "$(grep -c '^auth$' "$tmp/events")" = 1
echo 'H454_INTERNAL_ALIAS_FEASIBILITY=PASS_SYNTHETIC_ONLY'

# Test the same staged fixture through an isolated proxy and a pinned TLS relay.
# Both networks, certificates, keys and credentials are disposable CI fixtures.
docker stop --time 5 "$isolated" >/dev/null
test "$(docker inspect --format '{{index .Config.Labels "com.hermes.h454.fixture"}}' "$sidecar")" = "$nonce"
docker rm --force "$sidecar" >/dev/null
sidecar=''
mkdir "$tmp/certs"
bash scripts/h454_wss_fixture_certificates.sh "$tmp/certs" >/dev/null
cp "$tmp/certs/relay-ca.pem" "$tmp/relay-ca.pem"
cp "$tmp/certs/trusted.crt" "$tmp/certs/trusted.key" "$tmp/"
cp scripts/h454_isolated_rollback_proxy.mjs "$tmp/"
docker build --quiet --pull=false --network none --build-arg "H454_BASE_IMAGE=$base" \
  --label "com.hermes.h454.fixture=$nonce" --file deploy/h15/Dockerfile.brc-rollback-proxy \
  --tag "$proxy_image" "$tmp" >/dev/null
cat > "$tmp/Dockerfile.relay" <<'DOCKER'
ARG H454_TEST_BASE
FROM ${H454_TEST_BASE}
USER 0:0
RUN mkdir -p /fixtures
COPY trusted.crt trusted.key /fixtures/
USER 65534:65534
DOCKER
docker build --quiet --pull=false --network none --build-arg "H454_TEST_BASE=$base" \
  --label "com.hermes.h454.fixture=$nonce" --file "$tmp/Dockerfile.relay" \
  --tag "$relay_image" "$tmp" >/dev/null
upstream_network="$(docker network create --internal --label "com.hermes.h454.fixture=$nonce" "h454-upstream-$nonce")"
relay="$(docker create --pull never --network "$upstream_network" --read-only --init --cap-drop ALL \
  --security-opt no-new-privileges --user 65534:65534 --memory 128m --pids-limit 32 \
  --label "com.hermes.h454.fixture=$nonce" --entrypoint node "$relay_image" -e '
    const fs=require("node:fs"),tls=require("node:tls");
    const server=tls.createServer({cert:fs.readFileSync("/fixtures/trusted.crt"),key:fs.readFileSync("/fixtures/trusted.key")},s=>{
      let received="";s.on("error",()=>{});s.on("data",chunk=>{
        received+=chunk.toString();if(received.length>8192)return s.destroy();
        if(received.includes("\r\n\r\n")){
          if(received.includes("Bearer brc_dev_"+"a".repeat(43)))console.log("H454_TEST_TLS_AUTH");
          s.end("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
        }
      });
    });server.on("tlsClientError",()=>{});server.listen(38184,"0.0.0.0",()=>console.log("H454_TEST_TLS_READY"));')"
docker start "$relay" >/dev/null
for _ in $(seq 1 50); do
  docker logs "$relay" 2>&1 | grep -q '^H454_TEST_TLS_READY$' && break
  sleep 0.1
done
docker logs "$relay" 2>&1 | grep -q '^H454_TEST_TLS_READY$'
relay_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$relay")"
node -e 'if(require("node:net").isIP(process.argv[1])!==4)process.exit(1)' "$relay_ip"
ca_hash="$(sha256sum "$tmp/relay-ca.pem" | cut -d' ' -f1)"
sidecar="$(docker create --pull never --network "$network_id" --network-alias host.docker.internal \
  --read-only --init --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 \
  --memory 128m --pids-limit 32 --label "com.hermes.h454.fixture=$nonce" \
  "$proxy_image" "$relay_ip" "$ca_hash")"
docker start "$sidecar" >/dev/null
for _ in $(seq 1 50); do
  docker logs "$sidecar" 2>&1 | grep -q '^H454_ROLLBACK_PROXY_READY$' && break
  sleep 0.1
done
docker logs "$sidecar" 2>&1 | grep -q '^H454_ROLLBACK_PROXY_READY$'
side_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$sidecar")"
docker network connect --alias "h454-u-$nonce" "$upstream_network" "$sidecar"
test "$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$sidecar")" = 2
docker exec "$relay" node -e '
  const net=require("node:net"),s=net.connect(38180,process.argv[1]);
  s.on("connect",()=>process.exit(1));s.on("error",e=>process.exit(e.code==="ECONNREFUSED"?0:1));
  setTimeout(()=>process.exit(1),2000).unref();' "h454-u-$nonce"
docker start "$isolated" >/dev/null
docker exec "$isolated" /bin/sh -c 'test ! -e /run/brc/ready && test ! -e /run/brc/device.json'
test "$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$isolated")" = 1
timeout 8s docker exec "$isolated" node -e '
  const dns=require("node:dns"),expected=process.argv[1];
  dns.lookup("host.docker.internal",{all:true,verbatim:true},(e,a)=>
    process.exit(e||!a.length||a.some(x=>x.address!==expected)?1:0));' "$side_ip"
printf '%s' "$isolated_credential" | docker exec --interactive "$isolated" /bin/sh /usr/local/bin/h15-stage.sh
for _ in $(seq 1 50); do
  docker logs "$relay" 2>&1 | grep -q '^H454_TEST_TLS_AUTH$' && break
  sleep 0.1
done
docker logs "$relay" 2>&1 | grep -q '^H454_TEST_TLS_AUTH$'
test "$(grep -c '^auth$' "$tmp/events")" = 1
echo 'H454_SYNTHETIC_RESTAGE_VIA_ISOLATED_PINNED_TLS=PASS'
echo 'H454_SYNTHETIC_PROXY_UPSTREAM_LISTENER_CLOSED=PASS'

# A namespace-sharing WSS proxy must rejoin the relay after its container restarts.
cp scripts/h454_wss_relay_proxy.mjs "$tmp/"
cat > "$tmp/Dockerfile.wss-restart" <<'DOCKER'
ARG H454_TEST_BASE
FROM ${H454_TEST_BASE}
USER 0:0
COPY h454_wss_relay_proxy.mjs /opt/h454-wss-proxy.mjs
COPY trusted.key /run/h454-wss/relay.key
COPY trusted.crt /run/h454-wss/relay.crt
COPY relay-ca.pem /run/h454-wss/relay-ca.pem
USER 65534:65534
ENTRYPOINT ["node", "/opt/h454-wss-proxy.mjs"]
DOCKER
docker build --quiet --pull=false --network none --build-arg "H454_TEST_BASE=$base" \
  --label "com.hermes.h454.fixture=$nonce" --file "$tmp/Dockerfile.wss-restart" \
  --tag "$wss_proxy_image" "$tmp" >/dev/null
ns_network="$(docker network create --internal --label "com.hermes.h454.fixture=$nonce" "h454-ns-$nonce")"
ns_relay="$(docker create --pull never --network "$ns_network" --read-only --init --cap-drop ALL \
  --security-opt no-new-privileges --user 65534:65534 --memory 128m --pids-limit 32 \
  --label "com.hermes.h454.fixture=$nonce" --entrypoint node "$base" -e '
  require("node:http").createServer((q,r)=>{r.writeHead(q.method==="GET"&&q.url==="/health"?200:404);r.end()}).listen(3000,"127.0.0.1")')"
docker start "$ns_relay" >/dev/null
ns_probe="$(docker create --pull never --network "$ns_network" --read-only --init --cap-drop ALL \
  --security-opt no-new-privileges --user 65534:65534 --memory 128m --pids-limit 32 \
  --label "com.hermes.h454.fixture=$nonce" --entrypoint node "$wss_proxy_image" -e 'setInterval(()=>{},1000)')"
docker start "$ns_probe" >/dev/null
ns_peer="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$ns_probe")"
node -e 'if(require("node:net").isIP(process.argv[1])!==4)process.exit(1)' "$ns_peer"
ns_proxy="$(docker create --pull never --network "container:$ns_relay" --restart unless-stopped \
  --read-only --init --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 \
  --memory 128m --pids-limit 32 --env "H454_SSH_SOURCE_IPV4=$ns_peer" \
  --label "com.hermes.h454.fixture=$nonce" "$wss_proxy_image")"
docker start "$ns_proxy" >/dev/null
ns_of() { docker exec "$1" node -e 'console.log(require("node:fs").readlinkSync("/proc/self/ns/net"))'; }
probe_proxy() {
  local relay_ip
  relay_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$ns_relay")"
  docker exec "$ns_probe" node -e '
    const fs=require("node:fs"),tls=require("node:tls");
    const s=tls.connect({host:process.argv[1],port:3001,ca:fs.readFileSync("/run/h454-wss/relay-ca.pem"),
      servername:"brc-agent.internal",rejectUnauthorized:true},()=>{s.destroy();process.exit(0)});
    s.on("error",()=>process.exit(1));setTimeout(()=>process.exit(1),3000).unref();' "$relay_ip"
}
before_ns="$(ns_of "$ns_relay")"
[[ "$before_ns" =~ ^net:\[[0-9]+\]$ ]]
test "$before_ns" = "$(ns_of "$ns_proxy")"
test "$(docker inspect --format '{{.RestartCount}}' "$ns_proxy")" = 0
ready=false
for _ in $(seq 1 40); do
  if probe_proxy; then ready=true; break; fi
  sleep 0.25
done
test "$ready" = true
docker exec "$ns_proxy" node -e '
  const fs=require("node:fs"),tls=require("node:tls");
  const s=tls.connect({host:"127.0.0.1",port:3001,ca:fs.readFileSync("/run/h454-wss/relay-ca.pem"),
    servername:"brc-agent.internal",rejectUnauthorized:true},()=>process.exit(1));
  s.on("error",e=>process.exit(e.code==="ECONNRESET"?0:1));setTimeout(()=>process.exit(1),3000).unref();'
probe_proxy
test "$(docker inspect --format '{{index .Config.Labels "com.hermes.h454.fixture"}}' "$ns_relay")" = "$nonce"
docker restart --time 1 "$ns_relay" >/dev/null
recovered=false
for _ in $(seq 1 120); do
  count="$(docker inspect --format '{{.RestartCount}}' "$ns_proxy")"
  relay_ns="$(ns_of "$ns_relay" 2>/dev/null || true)"
  proxy_ns="$(ns_of "$ns_proxy" 2>/dev/null || true)"
  if [[ "$count" =~ ^[0-9]+$ ]] && test "$count" -gt 0 &&
      [[ "$relay_ns" =~ ^net:\[[0-9]+\]$ ]] && test "$relay_ns" = "$proxy_ns" && probe_proxy; then
    recovered=true; break
  fi
  sleep 0.25
done
test "$recovered" = true
probe_proxy
echo 'H454_WSS_PROXY_NAMESPACE_RESTART=PASS_SYNTHETIC_ONLY'
echo 'H454_WSS_PROXY_UNAPPROVED_PEER_REFUSED=PASS_SYNTHETIC_ONLY'
