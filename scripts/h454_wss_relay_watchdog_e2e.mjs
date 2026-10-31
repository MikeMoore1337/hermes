import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { createProxy, privateIPv4, relayHealthy, relayWatchdog } from './h454_wss_relay_proxy.mjs';

for (const address of ['10.1.2.3', '172.16.0.1', '172.31.255.254', '192.168.1.1'])
  assert.equal(privateIPv4(address), true);
for (const address of [undefined, '', '0.0.0.0', '127.0.0.1', '172.32.0.1', '8.8.8.8', '::1', '010.1.2.3'])
  assert.equal(privateIPv4(address), false);
assert.throws(() => createProxy({ upstreamPort: 3000, allowedPeer: '0.0.0.0' }), /H454_PROXY_CONFIGURATION/);
assert.throws(() => createProxy({ upstreamPort: 3000 }), /H454_PROXY_CONFIGURATION/);
const cleanEnv = { ...process.env };
delete cleanEnv.H454_SSH_SOURCE_IPV4;
const missingPeer = spawnSync(process.execPath, [fileURLToPath(new URL('./h454_wss_relay_proxy.mjs', import.meta.url))],
  { env: cleanEnv, encoding: 'utf8', timeout: 5000 });
assert.equal(missingPeer.status, 1);
assert.equal(missingPeer.stderr.trim(), 'H454_WSS_PROXY_START_FAILED');

let status = 200;
const relay = http.createServer((request, response) => {
  if (request.method !== 'GET' || request.url !== '/health') { response.writeHead(404); response.end(); return; }
  if (status !== 0) { response.writeHead(status); response.end(); }
});
await new Promise((resolve, reject) => { relay.once('error', reject); relay.listen(0, '127.0.0.1', resolve); });
const port = relay.address().port;
try {
  assert.equal(await relayHealthy(port), true);
  status = 503;
  assert.equal(await relayHealthy(port), false);
  status = 0;
  assert.equal(await relayHealthy(port), false, 'a stalled health response must time out');
} finally { await new Promise(resolve => relay.close(resolve)); }
assert.equal(await relayHealthy(port), false, 'a stopped relay must fail');
assert.throws(() => relayHealthy(0), /UPSTREAM_PORT/);

const values = [false, false, true, false, false, false];
let lost = 0;
const watch = relayWatchdog(async () => values.shift(), () => { lost++; });
for (let i = 0; i < 5; i++) await watch();
assert.equal(lost, 0, 'one success must reset failures');
await watch();
await watch();
assert.equal(lost, 1, 'three consecutive failures must stop the proxy only once');

let release, probes = 0;
const delayed = relayWatchdog(() => { probes++; return new Promise(resolve => { release = resolve; }); }, () => {});
const pending = delayed();
await delayed();
assert.equal(probes, 1, 'health checks must not overlap');
release(true);
await pending;
console.log('H454_WSS_RELAY_WATCHDOG=PASS');
