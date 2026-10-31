import assert from 'node:assert/strict';
import http from 'node:http';
import { relayHealthy, relayWatchdog } from './h454_wss_relay_proxy.mjs';

let status = 200;
const relay = http.createServer((_request, response) => {
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
