// Synthetic TLS regression: open device-like persistent connections and
// prove a separate owner-status request can still pass without broadening peers.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { pathToFileURL } from 'node:url';

const { createProxy } = await import(pathToFileURL(process.argv[2]).href);
const read = name => readFileSync(process.argv[3] + '/' + name);
const token = 'Bearer brc_dev_' + 'a'.repeat(64);
const deviceId = 'h454-linux-personal-yfc-' + 'b'.repeat(32);
const backend = http.createServer((req, res) => {
  assert.equal(req.url, '/device/native-status');
  assert.equal(req.headers.authorization, token);
  res.writeHead(200, {'Content-Type':'application/json'});
  res.end(JSON.stringify({schema:'h454-native-device-status-v1', device_id:deviceId,
                          active:true, owner_bound:true}));
});
await new Promise(resolve => backend.listen(0, '127.0.0.1', resolve));
const proxy = createProxy({key:read('trusted.key'), cert:read('trusted.crt'),
  upstreamPort:backend.address().port, allowedPeer:'127.0.0.1'});
await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
const sockets = [];
function persistentConnection() {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({host:'127.0.0.1', port:proxy.address().port,
      servername:'brc-agent.internal', ca:read('ca.crt'), rejectUnauthorized:true});
    socket.setTimeout(5000, () => socket.destroy(new Error('fixture_timeout')));
    socket.once('secureConnect', () => { socket.setTimeout(0); sockets.push(socket); resolve(); });
    socket.once('error', reject);
  });
}
function statusRequest() {
  return new Promise((resolve, reject) => {
    const req = https.request({host:'127.0.0.1', port:proxy.address().port,
      path:'/device/native-status', servername:'brc-agent.internal', ca:read('ca.crt'),
      rejectUnauthorized:true, agent:false, timeout:5000, headers:{Authorization:token}}, res => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve({status:res.statusCode, body}));
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('fixture_timeout')));
    req.end();
  });
}
try {
  for (let i = 0; i < 8; i++) await persistentConnection();
  const response = await statusRequest();
  assert.equal(response.status, 200);
  assert.equal(JSON.parse(response.body).device_id, deviceId);
  assert.equal(proxy.maxConnections, 32);
  console.log('H454_STATUS_WITH_EIGHT_PERSISTENT_CONNECTIONS=PASS');
} finally {
  for (const socket of sockets) socket.destroy();
  await new Promise(resolve => proxy.close(resolve));
  await new Promise(resolve => backend.close(resolve));
}
