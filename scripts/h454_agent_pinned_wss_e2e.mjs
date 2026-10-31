// Actual compiled agent and relay; synthetic certificates and token only.
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import dns from 'node:dns';
import fs from 'node:fs';
import https from 'node:https';
import tls from 'node:tls';
import { pathToFileURL } from 'node:url';
import { createProxy } from './h454_wss_relay_proxy.mjs';

const [agentPath, relayPath, invokePath, fixtures] = process.argv.slice(2);
if (!agentPath || !relayPath || !invokePath || !fixtures) throw Error('FIXTURE_ARGUMENTS');
const { WsClient } = await import(pathToFileURL(agentPath));
const { buildRelay } = await import(pathToFileURL(relayPath));
const { invokeTool } = await import(pathToFileURL(invokePath));
const read = name => fs.readFileSync(`${fixtures}/${name}`);
const options = (token, url = 'https://host.docker.internal:38184') => ({
  relayUrl: url, token, deviceId: 'synthetic-wss-device', name: 'fixture',
  agentVersion: 'fixture', coreVersion: 'fixture',
  tools: [{ name: 'read_file', description: 'fixture', inputSchema: { type: 'object', properties: {} } }],
  callTool: async () => ({ content: [{ type: 'text', text: 'synthetic-result' }] }), log: () => {},
});
const listen = server => new Promise((resolve, reject) => {
  server.once('error', reject); server.listen(38184, '127.0.0.1', resolve);
});
const close = server => new Promise(resolve => server.close(resolve));
const until = async predicate => {
  const deadline = Date.now() + 10000;
  while (!predicate() && Date.now() < deadline) await new Promise(r => setTimeout(r, 50));
  assert.ok(predicate(), 'fixture timeout');
};
dns.setDefaultResultOrder('ipv4first');

for (const url of ['http://host.docker.internal:38184', 'https://example.invalid:38184',
  'https://host.docker.internal:38185', 'https://user@host.docker.internal:38184',
  'https://host.docker.internal:38184/?q=x', 'https://host.docker.internal:38184/other']) {
  assert.throws(() => new WsClient(options('synthetic', url)), /WSS_TARGET_REFUSED/);
}

const relay = buildRelay({ port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1',
  trustProxy: false, dbFile: '/tmp/h454-wss-relay.sqlite', sessionSecret: 'fixture-session-secret-0123456789abcdef',
  adminUser: 'fixture-only', adminPassword: 'fixture-password-0123456789abcdef', relayVersion: 'fixture' }, () => {});
await new Promise((resolve, reject) => { relay.http.once('error', reject); relay.http.listen(0, '127.0.0.1', resolve); });
const owner = relay.store.getUserByName('fixture-only');
const token = relay.store.issueDeviceToken('synthetic-wss-device', owner.id, 'fixture', 'linux');
const proxy = createProxy({ key: read('trusted.key'), cert: read('trusted.crt'), upstreamPort: relay.http.address().port });
const proxySockets = new Set();
let connections = 0, upstreamUpgrades = 0;
proxy.on('secureConnection', socket => { connections++; proxySockets.add(socket); socket.once('close', () => proxySockets.delete(socket)); });
relay.http.on('upgrade', () => { upstreamUpgrades++; });
await listen(proxy);
let client, fake;
const fakeSockets = new Set();
let refused = 0;
try {
  const status = await new Promise((resolve, reject) => {
    https.get({ host: '127.0.0.1', port: 38184, path: '/not-ws', ca: read('ca.crt'),
      servername: 'brc-agent.internal' }, response => { response.resume(); resolve(response.statusCode); }).on('error', reject);
  });
  assert.equal(status, 404);
  assert.equal(upstreamUpgrades, 0, 'non-WebSocket route reached relay');
  for (const [path, duplicate] of [['/ws?x=1', false], ['/ws', true]]) {
    await new Promise((resolve, reject) => {
      const socket = tls.connect({ host: '127.0.0.1', port: 38184, ca: read('ca.crt'),
        servername: 'brc-agent.internal' }, () => {
        socket.write(`GET ${path} HTTP/1.1\r\nHost: fixture\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n` +
          `Authorization: Bearer ${token}\r\n` + (duplicate ? `Authorization: Bearer ${token}\r\n` : '') +
          'Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\nSec-WebSocket-Version: 13\r\nX-BRC-Protocol: 1\r\n\r\n');
      });
      socket.setTimeout(3000, () => socket.destroy(Error('rejection timeout')));
      socket.on('error', error => { if (error.code !== 'ECONNRESET') reject(error); });
      socket.on('close', resolve);
    });
  }
  assert.equal(upstreamUpgrades, 0, 'invalid WebSocket request reached relay');
  client = new WsClient({ ...options(token), log: (_level, message) => {
    if (typeof message === 'string' && message.includes('ECONNREFUSED')) refused++;
  } });
  client.start();
  await until(() => !!relay.hub.get('synthetic-wss-device'));
  const call = await invokeTool(relay.hub, relay.store, { userId: owner.id, clientId: 'fixture' }, 'read_file',
    { deviceId: 'synthetic-wss-device', path: '/workspace/fixture' });
  assert.equal(call.ok, true);
  assert.equal(call.result.content[0].text, 'synthetic-result');
  const before = connections;
  const firstSocket = relay.hub.get('synthetic-wss-device').socket;
  for (const socket of proxySockets) socket.destroy();
  await until(() => connections > before && !!relay.hub.get('synthetic-wss-device') &&
    relay.hub.get('synthetic-wss-device').socket !== firstSocket);
  const again = await invokeTool(relay.hub, relay.store, { userId: owner.id, clientId: 'fixture' }, 'read_file',
    { deviceId: 'synthetic-wss-device', path: '/workspace/fixture' });
  assert.equal(again.ok, true);
  const secondSocket = relay.hub.get('synthetic-wss-device').socket;
  for (const socket of proxySockets) socket.destroy();
  await close(proxy);
  await until(() => refused > 0);
  let fakeAttempted = false, fakeSettled = false, fakeDataBytes = 0;
  fake = tls.createServer({ key: read('fake.key'), cert: read('fake.crt') }, socket => {
    socket.on('data', data => { fakeDataBytes += data.length; socket.destroy(); });
    socket.on('error', () => {});
  });
  fake.on('connection', socket => {
    fakeAttempted = true; fakeSockets.add(socket);
    socket.once('close', () => { fakeSockets.delete(socket); fakeSettled = true; });
  });
  fake.on('tlsClientError', () => {});
  await listen(fake);
  await until(() => fakeAttempted && fakeSettled);
  assert.equal(fakeDataBytes, 0, 'application bytes reached the replacement listener');
  for (const socket of fakeSockets) socket.destroy();
  await close(fake); fake = null;
  await listen(proxy);
  await until(() => !!relay.hub.get('synthetic-wss-device') &&
    relay.hub.get('synthetic-wss-device').socket !== secondSocket);
  const restored = await invokeTool(relay.hub, relay.store, { userId: owner.id, clientId: 'fixture' }, 'read_file',
    { deviceId: 'synthetic-wss-device', path: '/workspace/fixture' });
  assert.equal(restored.ok, true);
  assert.equal(restored.result.content[0].text, 'synthetic-result');
  let unauthorized = 0;
  const invalid = new WsClient({ ...options('brc_dev_' + 'x'.repeat(43)),
    onUnauthorized: async () => { unauthorized++; return true; } });
  invalid.start();
  await until(() => unauthorized === 1);
  invalid.stop();
  assert.ok(relay.hub.get('synthetic-wss-device'));
  console.log('PINNED_WSS_REAL_RELAY_TOOL_AND_RECONNECT=PASS');
  console.log('PINNED_WSS_ABSENT_AND_FAKE_LISTENER_RECOVERY=PASS');
  console.log('PROXY_INVALID_HTTP_AND_UNAUTHORIZED=PASS');
} finally {
  client?.stop();
  for (const socket of fakeSockets) socket.destroy();
  if (fake) await close(fake);
  for (const socket of proxySockets) socket.destroy();
  await close(proxy);
  await relay.close();
}

const originalRoots = tls.getCACertificates('default');
const originalInsecure = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
tls.setDefaultCACertificates([...originalRoots, read('fake.crt').toString('utf8')]);
async function rejectFake(name) {
  let gotBearer = false, attempted = false, finished;
  const event = new Promise(resolve => { finished = resolve; });
  const sockets = new Set();
  const server = tls.createServer({ key: read(`${name}.key`), cert: read(`${name}.crt`) }, socket => {
    socket.on('data', data => { gotBearer ||= data.toString('utf8').includes(token); finished(); });
    socket.on('error', () => {});
  });
  server.on('connection', socket => { attempted = true; sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => finished());
  await listen(server);
  const attemptedClient = new WsClient(options(token));
  attemptedClient.start();
  await Promise.race([event, new Promise(resolve => setTimeout(resolve, 3000))]);
  attemptedClient.stop();
  assert.ok(attempted, 'fake listener was not contacted');
  assert.equal(gotBearer, false, 'bearer reached fake listener');
  for (const socket of sockets) socket.destroy();
  await close(server);
}
try {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  await rejectFake('fake');
  await rejectFake('wrong');
  const fakeFingerprint = new X509Certificate(read('fake.crt')).fingerprint256;
  assert.ok(tls.getCACertificates('default').some(cert =>
    new X509Certificate(cert).fingerprint256 === fakeFingerprint));
  console.log('GLOBALLY_TRUSTED_FAKE_AND_WRONG_HOST_NO_BEARER=PASS');
} finally {
  tls.setDefaultCACertificates(originalRoots);
  if (originalInsecure === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = originalInsecure;
}
console.log('REAL_CREDENTIALS_USED=FALSE');
