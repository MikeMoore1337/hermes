// Synthetic credentials and certificates only.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import fs from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createCredentialBroker, SURROGATE } from './h454_credential_broker.mjs';

const fixture = process.argv[2];
if (!fixture || process.argv.length !== 3) throw Error('SYNTHETIC_FIXTURE_REQUIRED');
const read = name => fs.readFileSync(path.join(fixture, name));
const ca = read('ca.crt'), token = 'brc_dev_' + 'a'.repeat(43), other = 'brc_dev_' + 'b'.repeat(43);
const guid = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const wsKey = 'AAAAAAAAAAAAAAAAAAAAAA==';
const headers = (bearer = SURROGATE, target = '/ws', extra = '') =>
  `GET ${target} HTTP/1.1\r\nHost: fixture\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n` +
  `Authorization: Bearer ${bearer}\r\nSec-WebSocket-Key: ${wsKey}\r\n` +
  `Sec-WebSocket-Version: 13\r\nX-BRC-Protocol: 1\r\n${extra}\r\n`;

async function listen(server) {
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port;
}
function track(server) {
  const sockets = new Set();
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  return async () => {
    for (const socket of sockets) socket.destroy();
    if (server.listening) await new Promise(resolve => server.close(resolve));
  };
}
async function stage(port, value) {
  const socket = net.connect(port, '127.0.0.1'); let data = '';
  socket.on('data', chunk => { data += chunk; });
  await once(socket, 'connect'); socket.end(value);
  await once(socket, 'close'); return data;
}
async function connect(port, request) {
  const socket = net.connect(port, '127.0.0.1'); socket.on('error', () => {});
  const result = Promise.race([
    once(socket, 'data').then(([data]) => ({ type:'data', data:data.toString() })),
    once(socket, 'close').then(() => ({ type:'closed' })),
    delay(4000).then(() => ({ type:'timeout' })),
  ]);
  await once(socket, 'connect'); socket.write(request);
  return { socket, result:await result };
}

for (const invalid of [{ upstreamHost:'bad', upstreamPort:1, ca },
  { upstreamHost:'127.0.0.1', upstreamPort:0, ca },
  { upstreamHost:'127.0.0.1', upstreamPort:1, ca:Buffer.alloc(0) }])
  assert.throws(() => createCredentialBroker(invalid), /H454_BROKER_CONFIGURATION/);

async function run(certName, keyName, trusted) {
  let calls = 0, authorization = '', output = '';
  const relay = https.createServer({ cert:read(certName), key:read(keyName) });
  relay.on('tlsClientError', () => {});
  relay.on('upgrade', (request, socket) => {
    calls++; authorization = request.headers.authorization;
    const accept = createHash('sha1').update(request.headers['sec-websocket-key'] + guid).digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.on('data', data => { output += data; socket.write(data); });
    socket.on('error', () => {});
  });
  const closeRelay = track(relay); let closeServer = async () => {}, closeStaging = async () => {};
  try {
    const relayPort = await listen(relay);
    const broker = createCredentialBroker({ upstreamHost:'127.0.0.1', upstreamPort:relayPort, ca });
    closeServer = track(broker.server); closeStaging = track(broker.staging);
    const port = await listen(broker.server), stagePort = await listen(broker.staging);
    let attempt = await connect(port, headers());
    assert.equal(attempt.result.type, 'closed'); attempt.socket.destroy();
    assert.equal(calls, 0);
    assert.equal(await stage(stagePort, SURROGATE), 'H454_BROKER_TOKEN_REFUSED');
    assert.equal(await stage(stagePort, 'invalid'), 'H454_BROKER_TOKEN_REFUSED');
    assert.equal(await stage(stagePort, token), 'H454_BROKER_TOKEN_STAGED');
    assert.equal(await stage(stagePort, token), 'H454_BROKER_TOKEN_STAGED');
    assert.equal(await stage(stagePort, other), 'H454_BROKER_TOKEN_REFUSED');
    for (const request of [headers(token), headers(SURROGATE, '/ws?extra=1'),
      headers(SURROGATE, '/ws', `Authorization: Bearer ${SURROGATE}\r\n`)]) {
      attempt = await connect(port, request);
      assert.equal(attempt.result.type, 'closed'); attempt.socket.destroy();
    }
    assert.equal(calls, 0);
    attempt = await connect(port, headers());
    if (trusted) {
      assert.equal(attempt.result.type, 'data');
      assert.match(attempt.result.data, /^HTTP\/1\.1 101 /);
      assert(!attempt.result.data.includes(token));
      assert.equal(authorization, `Bearer ${token}`);
      const second = await connect(port, headers());
      assert.equal(second.result.type, 'closed'); second.socket.destroy();
      attempt.socket.write('synthetic-frame');
      const [echo] = await once(attempt.socket, 'data');
      assert.equal(echo.toString(), 'synthetic-frame');
      assert.equal(output, 'synthetic-frame');
    } else {
      assert.equal(attempt.result.type, 'closed');
      assert.equal(calls, 0);
      assert.equal(authorization, '');
    }
    attempt.socket.destroy();
  } finally { await closeServer(); await closeStaging(); await closeRelay(); }
}

await run('trusted.crt', 'trusted.key', true);
await run('fake.crt', 'fake.key', false);
await run('wrong.crt', 'wrong.key', false);
console.log('H454_SYNTHETIC_BROKER_SURROGATE_AND_TLS=PASS');
console.log('H454_SYNTHETIC_BROKER_STAGING_AND_REFUSALS=PASS');
