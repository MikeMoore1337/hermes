// Synthetic certificates and token only; runs in a network-isolated container.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { createRollbackProxy, isolatedIPv4 } from './h454_isolated_rollback_proxy.mjs';

const fixture = process.argv[2];
if (!fixture || process.argv.length !== 3) throw Error('SYNTHETIC_FIXTURE_REQUIRED');
const read = name => fs.readFileSync(path.join(fixture, name));
const ca = read('ca.crt');
const marker = Buffer.from('Bearer brc_dev_' + 'a'.repeat(43));

const isolated = { address:'172.18.0.2', family:'IPv4', internal:false, cidr:'172.18.0.2/16' };
const upstreamInterface = { address:'10.0.0.2', family:'IPv4', internal:false, cidr:'10.0.0.2/8' };
assert.equal(isolatedIPv4({ lo:[{ address:'127.0.0.1', family:'IPv4', internal:true }],
  eth0:[isolated] }, '172.18.0.0/16'), '172.18.0.2');
assert.equal(isolatedIPv4({ eth0:[isolated], eth1:[upstreamInterface] }, '172.18.0.0/16'), '172.18.0.2');
for (const interfaces of [{}, { eth0:[{ address:'8.8.8.8', family:'IPv4', internal:false }] },
  { a:[upstreamInterface] }, { a:[{ ...isolated, cidr:'172.18.0.2/24' }] },
  { a:[isolated], b:[{ ...isolated, address:'172.18.0.3', cidr:'172.18.0.3/16' }] },
  { a:[isolated], b:[upstreamInterface], c:[{ ...upstreamInterface, address:'10.1.0.2' }] }]) {
  assert.throws(() => isolatedIPv4(interfaces, '172.18.0.0/16'), /H454_ISOLATED_INTERFACE/);
}
for (const cidr of ['172.18.0.2/16', '172.16.0.0/11', '127.0.0.0/8', '10.0.0.0/08', '0.0.0.0/0', 'invalid'])
  assert.throws(() => isolatedIPv4({ eth0:[isolated] }, cidr), /H454_ISOLATED_NETWORK/);
for (const invalid of [
  {upstreamHost:'invalid', upstreamPort:38184, ca},
  {upstreamHost:'127.0.0.1', upstreamPort:0, ca},
  {upstreamHost:'127.0.0.1', upstreamPort:38184, ca:Buffer.alloc(0)}
]) assert.throws(() => createRollbackProxy(invalid), /H454_PROXY_CONFIGURATION/);

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}
function track(server) {
  const sockets = new Set();
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  return async () => {
    for (const socket of sockets) socket.destroy();
    if (server.listening) await new Promise(resolve => server.close(resolve));
  };
}
async function attempt(proxy, expected, received, timeout = 3500) {
  const client = net.connect(proxy.address().port, '127.0.0.1');
  client.on('error', () => {});
  const outcome = new Promise(resolve => {
    client.once('data', data => resolve({ kind:'data', data }));
    client.once('close', () => resolve({ kind:'closed' }));
  });
  await once(client, 'connect');
  client.write(marker);
  const result = await Promise.race([outcome, delay(timeout).then(() => ({kind:'timeout'}))]);
  if (expected) {
    assert.equal(result.kind, 'data');
    assert.equal(result.data.toString(), 'ACK');
    assert(Buffer.concat(received).includes(marker));
  } else {
    assert.equal(result.kind, 'closed');
    await delay(100);
    assert(!Buffer.concat(received).includes(marker));
  }
  client.destroy();
}

async function tlsCase(certName, keyName, expected) {
  const received = [];
  const upstream = tls.createServer({ cert:read(certName), key:read(keyName), minVersion:'TLSv1.2' }, socket => {
    socket.on('error', () => {});
    socket.on('data', chunk => {
      received.push(chunk);
      if (Buffer.concat(received).includes(marker)) socket.write('ACK');
    });
  });
  upstream.on('tlsClientError', () => {});
  const closeUpstream = track(upstream);
  let closeProxy = async () => {};
  try {
    const upstreamPort = await listen(upstream);
    const proxy = createRollbackProxy({upstreamHost:'127.0.0.1', upstreamPort, ca});
    closeProxy = track(proxy);
    await listen(proxy);
    await attempt(proxy, expected, received);
  } finally { await closeProxy(); await closeUpstream(); }
}

await tlsCase('trusted.crt', 'trusted.key', true);
await tlsCase('fake.crt', 'fake.key', false);
await tlsCase('wrong.crt', 'wrong.key', false);

const raw = [];
const slow = net.createServer(socket => {
  socket.on('error', () => {});
  socket.on('data', data => raw.push(data));
  socket.write(Buffer.from([0x16]));
  const timer = setTimeout(() => socket.write(Buffer.from([0x03])), 3000);
  socket.once('close', () => clearTimeout(timer));
});
const closeSlow = track(slow);
let closeProxy = async () => {};
try {
  const upstreamPort = await listen(slow);
  const proxy = createRollbackProxy({upstreamHost:'127.0.0.1', upstreamPort, ca});
  closeProxy = track(proxy);
  await listen(proxy);
  const held = [];
  try {
    for (let i = 0; i < 4; i++) {
      const socket = net.connect(proxy.address().port, '127.0.0.1');
      socket.on('error', () => {});
      held.push(socket);
      await once(socket, 'connect');
    }
    const dropped = Promise.race([once(proxy, 'drop'), delay(2500).then(() => { throw Error('H454_CONNECTION_LIMIT'); })]);
    const extra = net.connect(proxy.address().port, '127.0.0.1');
    extra.on('error', () => {});
    held.push(extra);
    await dropped;
  } finally { for (const socket of held) socket.destroy(); }
  let connections = -1;
  for (let i = 0; i < 100; i++) {
    connections = await new Promise((resolve, reject) => proxy.getConnections((error, count) => error ? reject(error) : resolve(count)));
    if (connections === 0) break;
    await delay(20);
  }
  assert.equal(connections, 0);
  const started = Date.now();
  await attempt(proxy, false, raw, 7000);
  assert(Date.now() - started >= 4500);
} finally { await closeProxy(); await closeSlow(); }

console.log('H454_SYNTHETIC_ROLLBACK_PROXY_PINNED_TLS=PASS');
console.log('H454_SYNTHETIC_ROLLBACK_PROXY_UNTRUSTED_RECEIVED_NO_TOKEN=PASS');
