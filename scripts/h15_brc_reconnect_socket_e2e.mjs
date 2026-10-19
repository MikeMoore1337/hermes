#!/usr/bin/env node
// Genuine compiled hardened BRC DeviceHub: no old/foreign socket can
// complete a live call or revive stale presence. Runs offline in CI only.
import { EventEmitter } from 'node:events';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
const { DeviceHub } = await import(pathToFileURL(path.join(process.cwd(), 'packages/relay/dist/device-hub.js')).href);

class Socket extends EventEmitter {
  constructor() {
    super();
    this.OPEN = 1;
    this.readyState = 1;
    this.sent = [];
    this.closed = null;
  }
  send(raw) { this.sent.push(JSON.parse(raw)); }
  close(code, reason) {
    this.closed = { code, reason };
    this.readyState = 3;
    this.emit('close', code, reason);
  }
  terminate() { this.close(1006, 'terminated'); }
  recv(msg) { this.emit('message', Buffer.from(JSON.stringify(msg))); }
  lastCall() { return this.sent.filter((m) => m.type === 'call').at(-1); }
}

function hello(id) {
  return {
    type: 'hello', protocol: 1,
    device: { deviceId: id, name: id, platform: 'ci', arch: 'x64',
      hostname: id, agentVersion: 'ci', coreVersion: 'ci' },
    tools: [{ name: 'read_file', description: 'fixture', inputSchema: { type: 'object' } }],
  };
}
function okText(text) {
  return { content: [{ type: 'text', text }] };
}
const hub = new DeviceHub('test', () => {});
const a = new Socket();
const b = new Socket();
const foreign = new Socket();
try {
  hub.attach(a, 'owner-a', 'dev-a');
  a.recv(hello('dev-a'));
  const prev = hub.call('dev-a', 'read_file', { path: 'first' });
  const prevId = a.lastCall().id;

  hub.attach(foreign, 'owner-b', 'dev-b');
  foreign.recv(hello('dev-b'));
  hub.attach(b, 'owner-a', 'dev-a');
  b.recv(hello('dev-a'));

  await assert.rejects(prev, /DEVICE_REPLACED/);
  assert.equal(a.closed?.code, 1006);
  console.log('REPLACED_DEVICE_PENDING=REJECTED');

  const latest = hub.call('dev-a', 'read_file', { path: 'second' });
  const newId = b.lastCall().id;
  let settled = false;
  latest.then(() => { settled = true; }, () => { settled = true; });

  a.recv({ type: 'result', id: newId, result: okText('old-socket-forgery') });
  foreign.recv({ type: 'result', id: newId, result: okText('cross-device-forgery') });
  await Promise.resolve();
  assert.equal(settled, false);
  assert.equal(hub.get('dev-a')?.socket, b);
  console.log('STALE_AND_CROSS_DEVICE_RESULT=IGNORED');

  // Replaying an old id cannot revive its already rejected promise.
  a.recv({ type: 'result', id: prevId, result: okText('late-success') });
  b.recv({ type: 'result', id: newId, result: okText('legitimate') });
  assert.equal((await latest).content[0].text, 'legitimate');
  console.log('AUTHENTIC_SOCKET_RESULT=ACCEPTED');

  const disconnected = hub.call('dev-a', 'read_file', { path: 'third' });
  b.close(1000, 'ci-close');
  await assert.rejects(disconnected, /DEVICE_DISCONNECTED/);
  assert.equal(hub.get('dev-a'), undefined);
  console.log('DISCONNECTED_PENDING=REJECTED');

  const c = new Socket();
  hub.attach(c, 'owner-a', 'dev-a');
  c.recv(hello('dev-a'));
  c.recv(hello('dev-a'));
  assert.equal(c.closed?.code, 1002);
  assert.equal(hub.get('dev-a'), undefined);
  console.log('DUPLICATE_HELLO=REJECTED');

  const d = new Socket();
  hub.attach(d, 'owner-a', 'dev-a');
  d.recv(hello('dev-a'));
  const heartbeat = hub.call('dev-a', 'read_file', { path: 'fourth' });
  hub.get('dev-a').lastSeen = Date.now() - 60000;
  hub.tick();
  await assert.rejects(heartbeat, /DEVICE_HEARTBEAT_EXPIRED/);
  assert.equal(hub.get('dev-a'), undefined);
  console.log('EXPIRED_HEARTBEAT_PENDING=REJECTED');

  console.log('HERMES_BRC_RECONNECT_SOCKET_BINDING_E2E=PASS');
} finally {
  hub.close();
}
