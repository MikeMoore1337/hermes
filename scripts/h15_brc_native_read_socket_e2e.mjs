#!/usr/bin/env node
// #454: disposable REAL relay WebSocket + synthetic native reader. Never uses D:\\,
// owner tokens, public ports or Windows processes. Run from pinned built BRC checkout.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';

const cwd = process.cwd();
const requireRelay = createRequire(path.join(cwd, 'packages/relay/package.json'));
const WebSocket = requireRelay('ws');
const { buildRelay } = await import(pathToFileURL(path.join(cwd, 'packages/relay/dist/app.js')).href);
const { invokeTool } = await import(pathToFileURL(path.join(cwd, 'packages/relay/dist/mcp/invoke.js')).href);
const { NATIVE_TOOLS, invokeOwnerNativeRead } =
  await import(pathToFileURL(path.join(cwd, 'packages/relay/dist/mcp/hermes-native-read.js')).href);

const { pinnedToolCatalog } = await import(pathToFileURL(path.join(cwd, 'packages/relay/dist/mcp/hermes-tool-catalog.js')).href);

const DEVICE_NAME = 'H15 Windows native read-only';
const DEVICE_ID = 'h15-native-ci-read-12345678';
const tmp = mkdtempSync(path.join(tmpdir(), 'h454-native-wss-ci-'));
const secret = () => randomBytes(32).toString('hex');
const assert = (predicate, label) => {
  if (!predicate) throw new Error('NATIVE_RELAY_CONTRACT_FAILED:' + label);
  console.log(label + '=PASS');
};
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const until = async predicate => {
  for (let i = 0; i < 60; i++) {
    if (predicate()) return true;
    await pause(50);
  }
  return false;
};

const relay = buildRelay({
  port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1',
  trustProxy: false, dbFile: path.join(tmp, 'state.sqlite'),
  sessionSecret: secret(), adminUser: 'native-ci-owner', adminPassword: secret(),
  relayVersion: 'ci-only',
}, () => {});
let socket;
let calls = 0;
let corrupt = false;
try {
  await new Promise((resolve, reject) => {
    relay.http.once('error', reject);
    relay.http.listen(0, '127.0.0.1', resolve);
  });
  const address = relay.http.address();
  if (!address || typeof address === 'string') throw new Error('NO_EPHEMERAL_PORT');
  const owner = relay.store.getUserByName('native-ci-owner');
  if (!owner) throw new Error('NO_OWNER');
  const token = relay.store.issueDeviceToken(DEVICE_ID, owner.id, DEVICE_NAME, 'win32');
  const ctx = { userId: owner.id, clientId: 'ci-chatgpt-synthetic' };
  const args = { project: 'hermes', relative: 'README.md' };
  const payload = (tool) => {
    const operation = tool === 'native_file_read' ? 'read' : 'stat';
    const data = Buffer.from('abc');
    const obj = { status: 'ok', ...args, action: operation, kind: 'file', size_bytes: data.length };
    if (operation === 'read') Object.assign(obj, {
      encoding: 'base64', data: data.toString('base64'),
      sha256: corrupt ? '0'.repeat(64) : createHash('sha256').update(data).digest('hex'),
    });
    return obj;
  };
  const beforePairing = await invokeOwnerNativeRead(relay.hub, relay.store, ctx, 'native_file_stat', args);
  assert(beforePairing.isError === true, 'NATIVE_PREPAIR_DISPATCH_DENIED');
  socket = new WebSocket('ws://127.0.0.1:' + address.port + '/ws', {
    headers: { Authorization: 'Bearer ' + token },
  });
  socket.on('error', () => {});
  socket.on('message', raw => {
    const msg = JSON.parse(String(raw));
    if (msg.type !== 'call') return;
    calls++;
    socket.send(JSON.stringify({
      type: 'result', id: msg.id,
      result: { isError: false, content: [{ type: 'text', text: JSON.stringify(payload(msg.tool)) }] },
    }));
  });
  await once(socket, 'open');
  assert(NATIVE_TOOLS.map(t => t.name).join(',') === 'native_file_stat,native_file_read,native_file_list',
    'NATIVE_TWO_TOOLS_ONLY');
  socket.send(JSON.stringify({
    type: 'hello', protocol: 1,
    device: { deviceId: DEVICE_ID, name: DEVICE_NAME, platform: 'win32',
      arch: 'x64', hostname: 'native-ci-fixture', agentVersion: 'ci-only', coreVersion: 'ci-only' },
    tools: NATIVE_TOOLS,
  }));
  assert(await until(() => !!relay.hub.get(DEVICE_ID)), 'NATIVE_WSS_OWNER_PAIRED');
  assert(!pinnedToolCatalog().some(t => t.name === 'native_file_read' || t.name === 'native_file_stat'),
    'NATIVE_GENERIC_CATALOG_NO_DUPLICATES');
  const ok = await invokeOwnerNativeRead(relay.hub, relay.store, ctx, 'native_file_read', args);
  assert(ok.isError === false && JSON.parse(ok.content[0].text).data === 'YWJj' && calls === 1,
    'NATIVE_WSS_RELAY_READ_AND_DIGEST_PASS');
  const stat = await invokeOwnerNativeRead(relay.hub, relay.store, ctx, 'native_file_stat', args);
  assert(stat.isError === false && JSON.parse(stat.content[0].text).action === 'stat' && calls === 2,
    'NATIVE_WSS_RELAY_STAT_PASS');
  for (const bad of [
    { project: 'hermes', relative: '..\\README.md' },
    { project: 'hermes', relative: 'vault\\secrets.md' },
    { project: 'hermes', relative: 'README.md', deviceId: DEVICE_ID },
    { project: 'unknown', relative: 'README.md' },
  ]) {
    const out = await invokeOwnerNativeRead(relay.hub, relay.store, ctx, 'native_file_read', bad);
    assert(out.isError === true, 'NATIVE_INVALID_ARGS_DENIED');
  }
  assert(calls === 2, 'NATIVE_INVALID_ARGS_NO_HOST_DISPATCH');
  const other = await invokeOwnerNativeRead(relay.hub, relay.store,
    { userId: 'wrong-owner', clientId: 'ci-codex-synthetic' }, 'native_file_read', args);
  assert(other.isError === true && calls === 2, 'NATIVE_FOREIGN_OWNER_DENIED');
  corrupt = true;
  const forged = await invokeOwnerNativeRead(relay.hub, relay.store, ctx, 'native_file_read', args);
  assert(forged.isError === true, 'NATIVE_FORGED_HASH_DENIED');
  corrupt = false;
  const command = await invokeTool(relay.hub, relay.store, ctx, 'start_process',
    { deviceId: DEVICE_ID, command: 'not-executed' });
  assert(command.ok === false, 'NATIVE_GENERIC_PROCESS_DENIED');
  const beforePaused = calls;
  relay.store.setDevicePaused(DEVICE_ID, true);
  const paused = await invokeOwnerNativeRead(relay.hub, relay.store, ctx, 'native_file_read', args);
  assert(paused.isError === true && calls === beforePaused, 'NATIVE_PAUSED_DENIED');
  relay.store.setDevicePaused(DEVICE_ID, false);
  socket.close(1000);
  assert(await until(() => !relay.hub.get(DEVICE_ID)), 'NATIVE_DISCONNECT_OBSERVED');
  const offline = await invokeOwnerNativeRead(relay.hub, relay.store, ctx, 'native_file_stat', args);
  assert(offline.isError === true, 'NATIVE_OFFLINE_DENIED');
  console.log('H454_NATIVE_READ_RELAY_SYNTHETIC_SOCKET_E2E=PASS');
} finally {
  if (socket) {
    try { socket.terminate(); } catch {}
  }
  await relay.close();
  rmSync(tmp, { recursive: true, force: true });
}
