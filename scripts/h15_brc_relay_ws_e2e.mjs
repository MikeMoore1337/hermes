#!/usr/bin/env node
// Real end-to-end BRC relay handshake against disposable loopback SQLite.
// Run from pinned upstream source root AFTER pnpm build + Hermes relay patch.
// Never opens production ports, uses owner secrets or connects real devices.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';

const root = process.cwd();
const requireRelay = createRequire(path.join(root, 'packages/relay/package.json'));
const WebSocket = requireRelay('ws');
const { buildRelay } = await import(pathToFileURL(path.join(root, 'packages/relay/dist/app.js')).href);
const temp = mkdtempSync(path.join(tmpdir(), 'hermes-brc-wss-auth-'));
const secret = () => randomBytes(32).toString('hex');
const relay = buildRelay({
  port: 0, host: '127.0.0.1', publicUrl: 'http://127.0.0.1',
  trustProxy: false,
  dbFile: path.join(temp, 'relay.sqlite'),
  sessionSecret: secret(), adminUser: 'unit-only', adminPassword: secret(),
  relayVersion: 'test-pinned',
}, () => {});
let goodSocket = null;

async function connectOnce(uri, opts = {}) {
  return await new Promise((resolve, reject) => {
    const ws = new WebSocket(uri, opts);
    const timer = setTimeout(() => {
      ws.terminate();
      reject(new Error('WEBSOCKET_HANDSHAKE_TIMEOUT'));
    }, 4000);
    let done = false;
    const complete = (value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(value);
    };
    ws.once('open', () => complete({ accepted: true, socket: ws }));
    ws.once('unexpected-response', (_req, response) => {
      const status = response.statusCode;
      response.resume();
      complete({ accepted: false, status });
    });
    ws.on('error', (err) => {
      // Some Node runtimes report a connection reset after the 401 response.
      complete({ accepted: false, errorCode: err.code || 'NETWORK_REJECTED' });
    });
    ws.once('close', () => complete({ accepted: false, errorCode: 'SOCKET_CLOSED' }));
  });
}

try {
  await new Promise((resolve, reject) => {
    relay.http.once('error', reject);
    relay.http.listen(0, '127.0.0.1', resolve);
  });
  const addr = relay.http.address();
  if (!addr || typeof addr === 'string') throw Error('PORT_NOT_ASSIGNED');
  const base = 'ws://127.0.0.1:' + addr.port + '/ws';
  const user = relay.store.getUserByName('unit-only');
  if (!user) throw Error('USER_NOT_CREATED');
  const validToken = relay.store.issueDeviceToken('sandbox-agent', user.id, 'sandbox-agent', 'linux');

  const queryOnly = await connectOnce(base + '?token=' + encodeURIComponent(validToken));
  if (queryOnly.accepted) throw Error('QUERY_DEVICE_TOKEN_ACCEPTED');
  console.log('WSS_TOKEN_QUERY_ONLY=DENIED');

  const queryAndBearer = await connectOnce(base + '?token=' + encodeURIComponent(validToken), {
    headers: { Authorization: 'Bearer ' + validToken },
  });
  if (queryAndBearer.accepted) throw Error('QUERY_TOKEN_WITH_BEARER_ACCEPTED');
  console.log('WSS_TOKEN_QUERY_WITH_BEARER=DENIED');

  const missing = await connectOnce(base);
  if (missing.accepted) throw Error('MISSING_BEARER_ACCEPTED');
  console.log('WSS_MISSING_BEARER=DENIED');

  const bad = await connectOnce(base, { headers: { Authorization: 'Bearer unauthorized' } });
  if (bad.accepted) throw Error('BAD_BEARER_ACCEPTED');
  console.log('WSS_INVALID_BEARER=DENIED');

  const good = await connectOnce(base, { headers: { Authorization: 'Bearer ' + validToken } });
  if (!good.accepted) throw Error('VALID_BEARER_REJECTED');
  goodSocket = good.socket;
  console.log('WSS_VALID_BEARER=ACCEPTED');
  console.log('HERMES_BRC_WSS_AUTH_E2E=PASS');
} finally {
  if (goodSocket) goodSocket.terminate();
  await relay.close();
  rmSync(temp, { recursive: true, force: true });
}
