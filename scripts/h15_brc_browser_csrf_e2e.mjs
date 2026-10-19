#!/usr/bin/env node
// Real compiled BRC relay verifies cookie-authenticated mutating browser
// endpoints reject missing/cross-origin/cross-site POST (isolated loopback).
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createServer as createTcpServer } from 'node:net';

const root = process.cwd();
const { buildRelay } = await import(
  pathToFileURL(path.join(root, 'packages/relay/dist/app.js')).href
);
const dir = mkdtempSync(path.join(tmpdir(), 'hermes-brc-csrf-'));
const secret = () => randomBytes(24).toString('hex');
const password = secret();
const port = await new Promise((resolve, reject) => {
  const probe = createTcpServer();
  probe.once('error', reject);
  probe.listen(0, '127.0.0.1', () => {
    const address = probe.address();
    if (!address || typeof address === 'string') return reject(Error('PORT_PROBE_FAILED'));
    probe.close(() => resolve(address.port));
  });
});
const relay = buildRelay({
  port, host: '127.0.0.1', publicUrl: 'http://127.0.0.1:' + port,
  trustProxy: false, dbFile: path.join(dir, 'relay.sqlite'),
  sessionSecret: secret(), adminUser: 'cs-owner', adminPassword: password,
  relayVersion: 'csrf-test-only'
}, () => {});
try {
  await new Promise((ok, fail) => {
    relay.http.once('error', fail);
    relay.http.listen(port, '127.0.0.1', ok);
  });
  const addr = relay.http.address();
  if (!addr || typeof addr === 'string') throw Error('CSRF_TEST_PORT_UNASSIGNED');
  const base = 'http://127.0.0.1:' + addr.port;
  const login = await fetch(base + '/auth/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: 'cs-owner', password, returnTo: '/' }),
  });
  const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0];
  if (login.status !== 302 || !cookie.startsWith('brc_session=')) {
    throw Error('AUTHENTICATED_COOKIE_MISSING');
  }

  const post = async (route, headers = {}) => {
    const r = await fetch(base + route, {
      method: 'POST', redirect: 'manual',
      headers: { cookie, 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams({ name: 'csrf-test-only', action: 'delete',
        device_id: 'nonexistent', pending: 'none', decision: 'allow' })
    });
    await r.text();
    return r.status;
  };
  const paths = ['/admin/device', '/auth/consent', '/device/approve',
    '/auth/clients/delete', '/auth/apikeys', '/auth/apikeys/revoke',
    '/device/verify'];
  for (const route of paths) {
    if (await post(route) !== 403) throw Error('MISSING_ORIGIN_ACCEPTED:' + route);
    if (await post(route, { origin: 'https://attacker.example' }) !== 403) {
      throw Error('CROSS_ORIGIN_ACCEPTED:' + route);
    }
    if (await post(route, { origin: base, 'sec-fetch-site': 'cross-site' }) !== 403) {
      throw Error('CROSS_SITE_FETCH_ACCEPTED:' + route);
    }
    const valid = await post(route, { origin: base, 'sec-fetch-site': 'same-origin' });
    if (valid === 403) throw Error('SAME_ORIGIN_REJECTED:' + route);
  }
  console.log('BRC_BROWSER_CSRF_MUTATION_PATHS=' + paths.length);
  console.log('BRC_BROWSER_MISSING_ORIGIN=DENIED');
  console.log('BRC_BROWSER_CROSS_ORIGIN=DENIED');
  console.log('BRC_BROWSER_CROSS_SITE_FETCH=DENIED');
  console.log('BRC_BROWSER_SAME_ORIGIN=ACCEPTED');

  // MCP authorization is Bearer-only, not browser-session based.
  const mcp = await fetch(base + '/mcp', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
  });
  if (mcp.status !== 401) throw Error('UNAUTHENTICATED_MCP_ALLOWED_OR_BLOCKED_UNEXPECTEDLY');
  console.log('BRC_MCP_UNAUTHORIZED=401');
  console.log('HERMES_BRC_BROWSER_CSRF_E2E=PASS');
} finally {
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}
