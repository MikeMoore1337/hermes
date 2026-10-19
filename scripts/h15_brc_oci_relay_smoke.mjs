#!/usr/bin/env node
// #371: real BRC relay image accepts loopback-only health and OAuth metadata.
// This file is mounted into a fresh CI container; it does not touch real devices.
import fs from 'node:fs';

const base = 'http://127.0.0.1:3000';
async function untilHealthy() {
  for (let i = 0; i < 45; i++) {
    try {
      const r = await fetch(base + '/health', { signal: AbortSignal.timeout(1000) });
      if (r.ok) return await r.json();
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  throw Error('BRC_TEST_RELAY_DID_NOT_START');
}

function must(condition, description) {
  if (!condition) throw Error('BRC_OCI_SMOKE_DENIED:' + description);
  console.log(description + '=PASS');
}

const state = await untilHealthy();
must(state.ok === true && state.devices === 0, 'OCI_EMPTY_UNPAIRED_RELAY');
must(process.getuid?.() === 65534, 'OCI_NON_ROOT_IDENTITY');
must(fs.existsSync('/state/relay.sqlite'), 'OCI_SQLITE_EPHEMERAL_STATE');
must(!fs.existsSync('/root/.ssh/id_ed25519'), 'OCI_NO_HOST_SSH_PRIVATE_KEY');
must(!fs.existsSync('/var/lib/hermes-device-fabric/devices.sqlite3'), 'OCI_NO_PRESENCE_DATABASE');

try {
  fs.writeFileSync('/opt/brc/package.json', 'tampered');
  throw Error('OCI_SOURCE_IS_WRITABLE');
} catch (err) {
  if (err.message === 'OCI_SOURCE_IS_WRITABLE') throw err;
}
console.log('OCI_SOURCE_READONLY=PASS');

const unauthorized = await fetch(base + '/mcp', {
  method: 'POST',
  headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
});
must(unauthorized.status === 401, 'OCI_MCP_AUTH_REQUIRED');

const metadata = await (await fetch(base + '/.well-known/oauth-protected-resource/mcp')).json();
must(metadata.resource === base + '/mcp' &&
     Array.isArray(metadata.authorization_servers), 'OCI_OAUTH_RESOURCE_METADATA');

const page = await fetch(base + '/admin', { redirect: 'manual' });
must(page.status === 302 && new URL(page.headers.get('location'), base).pathname === '/auth/login',
     'OCI_ADMIN_LOGIN_REQUIRED');

const csrf = await fetch(base + '/auth/apikeys', {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ name: 'csrf-test' }),
  redirect: 'manual',
});
must(csrf.status === 403, 'OCI_BROWSER_ORIGIN_REQUIRED');
console.log('HERMES_BRC_NONROOT_OCI_RELAY_E2E=PASS');
