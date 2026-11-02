#!/usr/bin/env node
// Native compiled relay gate tests with a deliberately untrusted device
// advertising malicious tools, but NO actual remote command execution.
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const root = process.cwd();
const { liveTools } = await import(pathToFileURL(path.join(root, 'packages/relay/dist/mcp/server.js')).href);
const { pinnedToolCatalog } = await import(pathToFileURL(path.join(root, 'packages/relay/dist/mcp/hermes-tool-catalog.js')).href);
const { invokeTool } = await import(pathToFileURL(path.join(root, 'packages/relay/dist/mcp/invoke.js')).href);
const { isPermittedRemoteTool } = await import(pathToFileURL(path.join(root, 'packages/relay/dist/mcp/hermes-policy.js')).href);

// ChatGPT imports tool schemas before any device has been paired. That
// discovery must not depend on online agents or allow malicious agent schemas.
const pinned = pinnedToolCatalog();
const pinnedNames = new Set(pinned.map(t => t.name));
if (!['read_file', 'write_file', 'start_process'].every(t => pinnedNames.has(t)) ||
    ['get_config', 'set_config_value', 'send_file_transfer', 'unexpected_future_exec'].some(t => pinnedNames.has(t)) ||
    pinned.some(t => !t.inputSchema || typeof t.inputSchema !== 'object')) {
  throw Error('CHATGPT_PRE_PAIR_STABLE_TOOLS_INVALID');
}
console.log('H15_CHATGPT_PRE_PAIR_STABLE_MCP_TOOLS=PASS');

let forwarded = 0;
let audited = 0;
const auditRows = [];
const device = {
  ownerId: 'test-owner',
  deviceId: 'd-test',
  socket: {hermesAuthTokenHash: 'ci-token-hash'},
  info: { name: 'untrusted-device' },
  tools: [
    'get_config', 'get_recent_tool_calls', 'set_config_value',
    'send_file_transfer', 'start_process', 'read_file', 'write_file',
    'unexpected_future_exec'
  ].map((name) => ({
    name, description: name, inputSchema: { type: 'object', properties: {} },
  })),
};
const hub = {
  list: () => [{ deviceId: 'd-test' }],
  get: (id) => id === 'd-test' ? device : undefined,
  resolveDefault: () => 'd-test',
  call: async (_deviceId, name) => {
    forwarded++;
    return { isError: false, content: [{ type: 'text', text: 'fake-' + name }] };
  },
};
let grant = {user_id: 'test-owner', token_hash: 'ci-token-hash', paused: false};
const store = {
  getDevice: () => grant,
  audit: row => { audited++; auditRows.push(row); },
  touchDevice: () => {},
};
const ctx = { userId: 'test-owner', clientId: 'test-client' };
const listed = new Set(liveTools(hub, store, ctx.userId).tools.map((t) => t.name));
for (const name of [
  'get_config', 'get_recent_tool_calls', 'set_config_value',
  'send_file_transfer', 'unexpected_future_exec',
]) {
  if (listed.has(name) || isPermittedRemoteTool(name, {})) throw Error('UNSAFE_TOOL_ADVERTISED:' + name);
  const before = forwarded;
  const result = await invokeTool(hub, store, ctx, name, { deviceId: 'd-test' });
  if (result.ok || forwarded !== before || result.status !== 403) {
    throw Error('UNSAFE_TOOL_FORWARDED:' + name);
  }
}
console.log('HERMES_BRC_MALICIOUS_AGENT_TOOL_GATE=PASS');

for (const args of [{ isUrl: true, path: 'https://example.invalid' },
                   { isUrl: true, path: 'file:///etc/passwd' }]) {
  const before = forwarded;
  const result = await invokeTool(hub, store, ctx, 'read_file', args);
  if (result.ok || forwarded !== before) throw Error('REMOTE_URL_READ_GATE_BYPASS');
}
console.log('HERMES_BRC_GATEWAY_URL_FETCH=DENIED');

if (!listed.has('read_file') || !listed.has('write_file') || !listed.has('start_process')) {
  throw Error('REAL_COMPATIBLE_TOOLS_NOT_ADVERTISED');
}
for (const name of ['read_file', 'write_file', 'start_process']) {
  const result = await invokeTool(hub, store, ctx, name, { path: '/workspace/test' });
  if (!result.ok) throw Error('LEGITIMATE_TOOL_REFUSED:' + name);
}
if (forwarded !== 3 || audited !== 3) {
  throw Error('INCORRECT_ALLOWLIST_ROUTING_OR_AUDIT');
}

// A removed, transferred, re-keyed or paused device must not be able to run a
// queued tool even when its old socket remains present in DeviceHub.
const deniedGrants = [
  ['deleted', undefined, 403],
  ['wrong_owner', {user_id:'other-owner',token_hash:'ci-token-hash',paused:false}, 403],
  ['rotated_token', {user_id:'test-owner',token_hash:'another-hash',paused:false}, 403],
  ['paused', {user_id:'test-owner',token_hash:'ci-token-hash',paused:true}, 423],
];
for (const [scenario, candidate, expectedStatus] of deniedGrants) {
  grant = candidate;
  const before = forwarded;
  const result = await invokeTool(hub, store, ctx, 'read_file',
    {deviceId:'d-test',path:'/workspace/denied'});
  if (result.ok || result.status !== expectedStatus || forwarded !== before) {
    throw Error('DEVICE_GRANT_BOUNDARY_BYPASS:' + scenario);
  }
}
grant = {user_id:'test-owner',token_hash:'ci-token-hash',paused:false};
console.log('HERMES_BRC_DELETED_REKEYED_CROSS_OWNER_AND_PAUSED_GRANTS=DENIED');


// A malicious device may put arbitrary secret-looking strings in its remote
// exception text. Neither the persistent audit receipt nor MCP result may
// contain the untrusted raw message.
const originalHubCall = hub.call;
const syntheticSecret = 'CI_SYNTHETIC_REMOTE_SECRET_DO_NOT_EXPOSE';
for (const [remoteError, safeCode, status] of [
  ['UNKNOWN_TOOL: ' + syntheticSecret, 'UNKNOWN_TOOL', 404],
  ['CALL_TIMEOUT: ' + syntheticSecret, 'CALL_TIMEOUT', 504],
  ['untrusted exception: ' + syntheticSecret, 'REMOTE_TOOL_FAILED', 502],
]) {
  hub.call = async () => { throw Error(remoteError); };
  const result = await invokeTool(hub, store, ctx, 'read_file',
    {deviceId:'d-test',path:'/workspace/synthetic-only'});
  const recorded = auditRows.at(-1);
  if (result.ok || result.status !== status ||
      result.message !== 'Relay error: ' + safeCode ||
      recorded?.error !== safeCode ||
      JSON.stringify({result,recorded}).includes(syntheticSecret)) {
    throw Error('MCP_REMOTE_ERROR_SECRET_LEAK:' + safeCode);
  }
}
hub.call = originalHubCall;
console.log('HERMES_BRC_UNTRUSTED_REMOTE_ERROR_AUDIT_AND_MCP=REDACTED');

console.log('HERMES_BRC_LEGITIMATE_TOOLS_AND_AUDIT=PASS');
console.log('HERMES_BRC_GATEWAY_IMMUTABLE_POLICY_E2E=PASS');
