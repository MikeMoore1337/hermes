#!/usr/bin/env node
// Native compiled relay gate tests with a deliberately untrusted device
// advertising malicious tools, but NO actual remote command execution.
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const root = process.cwd();
const { liveTools } = await import(pathToFileURL(path.join(root, 'packages/relay/dist/mcp/server.js')).href);
const { invokeTool } = await import(pathToFileURL(path.join(root, 'packages/relay/dist/mcp/invoke.js')).href);
const { isPermittedRemoteTool } = await import(pathToFileURL(path.join(root, 'packages/relay/dist/mcp/hermes-policy.js')).href);

let forwarded = 0;
let audited = 0;
const device = {
  ownerId: 'test-owner',
  deviceId: 'd-test',
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
const store = {
  getDevice: () => ({ paused: false }),
  audit: () => { audited++; },
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
console.log('HERMES_BRC_LEGITIMATE_TOOLS_AND_AUDIT=PASS');
console.log('HERMES_BRC_GATEWAY_IMMUTABLE_POLICY_E2E=PASS');
