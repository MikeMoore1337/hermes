#!/usr/bin/env node
// #372: complete real browser OAuth PKCE -> HTTP MCP -> two real nonroot
// brc-agent processes in distinct disposable Docker filesystem namespaces.
// This runs INSIDE isolated CI only. Never touches owner machines.
import { createHash, randomBytes } from 'node:crypto';

const base = process.env.PUBLIC_URL ?? 'http://localhost:3000';
const pinnedDeviceId = 'h15-win-05be75515428';
const user = process.env.BRC_ADMIN_USER ?? 'ci-owner';
const pass = process.env.BRC_ADMIN_PASSWORD;
if (!pass) throw Error('CI_PASSWORD_NOT_PROVIDED');

const must = (ok, label) => {
  if (!ok) throw Error('TWO_NATIVE_MCP_FAILED:' + label);
  console.log(label + '=PASS');
};
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const readJson = async (res) => JSON.parse(await res.text());
const form = (obj) => new URLSearchParams(obj);
const b64 = (data) => data.toString('base64url');

let online = false;
for (let i = 0; i < 65; i++) {
  try {
    const r = await fetch(base + '/health', { signal: AbortSignal.timeout(1200) });
    const health = await r.json();
    if (r.ok && health.devices === 2) { online = true; break; }
  } catch {}
  await pause(250);
}
must(online, 'TWO_NATIVE_WSS_AGENTS_ONLINE');

const prm = await readJson(await fetch(base + '/.well-known/oauth-protected-resource/mcp'));
const meta = await readJson(await fetch(base + '/.well-known/oauth-authorization-server'));
must(prm.resource === base + '/mcp' && !!meta.authorization_endpoint &&
     !!meta.registration_endpoint && !!meta.token_endpoint,
     'TWO_NATIVE_OAUTH_DISCOVERY');
const redirectUri = 'https://hermes-ci.invalid/oauth-dummy';
const register = await readJson(await fetch(meta.registration_endpoint, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ client_name: 'H15 isolated CI only',
    redirect_uris: [redirectUri],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'], token_endpoint_auth_method: 'none' }),
}));
must(!!register.client_id, 'TWO_NATIVE_CLIENT_REGISTERED');

const verifier = b64(randomBytes(32));
const challenge = b64(createHash('sha256').update(verifier).digest());
const state = b64(randomBytes(12));
const authUrl = new URL(meta.authorization_endpoint);
for (const [k, v] of Object.entries({
  response_type: 'code', client_id: register.client_id,
  redirect_uri: redirectUri, code_challenge: challenge,
  code_challenge_method: 'S256', state, scope: 'mcp:tools',
  resource: prm.resource,
})) authUrl.searchParams.set(k, v);

const loginPage = await fetch(authUrl, { redirect: 'manual' });
const loginLoc = loginPage.headers.get('location') ?? '';
must(loginPage.status === 302 && loginLoc.startsWith('/auth/login'),
     'TWO_NATIVE_OAUTH_REDIRECT_TO_LOGIN');
const logged = await fetch(base + '/auth/login', {
  method: 'POST', redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: form({
    username: user, password: pass,
    returnTo: new URL(loginLoc, base).searchParams.get('returnTo') ?? '',
  }),
});
const cookie = (logged.headers.get('set-cookie') ?? '').split(';')[0];
const consentLoc = logged.headers.get('location') ?? '';
must(logged.status === 302 && cookie.startsWith('brc_session='),
     'TWO_NATIVE_OWNER_LOGIN');
const consentPage = await fetch(new URL(consentLoc, base), { headers: { cookie } });
const html = await consentPage.text();
const pending = html.match(/name="pending" value="([^"]+)"/)?.[1];
must(consentPage.status === 200 && !!pending, 'TWO_NATIVE_OWNER_CONSENT_PAGE');
const consent = await fetch(base + '/auth/consent', {
  method: 'POST', redirect: 'manual',
  headers: { cookie, origin: base, 'content-type': 'application/x-www-form-urlencoded' },
  body: form({ pending, decision: 'allow' }),
});
const callback = new URL(consent.headers.get('location') ?? base);
const code = callback.searchParams.get('code');
must(consent.status === 302 && code && callback.searchParams.get('state') === state,
     'TWO_NATIVE_PKCE_CODE_GRANTED');
const token = await readJson(await fetch(meta.token_endpoint, {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: form({
    grant_type: 'authorization_code', code, code_verifier: verifier,
    client_id: register.client_id, redirect_uri: redirectUri,
    resource: prm.resource,
  }),
}));
must(typeof token.access_token === 'string' && token.access_token.length > 20,
     'TWO_NATIVE_OAUTH_ACCESS_TOKEN');

const headers = {
  'content-type': 'application/json',
  accept: 'application/json, text/event-stream',
  authorization: 'Bearer ' + token.access_token,
};
let rpcId = 0;
async function rpc(method, params) {
  const response = await fetch(base + '/mcp', {
    method: 'POST', headers,
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
    signal: AbortSignal.timeout(10000),
  });
  const text = await response.text();
  const m = text.match(/^data: (.+)$/m);
  const obj = JSON.parse(m?.[1] ?? text);
  if (!response.ok || obj.error) {
    throw Error('MCP_HTTP_ERROR:' + method + ':' + response.status);
  }
  return obj.result;
}
const init = await rpc('initialize', {
  protocolVersion: '2025-06-18', capabilities: {},
  clientInfo: { name: 'hermes-native-ci', version: '1' },
});
must(init.serverInfo?.name === 'brc', 'TWO_NATIVE_MCP_INITIALIZE');
const t = await rpc('tools/list', {});
const tools = new Set(t.tools.map((x) => x.name));
must(tools.has('read_file') && tools.has('write_file') &&
     tools.has('start_process') && tools.has('list_devices'),
     'TWO_NATIVE_MCP_REAL_FILE_AND_PROCESS_TOOLS');
must(!tools.has('get_config') && !tools.has('send_file_transfer') &&
     !tools.has('set_config_value') && !tools.has('get_recent_tool_calls'),
     'TWO_NATIVE_MCP_RESTRICTED_TOOLSET');
const call = (name, args) => rpc('tools/call', { name, arguments: args });

// #454: REAL authenticated OAuth HTTP MCP discovery/calls, not a direct TS unit call.
// Device names and token are disposable CI fixtures. Git checkouts are never mounted.
must(tools.has('list_workspaces') && tools.has('resolve_workspace'),
     'H15_WORKSPACE_TOOLS_ADVERTISED_OVER_OAUTH_MCP');
const workspaceList = await call('list_workspaces', {});
const workspaceCatalog = JSON.parse(workspaceList.content?.[0]?.text ?? '{}');
must(workspaceList.isError !== true && workspaceCatalog.status === 'catalog' &&
     workspaceCatalog.workspaces?.length === 4 &&
     workspaceCatalog.workspaces.every(w => w.scope === 'sandbox' && w.git_verified === false &&
       w.deviceId === pinnedDeviceId && w.device_status === 'online'),
     'H15_OWNER_SCOPED_WORKSPACE_CATALOG_OVER_OAUTH_MCP');
for (const [alias, expected] of [
  ['YFC', 'your-fitness-coach'],
  ['toolkit', 'ai-development-toolkit'],
  ['second brain', 'second-brain'],
  ['hermes', 'hermes'],
]) {
  const result = await call('resolve_workspace', { project: alias });
  const resolved = JSON.parse(result.content?.[0]?.text ?? '{}');
  must(result.isError !== true && resolved.status === 'resolved' &&
       resolved.workspace === expected && resolved.root === '/workspace/projects/' + expected &&
       resolved.deviceId === pinnedDeviceId && resolved.git_verified === false &&
       resolved.verification_required_before_write === true,
       'H15_OAUTH_MCP_RESOLVE_' + expected.toUpperCase().replaceAll('-', '_'));
}
for (const args of [
  { project: '../../host-private' },
  { project: 'YFC', deviceId: 'ci-native-two' },
  { project: '/workspace/projects/hermes' },
  {},
]) {
  const result = await call('resolve_workspace', args);
  const refused = JSON.parse(result.content?.[0]?.text ?? '{}');
  must(result.isError === true && refused.status === 'refused',
       'H15_OAUTH_MCP_WORKSPACE_INVALID_REQUEST_DENIED');
}

const list = await call('list_devices', {});
const discovered = JSON.parse(list.content[0].text).devices;
const ids = new Set(discovered.filter((x) => x.online).map((x) => x.deviceId));
must(ids.size === 2 && ids.has(pinnedDeviceId) && ids.has('ci-native-two'),
     'TWO_NATIVE_REAL_MCP_DISCOVERY');
const implicit = await call('read_file', { path: '/workspace/identity.txt' });
must(implicit.isError === true, 'TWO_NATIVE_AMBIGUOUS_DEVICE_REFUSED');

// Identical paths exist on both agents; the approved catalog must choose
// the pinned owner device only when the caller omitted a device ID.
const projectPath = '/workspace/projects/hermes/identity.txt';
const autoProject = await call('read_file', { path: projectPath });
must(autoProject.isError !== true && JSON.stringify(autoProject).includes('project-on-owner-device') &&
     !JSON.stringify(autoProject).includes('project-on-other-device'),
     'H15_WORKSPACE_PATH_ROUTES_TO_PINNED_DEVICE');
const explicitOther = await call('read_file', { deviceId:'ci-native-two', path:projectPath });
must(explicitOther.isError !== true && JSON.stringify(explicitOther).includes('project-on-other-device'),
     'H15_WORKSPACE_EXPLICIT_DEVICE_UNCHANGED');
const mixedPaths = await call('read_multiple_files', { paths:[projectPath, '/workspace/identity.txt'] });
must(mixedPaths.isError === true && JSON.stringify(mixedPaths).includes('workspace_paths_not_routable'),
     'H15_WORKSPACE_MIXED_PATHS_REFUSED');
const searchStart = await call('start_search', {
  path:'/workspace/projects/hermes', pattern:'identity.txt', searchType:'files', timeout_ms:5000,
});
const searchText = searchStart.content?.[0]?.text ?? '';
const searchId = searchText.match(/^Started file search session: (hermes_search_[a-f0-9]{32}_search_[1-9][0-9]*_[0-9]+)\n/)?.[1];
must(searchStart.isError !== true && !!searchId, 'H15_WORKSPACE_SEARCH_SESSION_BOUND');
const secondStart = await call('start_search', {
  path:'/workspace/projects/hermes', pattern:'project-on-owner-device', searchType:'content', timeout_ms:5000,
});
const secondId = (secondStart.content?.[0]?.text ?? '').match(/^Started content search session: (hermes_search_[a-f0-9]{32}_search_[1-9][0-9]*_[0-9]+)\n/)?.[1];
must(secondStart.isError !== true && !!secondId && secondId !== searchId,
     'H15_WORKSPACE_TWO_SEARCH_SESSIONS_BOUND');
const secondResults = await call('get_more_search_results', { sessionId:secondId, length:20 });
must(secondResults.isError !== true && JSON.stringify(secondResults).includes(secondId),
     'H15_WORKSPACE_SECOND_SEARCH_RESULTS_ROUTED');
let searchResults;
for (let i=0;i<20;i++) {
  searchResults = await call('get_more_search_results', { sessionId:searchId, length:20 });
  if (JSON.stringify(searchResults).includes('identity.txt')) break;
  await pause(100);
}
must(searchResults.isError !== true && JSON.stringify(searchResults).includes(searchId) &&
     JSON.stringify(searchResults).includes('identity.txt'), 'H15_WORKSPACE_SEARCH_RESULTS_ROUTED');
const wrongSearchDevice = await call('get_more_search_results', { sessionId:searchId, deviceId:'ci-native-two' });
must(wrongSearchDevice.isError === true && JSON.stringify(wrongSearchDevice).includes('search_device_mismatch'),
     'H15_WORKSPACE_SEARCH_OTHER_DEVICE_REFUSED');
const missingSearchId = searchId.replace(/search_[1-9][0-9]*_[0-9]+$/, 'search_999999_1');
const missingSearch = await call('stop_search', { sessionId:missingSearchId });
must(missingSearch.isError === true && JSON.stringify(missingSearch).includes('not found'),
     'H15_WORKSPACE_MISSING_SEARCH_IS_ERROR');
const stoppedSearch = await call('stop_search', { sessionId:searchId });
must(stoppedSearch.isError !== true && JSON.stringify(stoppedSearch).includes(searchId),
     'H15_WORKSPACE_SEARCH_STOP_ROUTED');
const stoppedSecond = await call('stop_search', { sessionId:secondId });
must(stoppedSecond.isError !== true && JSON.stringify(stoppedSecond).includes(secondId),
     'H15_WORKSPACE_SECOND_SEARCH_STOP_ROUTED');

for (const [id, expected] of [
  [pinnedDeviceId, 'real-ci-agent-one'],
  ['ci-native-two', 'real-ci-agent-two'],
]) {
  const result = await call('read_file', {
    deviceId: id, path: '/workspace/identity.txt',
  });
  const text = JSON.stringify(result);
  must(result.isError !== true && text.includes(expected),
       'TWO_NATIVE_REAL_FILE_READ_' + id.toUpperCase().replaceAll('-', '_'));
  must(!text.includes(id === pinnedDeviceId ? 'real-ci-agent-two' : 'real-ci-agent-one'),
       'TWO_NATIVE_NO_CROSS_DEVICE_CONTENT_' + id.toUpperCase().replaceAll('-', '_'));
}

const write = await call('write_file', {
  deviceId: pinnedDeviceId, path: '/workspace/mcp-owner-proof.txt',
  content: 'owner-approved-ephemeral-mcp-file', mode: 'rewrite',
});
must(write.isError !== true, 'TWO_NATIVE_REAL_FILE_WRITE');
const readBack = await call('read_file', {
  deviceId: pinnedDeviceId, path: '/workspace/mcp-owner-proof.txt',
});
must(readBack.isError !== true &&
     JSON.stringify(readBack).includes('owner-approved-ephemeral-mcp-file'),
     'TWO_NATIVE_WRITTEN_FILE_READ_BACK');

const deniedPath = await call('write_file', {
  deviceId: 'ci-native-two', path: '/opt/brc/package.json',
  content: 'unauthorized', mode: 'rewrite',
});
must(deniedPath.isError === true, 'TWO_NATIVE_SOURCE_WRITE_DENIED_BY_KERNEL');
const deniedRead = await call('read_file', {
  deviceId: 'ci-native-two', path: '/root/.ssh/id_ed25519',
});
must(deniedRead.isError === true, 'TWO_NATIVE_HOST_PRIVATE_KEY_UNAVAILABLE');

const terminal = await call('start_process', {
  deviceId: 'ci-native-two', command: 'echo hermes-two-native-ci-shell',
  timeout_ms: 10000,
});
must(terminal.isError !== true &&
     JSON.stringify(terminal).includes('hermes-two-native-ci-shell'),
     'TWO_NATIVE_REAL_SHELL_ECHO');

const disallowed = await call('get_config', { deviceId: pinnedDeviceId });
must(disallowed.isError === true, 'TWO_NATIVE_DIRECT_CONFIG_ACCESS_DENIED');

// The synthetic admin can pause exactly one device while the other
// remains available. Validate through the same MCP HTTP client.
const paused = await fetch(base + '/admin/device', {
  method: 'POST', redirect: 'manual',
  headers: { cookie, origin: base, 'content-type': 'application/x-www-form-urlencoded' },
  body: form({ device_id: 'ci-native-two', action: 'pause' }),
});
must(paused.status === 302, 'TWO_NATIVE_OWNER_PAUSE_APPLIED');
const pauseResult = await call('read_file', {
  deviceId: 'ci-native-two', path: '/workspace/identity.txt',
});
must(pauseResult.isError === true, 'TWO_NATIVE_PAUSED_DEVICE_REFUSED');
const unaffected = await call('read_file', {
  deviceId: pinnedDeviceId, path: '/workspace/identity.txt',
});
must(unaffected.isError !== true && JSON.stringify(unaffected).includes('real-ci-agent-one'),
     'TWO_NATIVE_OTHER_DEVICE_UNAFFECTED');

// Pausing the unrelated VPS agent must not alter the selected Windows workspace.
const stillOnline = await call('resolve_workspace', { project: 'YFC' });
must(stillOnline.isError !== true &&
     JSON.parse(stillOnline.content?.[0]?.text ?? '{}').deviceId === pinnedDeviceId,
     'H15_OWNER_WORKSPACE_UNRELATED_DEVICE_PAUSE_UNAFFECTED');
const resumed = await fetch(base + '/admin/device', {
  method: 'POST', redirect: 'manual',
  headers: { cookie, origin: base, 'content-type': 'application/x-www-form-urlencoded' },
  body: form({ device_id: 'ci-native-two', action: 'resume' }),
});
must(resumed.status === 302, 'TWO_NATIVE_OTHER_DEVICE_RESUMED');

const malformedToken = await fetch(base + '/mcp', {
  method: 'POST',
  headers: { ...headers, authorization: 'Bearer denied-fixture' },
  body: JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'tools/list', params: {} }),
});
must(malformedToken.status === 401, 'TWO_NATIVE_WRONG_OAUTH_TOKEN_REFUSED');
// Pause the actual project device. The relay must refuse workspace resolution.
const pauseWindows = await fetch(base + '/admin/device', {
  method: 'POST', redirect: 'manual',
  headers: { cookie, origin: base, 'content-type': 'application/x-www-form-urlencoded' },
  body: form({ device_id: pinnedDeviceId, action: 'pause' }),
});
must(pauseWindows.status === 302, 'H15_WORKSPACE_DEVICE_OWNER_PAUSE_APPLIED');
const stoppedWorkspace = await call('resolve_workspace', { project: 'YFC' });
must(stoppedWorkspace.isError === true &&
     JSON.parse(stoppedWorkspace.content?.[0]?.text ?? '{}').reason === 'owner_device_unavailable',
     'H15_WORKSPACE_PAUSED_OWNER_DEVICE_REFUSED');
const stoppedAuto = await call('read_file', { path:projectPath });
must(stoppedAuto.isError === true && JSON.stringify(stoppedAuto).includes('owner_device_unavailable'),
     'H15_WORKSPACE_PAUSED_OWNER_NO_FALLBACK');
const stoppedSearchOwner = await call('get_more_search_results', { sessionId:searchId });
must(stoppedSearchOwner.isError === true && JSON.stringify(stoppedSearchOwner).includes('owner_device_unavailable'),
     'H15_WORKSPACE_SEARCH_PAUSED_OWNER_NO_FALLBACK');
const otherStillOnline = await call('read_file', { deviceId:'ci-native-two', path:projectPath });
must(otherStillOnline.isError !== true && JSON.stringify(otherStillOnline).includes('project-on-other-device'),
     'H15_WORKSPACE_OTHER_DEVICE_REMAINS_ONLINE');
const noncanonical = await call('read_file', { path:'/workspace//projects/hermes/identity.txt' });
must(noncanonical.isError === true && JSON.stringify(noncanonical).includes('workspace_paths_not_routable'),
     'H15_WORKSPACE_NONCANONICAL_NO_FALLBACK');
const emptyDevice = await call('read_file', { deviceId:'', path:projectPath });
must(emptyDevice.isError === true && JSON.stringify(emptyDevice).includes('invalid_device_id'),
     'H15_WORKSPACE_EMPTY_DEVICE_NO_FALLBACK');
const oversized = await call('read_multiple_files', { paths:Array(65).fill(projectPath) });
must(oversized.isError === true && JSON.stringify(oversized).includes('workspace_paths_not_routable'),
     'H15_WORKSPACE_OVERSIZED_NO_FALLBACK');
console.log('H15_OAUTH_MCP_WORKSPACE_ROUTING_E2E=PASS');

console.log('HERMES_BRC_TWO_REAL_NATIVE_AGENTS_OAUTH_MCP_E2E=PASS');
