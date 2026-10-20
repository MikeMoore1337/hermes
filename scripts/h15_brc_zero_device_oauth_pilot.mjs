#!/usr/bin/env node
// #371/#372: OAuth-only, zero-device, network-none BRC pilot.
// This script only performs OAuth HTTP discovery, registration, test-only
// owner consent, token/refresh flows and safe MCP initialize. No tools/call,
// no filesystem API, no command execution, no agent enrollment.
import { createHash, randomBytes } from 'node:crypto';

const loopback = 'http://127.0.0.1:3000';
const admin = process.env.BRC_ADMIN_USER || 'admin';
const password = process.env.BRC_ADMIN_PASSWORD;
if (typeof password !== 'string' || password.length < 16) throw Error('EPHEMERAL_ADMIN_SECRET_MISSING');
const body = (data) => new URLSearchParams(data);
const b64 = (x) => x.toString('base64url');
const must = (yes, label) => {
  if (!yes) throw Error('H15_OAUTH_ONLY_DENIED_' + label);
  console.log('H15_OAUTH_ONLY_' + label + '=PASS');
};
const safe = (endpoint, opts = {}) => {
  const url = new URL(endpoint, loopback);
  // Refuse redirects and all actual off-container HTTP traffic.
  if (url.protocol !== 'http:' ||
      !['127.0.0.1', 'localhost'].includes(url.hostname) ||
      url.port !== '3000' || url.username || url.password)
    throw Error('OAUTH_ENDPOINT_NOT_ISOLATED_LOOPBACK');
  url.hostname = '127.0.0.1';
  return fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(6000), ...opts });
};
const readJson = async (response) => {
  if (!response.ok) throw Error('OAUTH_RESPONSE_NOT_SUCCESSFUL_' + response.status);
  return response.json();
};
const jsonRpcBody = (method, params, id) =>
  JSON.stringify({ jsonrpc: '2.0', id, method, params });

let healthy;
for (let i = 0; i < 30; i++) {
  try {
    const resp = await safe('/health');
    const data = await resp.json();
    if (resp.ok && data.ok === true && data.devices === 0) {
      healthy = true;
      break;
    }
  } catch {}
  await new Promise((resolve) => setTimeout(resolve, 250));
}
must(healthy === true, 'NO_PAIRED_DEVICES');

const prm = await readJson(await safe('/.well-known/oauth-protected-resource/mcp'));
const meta = await readJson(await safe('/.well-known/oauth-authorization-server'));
const publicIssuer = new URL(meta.issuer);
must(publicIssuer.protocol === 'http:' &&
     ['127.0.0.1', 'localhost'].includes(publicIssuer.hostname) &&
     publicIssuer.port === '3000' &&
     prm.resource === meta.issuer + '/mcp' &&
     meta.code_challenge_methods_supported?.includes('S256') &&
     Boolean(meta.authorization_endpoint && meta.token_endpoint &&
             meta.registration_endpoint),
     'LOOPBACK_DISCOVERY_PKCE_S256');

const reqHeaders = {
  'content-type': 'application/json',
  accept: 'application/json, text/event-stream',
};
const unauthenticated = await safe('/mcp', {
  method: 'POST', headers: reqHeaders,
  body: jsonRpcBody('initialize', {
    protocolVersion: '2025-06-18', capabilities: {},
    clientInfo: { name: 'h15-zero-device', version: '1' },
  }, 1),
});
must(unauthenticated.status === 401, 'UNAUTHENTICATED_MCP_DENIED');

const redirect = 'https://hermes-oauth-only.invalid/never-follow';
const reg = await readJson(await safe(meta.registration_endpoint, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    client_name: 'Hermes local isolated zero-device OAuth test',
    redirect_uris: [redirect],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  }),
}));
must(typeof reg.client_id === 'string' && reg.client_id.length > 4, 'LOCAL_TEST_CLIENT_REGISTERED');

const verifier = b64(randomBytes(32));
const challenge = b64(createHash('sha256').update(verifier).digest());
const state = b64(randomBytes(12));
const authUrl = new URL(meta.authorization_endpoint);
for (const [key, value] of Object.entries({
  response_type: 'code', client_id: reg.client_id, redirect_uri: redirect,
  code_challenge: challenge, code_challenge_method: 'S256',
  state, scope: 'mcp:tools', resource: prm.resource,
})) authUrl.searchParams.set(key, value);
const auth = await safe(authUrl);
const loginLocation = auth.headers.get('location') ?? '';
must(auth.status === 302 && loginLocation.startsWith('/auth/login'), 'AUTH_REQUIRES_LOGIN');

const login = await safe('/auth/login', {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: body({
    username: admin, password,
    returnTo: new URL(loginLocation, loopback).searchParams.get('returnTo') ?? '',
  }),
});
const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0];
must(login.status === 302 && cookie.startsWith('brc_session='), 'EPHEMERAL_OWNER_LOGIN');

const page = await safe(login.headers.get('location') ?? '', { headers: { cookie } });
const html = await page.text();
const pending = html.match(/name="pending" value="([^"]+)"/)?.[1];
must(page.status === 200 && typeof pending === 'string', 'OWNER_CONSENT_PAGE');

const consent = await safe('/auth/consent', {
  method: 'POST',
  headers: {
    cookie, origin: meta.issuer, 'content-type': 'application/x-www-form-urlencoded',
  },
  body: body({ pending, decision: 'allow' }),
});
const callback = new URL(consent.headers.get('location') ?? 'https://invalid.invalid/');
const code = callback.searchParams.get('code');
must(consent.status === 302 && callback.origin === new URL(redirect).origin &&
     code?.length > 8 && callback.searchParams.get('state') === state,
     'PKCE_AUTHORIZATION_CODE_GRANTED');

const exchangeBody = body({
  grant_type: 'authorization_code', code, code_verifier: verifier,
  client_id: reg.client_id, redirect_uri: redirect, resource: prm.resource,
});
// An invalid PKCE verifier must not redeem or consume a valid authorization code.
const wrongVerifier = await safe(meta.token_endpoint, {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: body({
    grant_type: 'authorization_code', code,
    code_verifier: b64(randomBytes(32)), client_id: reg.client_id,
    redirect_uri: redirect, resource: prm.resource,
  }),
});
must(wrongVerifier.status >= 400 && wrongVerifier.status < 500,
     'WRONG_PKCE_VERIFIER_DENIED');

const token = await readJson(await safe(meta.token_endpoint, {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: exchangeBody,
}));
must(typeof token.access_token === 'string' && token.access_token.length > 20 &&
     typeof token.refresh_token === 'string' && token.refresh_token.length > 20,
     'S256_ACCESS_AND_REFRESH_TOKENS');

const headers = { ...reqHeaders, authorization: 'Bearer ' + token.access_token };
const init = await safe('/mcp', {
  method: 'POST', headers,
  body: jsonRpcBody('initialize', {
    protocolVersion: '2025-06-18', capabilities: {},
    clientInfo: { name: 'h15-zero-device', version: '1' },
  }, 2),
});
const responseText = await init.text();
const eventData = responseText.match(/^data: (.+)$/m)?.[1] ?? responseText;
let rpc;
try { rpc = JSON.parse(eventData); } catch { throw Error('OAUTH_AUTHORIZED_MCP_MALFORMED'); }
must(init.status === 200 && rpc?.result?.serverInfo?.name === 'brc',
     'MCP_INITIALIZE_WITH_BEARER');

const replay = await safe(meta.token_endpoint, {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: exchangeBody,
});
must(replay.status >= 400 && replay.status < 500, 'AUTHORIZATION_CODE_REPLAY_DENIED');

const wrong = await safe('/mcp', {
  method: 'POST', headers: { ...reqHeaders, authorization: 'Bearer h15-invalid-token' },
  body: jsonRpcBody('initialize', {}, 3),
});
must(wrong.status === 401, 'INVALID_BEARER_DENIED');

const refreshed = await readJson(await safe(meta.token_endpoint, {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: body({
    grant_type: 'refresh_token', refresh_token: token.refresh_token,
    client_id: reg.client_id,
  }),
}));
must(typeof refreshed.access_token === 'string' &&
     refreshed.access_token.length > 20 &&
     typeof refreshed.refresh_token === 'string' &&
     refreshed.refresh_token !== token.refresh_token,
     'REFRESH_TOKEN_ROTATED');
const reuse = await safe(meta.token_endpoint, {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: body({
    grant_type: 'refresh_token', refresh_token: token.refresh_token,
    client_id: reg.client_id,
  }),
});
must(reuse.status >= 400 && reuse.status < 500, 'OLD_REFRESH_TOKEN_REPLAY_DENIED');

// Revocation requires client ownership: another dynamically registered client
// must not revoke our access token. The endpoint deliberately returns 200 to
// avoid leaking token existence (RFC 7009); verify by reusing the real token.
must(typeof meta.revocation_endpoint === 'string', 'REVOCATION_ENDPOINT_ADVERTISED');
const otherClient = await readJson(await safe(meta.registration_endpoint, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    client_name: 'H15 unauthorized revocation client',
    redirect_uris: [redirect],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'], token_endpoint_auth_method: 'none',
  }),
}));
must(typeof otherClient.client_id === 'string' &&
     otherClient.client_id !== reg.client_id, 'SEPARATE_OAUTH_CLIENT_REGISTERED');
const revoke = (clientId, value, kind) => safe(meta.revocation_endpoint, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: body({ client_id: clientId, token: value, token_type_hint: kind }),
});
const foreignRevoke = await revoke(otherClient.client_id, refreshed.access_token, 'access_token');
must(foreignRevoke.status === 200, 'FOREIGN_REVOKE_OPAQUE_RESPONSE');
const stillAuthorized = await safe('/mcp', {
  method: 'POST',
  headers: { ...reqHeaders, authorization: 'Bearer ' + refreshed.access_token },
  body: jsonRpcBody('initialize', {
    protocolVersion: '2025-06-18', capabilities: {},
    clientInfo: { name: 'h15-zero-device', version: '1' },
  }, 4),
});
must(stillAuthorized.status === 200, 'FOREIGN_CLIENT_CANNOT_REVOKE_ACCESS');

const ownAccessRevoke = await revoke(reg.client_id, refreshed.access_token, 'access_token');
must(ownAccessRevoke.status === 200, 'ACCESS_TOKEN_REVOKE_ACCEPTED');
const revokedAccess = await safe('/mcp', {
  method: 'POST',
  headers: { ...reqHeaders, authorization: 'Bearer ' + refreshed.access_token },
  body: jsonRpcBody('initialize', {}, 5),
});
must(revokedAccess.status === 401, 'REVOKED_ACCESS_TOKEN_DENIED');

const ownRefreshRevoke = await revoke(reg.client_id, refreshed.refresh_token, 'refresh_token');
must(ownRefreshRevoke.status === 200, 'REFRESH_TOKEN_REVOKE_ACCEPTED');
const revokedRefresh = await safe(meta.token_endpoint, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: body({
    grant_type: 'refresh_token', refresh_token: refreshed.refresh_token,
    client_id: reg.client_id,
  }),
});
must(revokedRefresh.status >= 400 && revokedRefresh.status < 500,
     'REVOKED_REFRESH_TOKEN_DENIED');

const end = await readJson(await safe('/health'));
must(end.devices === 0, 'ZERO_DEVICES_AFTER_OAUTH');
console.log('H15_OAUTH_ONLY_SHELL_FILE_CALLS=NONE');
console.log('H15_OAUTH_ONLY_INTERNET_EGRESS=NONE');
console.log('H15_OAUTH_ONLY_RELEASE_APPROVAL=NO');
console.log('H15_OAUTH_ONLY_END_TO_END=PASS');
