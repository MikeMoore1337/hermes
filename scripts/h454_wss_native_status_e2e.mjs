import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { readFileSync } from 'node:fs';

import { EventEmitter } from 'node:events';
import { createProxy, nativeStatusResponse, privateIPv4 } from './h454_wss_relay_proxy.mjs';

const ID = 'h454-linux-hermes-' + 'a'.repeat(32);
const key = letter => 'Bearer brc_dev_' + letter.repeat(64);
const GOOD = key('A');
const BAD = key('B');
const REDIRECT = key('C');
const LARGE = key('D');
const FORGED = key('E');
const ERROR = key('F');
const raw = () => JSON.stringify({
  schema: 'h454-native-device-status-v1', device_id: ID,
  active: true, owner_bound: true,
});
let forwarded = 0;
let forwardedTokens = [];
const backend = http.createServer((req, res) => {
  forwarded++;
  forwardedTokens.push(req.headers.authorization);
  assert.equal(req.method, 'GET');
  assert.equal(req.url, '/device/native-status');
  assert.equal(req.headers.cookie, undefined);
  if (req.headers.authorization === GOOD) {
    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(raw());
  } else if (req.headers.authorization === REDIRECT) {
    res.writeHead(302, {Location: '/administrator'}); res.end();
  } else if (req.headers.authorization === LARGE) {
    res.writeHead(200); res.end('X'.repeat(1500));
  } else if (req.headers.authorization === FORGED) {
    res.writeHead(200);
    res.end(JSON.stringify({...JSON.parse(raw()), superuser: true}));
  } else if (req.headers.authorization === ERROR) {
    res.writeHead(500); res.end();
  } else {
    res.writeHead(403); res.end();
  }
});
await new Promise((resolve, reject) => {
  backend.once('error', reject);
  backend.listen(0, '127.0.0.1', resolve);
});
const port = backend.address().port;
class SyntheticResponse extends EventEmitter {
  constructor() { super(); this.destroyed = false; this.status = 0; this.headers = {}; this.body = ''; }
  writeHead(status, headers) { this.status = status; this.headers = headers; }
  end(body = '') { this.body = body; this.emit('close'); }
}
function probe({auth = GOOD, peer = '127.0.0.1', method = 'GET',
                url = '/device/native-status', headers = null} = {}) {
  const res = new SyntheticResponse();
  const entries = headers ?? (auth ? ['Authorization', auth] : []);
  const req = {url, method, httpVersion: '1.1', rawHeaders: entries,
    headers: {authorization: auth}, socket: {remoteAddress: peer}};
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('STATUS_PROXY_TIMEOUT')), 6000);
    res.once('close', () => {
      clearTimeout(timeout);
      resolve({status: res.status, headers: res.headers, body: res.body});
    });
    nativeStatusResponse(req, res, port, '127.0.0.1');
  });
}
try {
  assert.equal(privateIPv4('172.29.251.2'), true);
  assert.equal(privateIPv4('0.0.0.0'), false);
  const accepted = await probe();
  assert.equal(accepted.status, 200);
  assert.equal(accepted.headers['Cache-Control'], 'no-store');
  assert.deepEqual(JSON.parse(accepted.body), JSON.parse(raw()));
  assert.ok(!accepted.body.includes(GOOD));
  assert.equal(forwarded, 1);
  const blocked = await probe({auth: BAD});
  assert.equal(blocked.status, 403);
  assert.equal(forwarded, 2);
  assert.equal((await probe({auth: null})).status, 403);
  assert.equal((await probe({auth: 'not-a-bearer'})).status, 403);
  assert.equal((await probe({peer: '127.0.0.2'})).status, 403);
  assert.equal((await probe({method: 'POST'})).status, 403);
  assert.equal((await probe({url: '/device/native-status?token=abc'})).status, 404);
  assert.equal((await probe({url: '/device/start'})).status, 404);
  assert.equal((await probe({url: '/admin'})).status, 404);
  assert.equal((await probe({headers: ['Authorization', GOOD, 'Authorization', GOOD]})).status, 403);
  assert.equal((await probe({headers: ['Authorization', GOOD, 'Cookie', 'x=1']})).status, 403);
  assert.equal((await probe({headers: ['Authorization', GOOD, 'Transfer-Encoding', 'chunked']})).status, 403);
  assert.equal(forwarded, 2, 'invalid requests must not reach the relay');
  assert.equal((await probe({auth: REDIRECT})).status, 502);
  assert.equal((await probe({auth: LARGE})).status, 502);
  assert.equal((await probe({auth: FORGED})).status, 502);
  assert.equal((await probe({auth: ERROR})).status, 502);
  assert.equal(forwarded, 6);
  assert.deepEqual(forwardedTokens, [GOOD, BAD, REDIRECT, LARGE, FORGED, ERROR]);
  // Real TLS handshake against a disposable certificate with a pinned CA
  // and hostname. No owner bearer or external endpoint is ever contacted.
  const fixtures = process.argv[2];
  if (fixtures) {
    const read = name => readFileSync(fixtures + '/' + name);
    const proxy = createProxy({
      key: read('trusted.key'), cert: read('trusted.crt'),
      upstreamPort: port, allowedPeer: '127.0.0.1',
    });
    await new Promise((resolve, reject) => {
      proxy.once('error', reject);
      proxy.listen(0, '127.0.0.1', resolve);
    });
    const tlsPort = proxy.address().port;
    function tlsCall(auth, ca, servername = 'brc-agent.internal',
                     path = '/device/native-status') {
      return new Promise((resolve, reject) => {
        const req = https.request({
          host: '127.0.0.1', port: tlsPort, path, method: 'GET',
          servername, ca, rejectUnauthorized: true, agent: false,
          headers: auth ? { Authorization: auth } : {},
          timeout: 4000,
        }, response => {
          let body = '';
          response.on('data', chunk => { body += chunk; });
          response.on('end', () =>
            resolve({ status: response.statusCode, body, headers: response.headers }));
        });
        req.on('timeout', () => req.destroy(new Error('TLS_STATUS_TIMEOUT')));
        req.on('error', reject);
        req.end();
      });
    }
    try {
      const trusted = read('ca.crt');
      const ok = await tlsCall(GOOD, trusted);
      assert.equal(ok.status, 200);
      assert.deepEqual(JSON.parse(ok.body), JSON.parse(raw()));
      assert.equal(ok.headers['cache-control'], 'no-store');
      assert.equal((await tlsCall(null, trusted)).status, 403);
      assert.equal((await tlsCall(BAD, trusted)).status, 403);
      assert.equal((await tlsCall(GOOD, trusted, 'brc-agent.internal', '/admin')).status, 404);
      await assert.rejects(tlsCall(GOOD, read('fake.crt')));
      await assert.rejects(tlsCall(GOOD, trusted, 'wrong.invalid'));
      console.log('H454_PRIVATE_TLS_REAL_SOCKET_PINNED_CA_SNI=PASS');
    } finally {
      await new Promise(resolve => proxy.close(resolve));
    }
  }
  console.log('H454_PRIVATE_TLS_STATUS_PROXY_SYNTHETIC_E2E=PASS');
  console.log('H454_STATUS_INVALID_REQUESTS_AND_ADMIN_ROUTES=DENIED');
  console.log('H454_ORIGINAL_HOST_OR_TOKEN_USED=NO');
} finally {
  await new Promise(resolve => backend.close(resolve));
}
