// Exercise only a generated local candidate with synthetic requests and IDs.
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import http from 'node:http';
import { pathToFileURL } from 'node:url';

const { nativeStatusResponse } = await import(pathToFileURL(process.argv[2]).href);
const token = 'Bearer brc_dev_' + 'a'.repeat(64);
let identity = 'h454-win-personal-' + 'b'.repeat(32);
let active = true;
let forwarded = 0;
const backend = http.createServer((req, res) => {
  forwarded++;
  assert.equal(req.url, '/device/native-status');
  assert.equal(req.headers.authorization, token);
  res.writeHead(200, {'Content-Type': 'application/json'});
  res.end(JSON.stringify({schema:'h454-native-device-status-v1', device_id:identity,
                          active, owner_bound:true}));
});
await new Promise(resolve => backend.listen(0, '127.0.0.1', resolve));
class Response extends EventEmitter {
  constructor() { super(); this.destroyed = false; this.status = 0; this.body = ''; }
  writeHead(status) { this.status = status; }
  end(body = '') { this.body = body; this.emit('close'); }
}
function probe(url = '/device/native-status') {
  const res = new Response();
  const req = {url, method:'GET', httpVersion:'1.1', rawHeaders:['Authorization', token],
    headers:{authorization:token}, socket:{remoteAddress:'127.0.0.1'}};
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('STATUS_TIMEOUT')), 6000);
    res.once('close', () => { clearTimeout(timeout); resolve(res); });
    nativeStatusResponse(req, res, backend.address().port, '127.0.0.1');
  });
}
try {
  let response = await probe();
  assert.equal(response.status, 200);
  assert.equal(JSON.parse(response.body).device_id, identity);
  identity = 'h454-win-native-' + 'c'.repeat(32);
  assert.equal((await probe()).status, 200);
  identity = 'h454-linux-yfc-' + 'd'.repeat(32);
  assert.equal((await probe()).status, 200);
  identity = 'h454-win-personal-' + 'x'.repeat(32);
  assert.equal((await probe()).status, 502);
  identity = 'h454-win-personal-' + 'b'.repeat(32);
  active = false;
  assert.equal((await probe()).status, 502);
  assert.equal((await probe('/device/start')).status, 404);
  assert.equal(forwarded, 5);
  console.log('PERSONAL_STATUS_AND_LEGACY_IDENTITIES=PASS');
  console.log('INVALID_OR_INACTIVE_STATUS_AND_ENROLLMENT_ROUTE=DENIED');
} finally {
  await new Promise(resolve => backend.close(resolve));
}
