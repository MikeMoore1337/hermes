// Synthetic credentials and relay only; run inside the disposable candidate image.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

const fixture = process.argv[2];
assert.ok(fixture, 'fixture directory required');
const root = fs.realpathSync(os.tmpdir());
const temp = fs.mkdtempSync(path.join(root, 'h454-combined-'));
const identity = fs.lstatSync(temp);
const workspace = path.join(temp, 'workspace');
fs.mkdirSync(workspace);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(condition) {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) { if (condition()) return; await delay(100); }
  throw Error('H454_COMBINED_TIMEOUT');
}
async function stop(child) {
  if (!child.pid || child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGTERM');
  await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(3000)]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill('SIGKILL'); await until(() => child.exitCode !== null || child.signalCode !== null);
  }
}
function start(home, extra = []) {
  const child = spawn(process.execPath, ['/app/dist/cli.js', '--allow-dir', workspace, '--no-browser', ...extra],
    { env: { PATH: process.env.PATH, HOME: temp, BRC_HOME: home }, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '', error = null, closed = false;
  child.once('error', value => { error = value; });
  child.once('close', () => { closed = true; });
  for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { output = (output + chunk).slice(-8192); });
  return { child, output: () => output, error: () => error, closed: () => closed };
}

let connections = 0, requests = 0, upgrades = 0;
const server = https.createServer({ key: fs.readFileSync(path.join(fixture, 'trusted.key')),
  cert: fs.readFileSync(path.join(fixture, 'trusted.crt')) }, (req, res) => {
  requests++; req.resume(); res.writeHead(400); res.end();
});
server.on('tlsClientError', () => {});
server.on('connection', () => { connections++; });
server.on('upgrade', (_req, socket) => {
  upgrades++; socket.end('HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
});
try {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(38184, '127.0.0.1', resolve); });
  const missing = path.join(temp, 'missing'); fs.mkdirSync(missing);
  const first = start(missing, ['--relay', 'http://host.docker.internal:38184', '--device-id', 'synthetic-device']);
  try {
    await until(() => first.closed() || first.error() || connections > 0);
    if (connections > 0) throw Error('H454_MISSING_CREDENTIAL_PAIRING_REGRESSION');
    assert.equal(first.error(), null);
    assert.equal(first.child.exitCode, 2);
    assert.match(first.output(), /Existing credentials required; automatic pairing disabled\./);
    assert.equal(requests, 0); assert.equal(upgrades, 0);
  } finally { await stop(first.child); }

  const home = path.join(temp, 'denied'); fs.mkdirSync(home);
  const credential = JSON.stringify({ relayUrl: 'https://host.docker.internal:38184', deviceId: 'synthetic-device',
    deviceToken: 'brc_dev_' + 'a'.repeat(43), name: 'fixture', pairedAt: '2026-01-01T00:00:00Z' });
  const device = path.join(home, 'device.json'); fs.writeFileSync(device, credential, { mode: 0o600 });
  const second = start(home);
  try {
    await until(() => upgrades > 0 || second.error());
    assert.equal(second.error(), null);
    await until(() => second.output().includes('Device authorization refused; staged credentials retained.'));
    await delay(1200);
    assert.equal(upgrades, 1); assert.equal(requests, 0);
    assert.equal(fs.readFileSync(device, 'utf8'), credential);
  } finally { await stop(second.child); }
  console.log('H454_COMBINED_WSS_NO_AUTO_PAIR=PASS');
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  const now = fs.lstatSync(temp);
  assert.equal(fs.realpathSync(path.dirname(temp)), root);
  assert.ok(!now.isSymbolicLink() && now.dev === identity.dev && now.ino === identity.ino);
  fs.rmSync(temp, { recursive: true, force: true });
}
