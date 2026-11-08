// Synthetic-only compiled BRC startup regression. No live database or credentials.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [appPath, storePath] = process.argv.slice(2);
if (!appPath || !storePath) throw Error('H454_HASH_FIXTURE_ARGS');
const { buildRelay } = await import(pathToFileURL(path.resolve(appPath)).href);
const { verifyPassword } = await import(pathToFileURL(path.resolve(storePath)).href);
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'h454-admin-hash-fixture-'));
const database = path.join(root, 'relay.sqlite');
const username = 'fixture-admin';
const originalPassword = 'synthetic-initial-password-not-live';
const rotatedPassword = 'synthetic-rotated-password-not-live';

async function boot(password) {
  const relay = buildRelay({
    port: 0,
    host: '127.0.0.1',
    publicUrl: 'http://127.0.0.1',
    trustProxy: false,
    dbFile: database,
    sessionSecret: 'synthetic-session-key-not-live-0123456789abcdef',
    adminUser: username,
    adminPassword: password,
    relayVersion: 'fixture',
  }, () => {});
  try {
    await new Promise((resolve, reject) => {
      relay.http.once('error', reject);
      relay.http.listen(0, '127.0.0.1', resolve);
    });
    const row = relay.store.getUserByName(username);
    assert.ok(row, 'admin user was not created');
    return { id: row.id, hash: row.password_hash };
  } finally {
    await relay.close();
  }
}

try {
  const first = await boot(originalPassword);
  const second = await boot(originalPassword);
  assert.equal(second.id, first.id, 'admin identity changed on restart');
  assert.equal(second.hash, first.hash, 'same password rehashed on restart');
  assert.ok(verifyPassword(originalPassword, second.hash), 'persisted password refused');
  console.log('H454_ADMIN_HASH_SAME_PASSWORD_RESTART=PASS');

  const third = await boot(rotatedPassword);
  assert.equal(third.id, first.id, 'password rotation replaced user identity');
  assert.notEqual(third.hash, first.hash, 'password rotation was silently ignored');
  assert.ok(verifyPassword(rotatedPassword, third.hash), 'new password refused');
  assert.equal(verifyPassword(originalPassword, third.hash), false,
    'old password remained valid after authorized rotation');
  const fourth = await boot(rotatedPassword);
  assert.equal(fourth.hash, third.hash, 'rotated password was rehashed on next restart');
  console.log('H454_ADMIN_HASH_PASSWORD_ROTATION_NOT_BYPASSED=PASS');
  console.log('REAL_PRODUCTION_SQLITE_USED=FALSE');
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
