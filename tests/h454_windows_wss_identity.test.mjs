import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { generateIdentity, privateKeyForAgent, verifiedPublicKey } from '../scripts/h454_windows_wss_identity.mjs';

const modulePath = fileURLToPath(new URL('../scripts/h454_windows_wss_identity.mjs', import.meta.url));

test('the PowerShell operator pins the exact identity module it loads', () => {
  const source = readFileSync(new URL('../scripts/h454_windows_wss_identity.ps1', import.meta.url), 'utf8');
  const pin = source.match(/\$script:h454ModuleHash = '([A-F0-9]{64})'/);
  assert.ok(pin);
  assert.equal(createHash('sha256').update(readFileSync(modulePath)).digest('hex').toUpperCase(), pin[1]);
});

test('a synthetic identity round-trips without exposing the seed in the public key', () => {
  const identity = generateIdentity();
  assert.match(identity.seed, /^[A-Za-z0-9_-]{43}$/);
  assert.match(identity.publicKey, /^ssh-ed25519 [A-Za-z0-9+/]{68} hermes-h454-wss$/);
  assert.equal(verifiedPublicKey(identity), identity.publicKey);
  assert.ok(!identity.publicKey.includes(identity.seed));
  const pem = privateKeyForAgent(identity);
  try { assert.match(pem.toString('ascii'), /^-----BEGIN OPENSSH PRIVATE KEY-----\n/); }
  finally { pem.fill(0); }
});

test('altered or ambiguous identity records are refused', () => {
  const value = generateIdentity();
  for (const altered of [
    { ...value, seed: generateIdentity().seed },
    { ...value, publicKey: generateIdentity().publicKey },
    { ...value, seed: value.seed + '=' },
    { ...value, version: '1' },
    { ...value, unexpected: true },
    { ...value, publicKey: 'x'.repeat(1000) },
  ]) {
    assert.throws(() => verifiedPublicKey(altered));
    assert.throws(() => privateKeyForAgent(altered));
  }
});

test('the public-only pipe returns no private seed and rejects oversized input', () => {
  const identity = generateIdentity();
  const valid = spawnSync(process.execPath, [modulePath, 'public'], { input: JSON.stringify(identity), encoding: 'utf8' });
  assert.equal(valid.status, 0);
  assert.equal(valid.stdout, identity.publicKey);
  assert.ok(!valid.stdout.includes(identity.seed));
  const withBom = spawnSync(process.execPath, [modulePath, 'public'], {
    input: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(identity))]), encoding: 'utf8',
  });
  assert.equal(withBom.status, 0);
  assert.equal(withBom.stdout, identity.publicKey);
  const duplicateBom = spawnSync(process.execPath, [modulePath, 'public'], {
    input: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(identity))]), encoding: 'utf8',
  });
  assert.equal(duplicateBom.status, 2);
  assert.equal(duplicateBom.stdout, '');
  const large = spawnSync(process.execPath, [modulePath, 'public'], { input: 'x'.repeat(4097), encoding: 'utf8' });
  assert.equal(large.status, 2);
  assert.equal(large.stdout, '');
  assert.match(large.stderr, /H454_IDENTITY_HOLD/);
});

if (process.platform !== 'win32') {
  test('OpenSSH derives the same public key from a synthetic private key', () => {
    const identity = generateIdentity(), pem = privateKeyForAgent(identity);
    const directory = mkdtempSync(join(tmpdir(), 'h454-test-key-')), keyFile = join(directory, 'key');
    try {
      writeFileSync(keyFile, pem, { flag: 'wx', mode: 0o600 });
      const result = spawnSync('ssh-keygen', ['-y', '-f', keyFile], { encoding: 'utf8', timeout: 10000 });
      assert.equal(result.status, 0, 'ssh-keygen rejected synthetic key');
      assert.equal(result.stdout.trim().split(/\s+/).slice(0, 2).join(' '), identity.publicKey.split(' ').slice(0, 2).join(' '));
    } finally {
      pem.fill(0);
      try { unlinkSync(keyFile); } catch (error) { if (error.code !== 'ENOENT') throw error; }
      rmdirSync(directory);
    }
  });
}
