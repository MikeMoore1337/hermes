#!/usr/bin/env node
/**
 * H454: real compiled BRC SqliteStore startup/rotation regression, CI only.
 *
 * Uses synthetic credentials and a disposable private SQLite directory. Never
 * opens an owner relay database or prints credential/hash/salt material.
 * Runs against packages/relay/dist/store/sqlite.js built from the pinned tree.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const root = process.argv[2];
if (!root || !path.isAbsolute(root)) {
  throw Error('H454_PINNED_COMPILED_RELAY_ROOT_REQUIRED');
}
const source = path.join(root, 'packages/relay/dist/store/sqlite.js');
const { SqliteStore, verifyPassword } = await import(pathToFileURL(source).href);
const directory = mkdtempSync(path.join(tmpdir(), 'h454-admin-hash-ci-'));
const database = path.join(directory, 'relay.sqlite');
const username = 'synthetic-h454-admin';
const originalPassword = 'synthetic-admin-password-one-only-for-CI';
const rotatedPassword = 'synthetic-admin-password-two-only-for-CI';

try {
  let first;
  let originalId;
  const store = new SqliteStore(database);
  try {
    const created = store.upsertUser(username, originalPassword);
    first = created.password_hash;
    originalId = created.id;
    assert.match(first, /^[0-9a-f]{32}:[0-9a-f]{128}$/);
    assert.equal(verifyPassword(originalPassword, first), true);

    // Repeated startup with unchanged credentials cannot re-salt stored state.
    const reused = store.upsertUser(username, originalPassword);
    assert.equal(reused.id, originalId);
    assert.equal(reused.password_hash, first);
    assert.equal(store.getUserByName(username).password_hash, first);
  } finally {
    store.db.close();
  }

  // Actual disk reopen, not merely a second method call on one connection.
  const restarted = new SqliteStore(database);
  try {
    const preRestart = restarted.getUserByName(username);
    assert.equal(preRestart.password_hash, first);
    const reused = restarted.upsertUser(username, originalPassword);
    assert.equal(reused.password_hash, first);
    assert.equal(reused.id, originalId);

    // An explicit changed password continues to rotate the credential.
    const changed = restarted.upsertUser(username, rotatedPassword);
    assert.equal(changed.id, originalId);
    assert.notEqual(changed.password_hash, first);
    assert.equal(verifyPassword(rotatedPassword, changed.password_hash), true);
    assert.equal(verifyPassword(originalPassword, changed.password_hash), false);
  } finally {
    restarted.db.close();
  }

  const restartedAgain = new SqliteStore(database);
  try {
    const last = restartedAgain.getUserByName(username);
    assert.equal(last.id, originalId);
    const sameRotated = restartedAgain.upsertUser(username, rotatedPassword);
    assert.equal(sameRotated.password_hash, last.password_hash);
  } finally {
    restartedAgain.db.close();
  }

  console.log('H454_COMPILED_BRC_ADMIN_SAME_PASSWORD_HASH_STABLE=PASS');
  console.log('H454_COMPILED_BRC_ADMIN_PASSWORD_ROTATION=PASS');
  console.log('H454_COMPILED_BRC_RESTART_DISK_REOPEN=PASS');
  console.log('H454_OWNER_CREDENTIALS_READ=NO');
} finally {
  rmSync(directory, { recursive: true, force: true });
}
