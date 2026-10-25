// #454 functional and adversarial contracts. No MCP credentials or network.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  guardedUpdate, GuardedRefusal, MAX_BYTES
} from '../scripts/h454_guarded_sandbox_write.mjs';

const hash = x => crypto.createHash('sha256').update(x).digest('hex');
async function tempFixture(fn) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'h454-guarded-test-'));
  try { await fn(root); }
  finally { await fs.rm(root, { recursive: true, force: true }); }
}
function rejected(p, reason) {
  return assert.rejects(p, err =>
    err instanceof GuardedRefusal && err.message === reason);
}
test('create binary 128KiB from staged payload with hash and readback', () =>
  tempFixture(async root => {
    const bytes = Buffer.alloc(128 * 1024);
    for (let i = 0; i < bytes.length; i++) bytes[i] = i % 251;
    const source = path.join(root, 'payload.bin');
    const target = path.join(root, 'output.bin');
    await fs.writeFile(source, bytes);
    const result = await guardedUpdate({
      root, source, target, expected: 'absent', payloadSha256: hash(bytes)
    });
    assert.equal(result.status, 'created');
    assert.equal(result.bytes, 131072);
    assert.equal(result.new_sha256, hash(bytes));
    assert.deepEqual(await fs.readFile(target), bytes);
  })
);
test('update preserves preexisting file mode and content integrity', () =>
  tempFixture(async root => {
    const source = path.join(root, 'stage.txt');
    const target = path.join(root, 'target.txt');
    await fs.writeFile(target, 'old\n', { mode: 0o640 });
    await fs.chmod(target, 0o640);
    await fs.writeFile(source, 'new\n');
    const answer = await guardedUpdate({
      root, source, target, expected: hash(Buffer.from('old\n'))
    });
    assert.equal(answer.status, 'updated');
    assert.equal(answer.old_sha256, hash(Buffer.from('old\n')));
    assert.equal((await fs.stat(target)).mode & 0o777, 0o640);
    assert.equal(await fs.readFile(target, 'utf8'), 'new\n');
  })
);
test('stale hash rejects modification and leaves target intact', () =>
  tempFixture(async root => {
    const source = path.join(root, 'stage');
    const target = path.join(root, 'target');
    await fs.writeFile(source, 'future');
    await fs.writeFile(target, 'current');
    await rejected(guardedUpdate({
      root, source, target, expected: hash(Buffer.from('previous'))
    }), 'stale_target');
    assert.equal(await fs.readFile(target, 'utf8'), 'current');
  })
);
test('absent precondition rejects overwrite and preserves file', () =>
  tempFixture(async root => {
    const source = path.join(root, 'stage');
    const target = path.join(root, 'target');
    await fs.writeFile(source, 'future');
    await fs.writeFile(target, 'valuable');
    await rejected(guardedUpdate({ root, source, target, expected: 'absent' }),
      'stale_target');
    assert.equal(await fs.readFile(target, 'utf8'), 'valuable');
  })
);
test('payload digest mismatch does not change target', () =>
  tempFixture(async root => {
    const source = path.join(root, 'stage');
    const target = path.join(root, 'target');
    await fs.writeFile(source, 'future');
    await rejected(guardedUpdate({
      root, source, target, expected: 'absent',
      payloadSha256: hash(Buffer.from('different'))
    }), 'payload_digest_mismatch');
    await assert.rejects(fs.stat(target), { code: 'ENOENT' });
  })
);
test('symlink source, target and ancestor are all refused', () =>
  tempFixture(async root => {
    const real = path.join(root, 'real');
    const source = path.join(root, 'stage');
    await fs.mkdir(real);
    await fs.writeFile(source, 'data');
    await fs.writeFile(path.join(real, 'target'), 'preserve');
    const link = path.join(root, 'linked');
    await fs.symlink(real, link, 'dir');
    await rejected(guardedUpdate({
      root, source, target: path.join(link, 'target'),
      expected: hash(Buffer.from('preserve'))
    }), 'symlink_denied');
    const linkFile = path.join(root, 'linkfile');
    await fs.symlink(source, linkFile);
    await rejected(guardedUpdate({
      root, source: linkFile, target: path.join(root, 'output'),
      expected: 'absent'
    }), 'symlink_denied');
    await rejected(guardedUpdate({
      root, source, target: linkFile, expected: 'absent'
    }), 'symlink_denied');
    assert.equal(await fs.readFile(path.join(real, 'target'), 'utf8'),
      'preserve');
  })
);
test('hardlinked payload and target refused', () =>
  tempFixture(async root => {
    const source = path.join(root, 'source');
    const twin = path.join(root, 'twin');
    const target = path.join(root, 'target');
    await fs.writeFile(source, 'hello');
    await fs.link(source, twin);
    await rejected(guardedUpdate({
      root, source, target, expected: 'absent'
    }), 'not_unique_regular_file');
    await fs.unlink(twin);
    await fs.writeFile(target, 'current');
    await fs.link(target, twin);
    await rejected(guardedUpdate({
      root, source, target, expected: hash(Buffer.from('current'))
    }), 'not_unique_regular_file');
  })
);
test('protected components and sandbox escapes refused', () =>
  tempFixture(async root => {
    const source = path.join(root, 'source');
    await fs.writeFile(source, 'hello');
    for (const target of [
      path.join(root, '.git', 'config'),
      path.join(root, 'private-vault', 'message.md'),
      path.join(root, '.env'),
      path.join(root, 'secrets', 'token'),
    ]) await rejected(guardedUpdate({
      root, source, target, expected: 'absent'
    }), 'protected_component');
    await rejected(guardedUpdate({
      root, source, target: path.join(os.tmpdir(), 'not-the-root'),
      expected: 'absent'
    }), 'path_outside_sandbox');
  })
);
test('bounded 1MiB payload accepts exact max and rejects larger', () =>
  tempFixture(async root => {
    const source = path.join(root, 'payload');
    const target = path.join(root, 'binary');
    await fs.writeFile(source, Buffer.alloc(MAX_BYTES));
    const r = await guardedUpdate({ root, source, target, expected: 'absent' });
    assert.equal(r.bytes, MAX_BYTES);
    await fs.writeFile(source, Buffer.alloc(MAX_BYTES + 1));
    await rejected(guardedUpdate({
      root, source, target, expected: r.new_sha256
    }), 'file_too_large');
    assert.equal((await fs.stat(target)).size, MAX_BYTES);
  })
);
test('concurrent same-target updates cannot both commit', () =>
  tempFixture(async root => {
    const sourceA = path.join(root, 'source-a');
    const sourceB = path.join(root, 'source-b');
    const target = path.join(root, 'target');
    await fs.writeFile(sourceA, 'alpha');
    await fs.writeFile(sourceB, 'beta');
    await fs.writeFile(target, 'original');
    const args = { root, target, expected: hash(Buffer.from('original')) };
    const answers = await Promise.allSettled([
      guardedUpdate({ ...args, source: sourceA }),
      guardedUpdate({ ...args, source: sourceB })
    ]);
    assert.equal(answers.filter(x => x.status === 'fulfilled').length, 1);
    assert.equal(answers.filter(x => x.status === 'rejected').length, 1);
    assert.ok(['alpha', 'beta'].includes(await fs.readFile(target, 'utf8')));
  })
);
test('missing parent and self-copy rejected before source mutation', () =>
  tempFixture(async root => {
    const source = path.join(root, 'stage');
    await fs.writeFile(source, 'saved');
    await rejected(guardedUpdate({
      root, source, target: source, expected: 'absent'
    }), 'source_equals_target');
    await rejected(guardedUpdate({
      root, source, target: path.join(root, 'missing', 'target'),
      expected: 'absent'
    }), 'path_missing');
    assert.equal(await fs.readFile(source, 'utf8'), 'saved');
  })
);
test('malformed digest and directory payload rejected', () =>
  tempFixture(async root => {
    const source = path.join(root, 'stage');
    const target = path.join(root, 'target');
    await fs.mkdir(source);
    await rejected(guardedUpdate({
      root, source, target, expected: 'absent'
    }), 'not_unique_regular_file');
    await rejected(guardedUpdate({
      root, source, target, expected: '00'
    }), 'invalid_digest');
  })
);
