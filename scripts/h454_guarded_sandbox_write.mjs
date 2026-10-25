#!/usr/bin/env node
/**
 * #454: bounded compare-and-swap for EXISTING Hermes BRC sandbox files.
 * No MCP relay changes, host mounts, network, commands or new privileges.
 * Co-operating updates serialize per target. Other writers MUST NOT bypass
 * this helper if optimistic concurrency guarantees are required.
 */
import * as fs from 'node:fs/promises';
import * as constants from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const MAX_BYTES = 1024 * 1024;
const HEX = /^[a-f0-9]{64}$/;
const DENIED = new Set([
  '.git', '.ssh', '.aws', '.gnupg', '.secrets', 'secrets',
  'private-vault', '.vault', '.terraform', 'node_modules'
]);
const sha = buffer => crypto.createHash('sha256').update(buffer).digest('hex');

export class GuardedRefusal extends Error {
  constructor(reason) { super(reason); this.name = 'GuardedRefusal'; }
}
function refuse(reason) { throw new GuardedRefusal(reason); }
function isIn(root, child) {
  return child !== root && child.startsWith(root + path.sep);
}
async function noSymlinkComponents(root, name, { allowMissingLeaf = false } = {}) {
  // Only operate in an already authorised sandbox root. Parent components
  // and the optional target leaf must be real, non-reparse filesystem nodes.
  if (typeof name !== 'string' || name.length > 1024 ||
      !path.isAbsolute(name) || path.normalize(name) !== name ||
      !isIn(root, name)) refuse('path_outside_sandbox');
  const parts = path.relative(root, name).split(path.sep);
  if (parts.some(p => p === '..' || p === '.' || p === '' ||
        DENIED.has(p.toLowerCase()) || p.toLowerCase().startsWith('.env') ||
        p.includes('\0'))) refuse('protected_component');
  let cursor = root;
  for (let i = 0; i < parts.length; i++) {
    cursor = path.join(cursor, parts[i]);
    let st;
    try { st = await fs.lstat(cursor); }
    catch (err) {
      if (err.code === 'ENOENT' && allowMissingLeaf && i === parts.length - 1) return;
      refuse('path_missing');
    }
    if (st.isSymbolicLink()) refuse('symlink_denied');
    if (i < parts.length - 1 && !st.isDirectory()) refuse('parent_not_directory');
  }
}
async function regularData(file) {
  let h;
  try {
    h = await fs.open(file, constants.constants.O_RDONLY | constants.constants.O_NOFOLLOW);
    const before = await h.stat();
    if (!before.isFile() || before.nlink !== 1) refuse('not_unique_regular_file');
    if (before.size > MAX_BYTES) refuse('file_too_large');
    const body = await h.readFile();
    const after = await h.stat();
    if (body.length !== before.size ||
        before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs ||
        before.ctimeMs !== after.ctimeMs) refuse('file_changed_during_read');
    return { body, digest: sha(body), mode: before.mode & 0o777 };
  } catch (err) {
    if (err instanceof GuardedRefusal) throw err;
    if (err.code === 'ENOENT') return null;
    refuse('file_read_denied');
  } finally { if (h) await h.close(); }
}
async function secureRoot(root) {
  if (typeof root !== 'string' || !path.isAbsolute(root)) refuse('invalid_root');
  if (path.normalize(root) !== root) refuse('invalid_root');
  const st = await fs.lstat(root).catch(() => null);
  if (!st?.isDirectory() || st.isSymbolicLink() ||
      await fs.realpath(root) !== root) refuse('unsafe_root');
}
async function acquireLock(root, target) {
  // OS-native /tmp filesystem: reliable Unix permissions even when
  // /workspace is a Windows NTFS-backed bind mount.
  const base = path.join(os.tmpdir(), 'hermes-h454-guarded-locks-' + process.getuid());
  await fs.mkdir(base, { recursive: true, mode: 0o700 });
  const st = await fs.lstat(base);
  if (!st.isDirectory() || st.isSymbolicLink() ||
      st.uid !== process.getuid() || (st.mode & 0o077) !== 0)
    refuse('unsafe_lock_directory');
  const key = sha(Buffer.from(root + '\0' + target, 'utf8'));
  const file = path.join(base, key + '.lock');
  try { await fs.mkdir(file, { mode: 0o700 }); }
  catch (err) {
    if (err.code === 'EEXIST') refuse('target_locked');
    refuse('lock_creation_denied');
  }
  return async () => {
    try { await fs.rmdir(file); }
    catch { /* preserve fail-closed lock if tampered with */ }
  };
}
async function state(root, target) {
  await noSymlinkComponents(root, target, { allowMissingLeaf: true });
  return regularData(target);
}
export async function guardedUpdate({
  root = '/workspace', source, target, expected, payloadSha256
}) {
  if (typeof expected !== 'string' ||
      (expected !== 'absent' && !HEX.test(expected)) ||
      (payloadSha256 !== undefined && !HEX.test(payloadSha256)))
    refuse('invalid_digest');
  await secureRoot(root);
  if (source === target) refuse('source_equals_target');
  await noSymlinkComponents(root, source);
  await noSymlinkComponents(root, target, { allowMissingLeaf: true });
  const payload = await regularData(source);
  if (!payload) refuse('source_missing');
  if (payloadSha256 !== undefined && payload.digest !== payloadSha256)
    refuse('payload_digest_mismatch');
  const release = await acquireLock(root, target);
  let temp = null;
  try {
    const before = await state(root, target);
    if ((expected === 'absent' && before !== null) ||
        (expected !== 'absent' && (!before || before.digest !== expected)))
      refuse('stale_target');
    const parent = path.dirname(target);
    const name = '.' + path.basename(target) + '.hermes-' +
      crypto.randomBytes(12).toString('hex') + '.tmp';
    temp = path.join(parent, name);
    const h = await fs.open(temp, 'wx', before?.mode ?? 0o600);
    try {
      await h.writeFile(payload.body);
      await h.sync();
      if (before) await h.chmod(before.mode);
    } finally { await h.close(); }
    // Detect edits by non-cooperating writers as close as possible to
    // replacement. POSIX does not offer portable atomic rename-if-hash.
    const latest = await state(root, target);
    if ((before === null && latest !== null) ||
        (before !== null && (!latest || latest.digest !== before.digest)))
      refuse('target_changed_during_update');
    await noSymlinkComponents(root, parent);
    await fs.rename(temp, target);
    temp = null;
    return {
      schema: 1, status: before ? 'updated' : 'created',
      scope: 'sandbox', target, old_sha256: before?.digest ?? null,
      new_sha256: payload.digest, bytes: payload.body.length,
      compare_and_swap: true, external_writer_atomicity: 'not_guaranteed'
    };
  } finally {
    if (temp) await fs.unlink(temp).catch(() => {});
    await release();
  }
}
function parseArgs(argv) {
  const obj = {};
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i], value = argv[i + 1];
    if (!['--source', '--target', '--expect', '--payload-sha'].includes(name) ||
        value === undefined || Object.hasOwn(obj, name)) refuse('invalid_arguments');
    obj[name] = value;
  }
  if (Object.keys(obj).length < 3 || Object.keys(obj).length > 4 ||
      !obj['--source'] || !obj['--target'] || !obj['--expect'])
    refuse('invalid_arguments');
  return {
    source: obj['--source'], target: obj['--target'],
    expected: obj['--expect'], payloadSha256: obj['--payload-sha']
  };
}
async function main() {
  try {
    const result = await guardedUpdate(parseArgs(process.argv.slice(2)));
    console.log(JSON.stringify(result));
  } catch (err) {
    console.log(JSON.stringify({
      schema: 1, status: 'refused',
      reason: err instanceof GuardedRefusal ? err.message : 'internal_error'
    }));
    process.exitCode = 2;
  }
}
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]))
  await main();
