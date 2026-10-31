// Private material is passed only through the owner operator's anonymous pipes.
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const NAME = Buffer.from('ssh-ed25519');
const PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const COMMENT = 'hermes-h454-wss';
const u32 = value => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(value); return bytes; };
const field = value => { const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value); return Buffer.concat([u32(bytes.length), bytes]); };
const publicBlob = key => Buffer.concat([field(NAME), field(key)]);

function inspect(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record) ||
      Object.keys(record).sort().join(',') !== 'publicKey,seed,version' || record.version !== 1 ||
      typeof record.seed !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(record.seed) ||
      typeof record.publicKey !== 'string' || record.publicKey.length > 256) throw Error('H454_IDENTITY_FORMAT');
  const seed = Buffer.from(record.seed, 'base64url');
  if (seed.length !== 32 || seed.toString('base64url') !== record.seed) throw Error('H454_IDENTITY_FORMAT');
  const der = Buffer.concat([PREFIX, seed]);
  try {
    const key = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    const publicBytes = Buffer.from(createPublicKey(key).export({ format: 'jwk' }).x, 'base64url');
    const expected = Buffer.from(`ssh-ed25519 ${publicBlob(publicBytes).toString('base64')} ${COMMENT}`);
    const supplied = Buffer.from(record.publicKey);
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) throw Error('H454_IDENTITY_MISMATCH');
    return { seed, publicBytes, publicKey: expected.toString('ascii') };
  } catch (error) { seed.fill(0); throw error; }
  finally { der.fill(0); }
}

export function generateIdentity() {
  const key = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
  const seed = Buffer.from(key.d, 'base64url');
  try {
    const publicBytes = Buffer.from(key.x, 'base64url');
    return { version: 1, seed: seed.toString('base64url'),
      publicKey: `ssh-ed25519 ${publicBlob(publicBytes).toString('base64')} ${COMMENT}` };
  } finally { seed.fill(0); }
}

export function verifiedPublicKey(record) {
  const checked = inspect(record);
  try { return checked.publicKey; } finally { checked.seed.fill(0); }
}

export function privateKeyForAgent(record) {
  const checked = inspect(record), check = randomBytes(4);
  let material, materialField, plainBlock, privateBlock, raw, pem;
  try {
    material = Buffer.concat([checked.seed, checked.publicBytes]); materialField = field(material);
    plainBlock = Buffer.concat([check, check, field(NAME), field(checked.publicBytes), materialField, field(COMMENT)]);
    const padding = 8 - plainBlock.length % 8;
    privateBlock = Buffer.concat([plainBlock, Buffer.from(Array.from({ length: padding }, (_, i) => i + 1))]);
    raw = Buffer.concat([Buffer.from('openssh-key-v1\0'), field('none'), field('none'), field(''),
      u32(1), field(publicBlob(checked.publicBytes)), field(privateBlock)]);
    const lines = raw.toString('base64').match(/.{1,70}/g).join('\n');
    pem = Buffer.from(`-----BEGIN OPENSSH PRIVATE KEY-----\n${lines}\n-----END OPENSSH PRIVATE KEY-----\n`);
    return pem;
  } finally {
    checked.seed.fill(0);
    for (const bytes of [material, materialField, plainBlock, privateBlock, raw]) if (bytes) bytes.fill(0);
  }
}

async function readRecord() {
  const chunks = []; let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length; if (size > 4096) throw Error('H454_IDENTITY_INPUT');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

export async function run(mode, sshAddPath) {
  if (mode === 'generate' && !sshAddPath) {
    if (process.stdout.isTTY) throw Error('H454_IDENTITY_PIPE_REQUIRED');
    process.stdout.write(JSON.stringify(generateIdentity())); return;
  }
  if (mode === 'public' && !sshAddPath) {
    process.stdout.write(verifiedPublicKey(await readRecord())); return;
  }
  if (mode === 'load' && sshAddPath && process.platform === 'win32') {
    if (process.env.SSH_AUTH_SOCK) throw Error('H454_SSH_AGENT_OVERRIDE');
    const systemRoot = process.env.SystemRoot || '';
    const expected = path.win32.join(systemRoot, 'System32', 'OpenSSH', 'ssh-add.exe');
    if (!path.win32.isAbsolute(expected) || path.win32.normalize(sshAddPath).toLowerCase() !== expected.toLowerCase())
      throw Error('H454_SSH_ADD_PATH');
    const pem = privateKeyForAgent(await readRecord());
    try {
      const result = spawnSync(expected, ['-'], { input: pem, stdio: ['pipe', 'ignore', 'ignore'],
        timeout: 10000, windowsHide: true });
      if (result.status !== 0 || result.error) throw Error('H454_SSH_ADD_FAILED');
    } finally { pem.fill(0); }
    process.stdout.write('H454_IDENTITY_LOADED'); return;
  }
  throw Error('H454_IDENTITY_MODE');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length > 4) { console.error('H454_IDENTITY_HOLD'); process.exitCode = 2; }
  else run(process.argv[2], process.argv[3]).catch(() => { console.error('H454_IDENTITY_HOLD'); process.exitCode = 2; });
}
