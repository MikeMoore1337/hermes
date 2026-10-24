/* #455: owner-only relay-local sanitized observation. No HTTP, OAuth or host grants.
 * Disabled until an owner places a secure opt-in marker in existing /state.
 * Device presence comes from LIVE DeviceHub, never old SQLite last_seen alone.
 */
import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import type { DeviceHub } from './device-hub.js';
import type { SqliteStore } from './store/sqlite.js';

export const OBSERVER_FILE = '/state/hermes-brc-observation.json';
export const OBSERVER_ENABLE_FILE = '/state/.hermes-brc-observer-enable';
const SANDBOXES = [
  'H15 Windows permanent sandbox',
  'H15 Hermes VPS sandbox',
  'H15 YFC VPS sandbox',
] as const;
const NATIVE_NAME = 'H15 Windows native read-only';
const NATIVE_ID = 'h454-win-01335a1f6e6705b4';
const WORKSPACES = [
  ['hermes', 'main'],
  ['your-fitness-coach', 'master'],
  ['second-brain', 'main'],
  ['ai-development-toolkit', 'main'],
] as const;
const DEVICE_ID = /^[A-Za-z0-9_-]{8,128}$/;

function strictParent(directory: string): void {
  const info = fs.lstatSync(directory);
  if (!info.isDirectory() || info.isSymbolicLink() ||
      info.uid !== process.getuid?.() || (info.mode & 0o022) !== 0) {
    throw Error('observer_parent_untrusted');
  }
}
export function observerEnabled(file = OBSERVER_ENABLE_FILE): boolean {
  try {
    if (file !== OBSERVER_ENABLE_FILE) return false;
    strictParent('/state');
    const info = fs.lstatSync(file);
    return info.isFile() && !info.isSymbolicLink() &&
      info.uid === process.getuid?.() && (info.mode & 0o077) === 0 &&
      info.size === 8 && fs.readFileSync(file, 'utf8') === 'enabled\n';
  } catch {
    return false;
  }
}

/** Pure, bounded projection: never include raw owner ID, device ID or token. */
export function sanitizedLiveObservation(
  hub: DeviceHub, store: SqliteStore, userId: string, now = Date.now(),
) {
  if (!Number.isSafeInteger(now) || now < 1_600_000_000_000) throw Error('invalid_clock');
  const rows = store.listDevices(userId);
  if (rows.length < 3 || rows.length > 4) throw Error('unexpected_devices');
  const live = new Map(hub.list(userId).map(d => [d.deviceId, d]));
  const names = new Set<string>();
  const ids = new Set<string>();
  const byName = new Map<string, typeof rows[number]>();
  for (const row of rows) {
    if (!DEVICE_ID.test(row.device_id) || names.has(row.name) || ids.has(row.device_id) ||
        row.user_id !== userId || (row.paused !== 0 && row.paused !== 1)) {
      throw Error('invalid_device_identity');
    }
    if (row.name === NATIVE_NAME) {
      if (row.device_id !== NATIVE_ID || row.platform !== 'win32') throw Error('invalid_native_identity');
    } else if (!SANDBOXES.includes(row.name as typeof SANDBOXES[number]) ||
               row.platform !== 'linux/docker') {
      throw Error('unapproved_device');
    }
    names.add(row.name); ids.add(row.device_id); byName.set(row.name, row);
  }
  if (SANDBOXES.some(name => !byName.has(name)) ||
      (rows.length === 4 && !byName.has(NATIVE_NAME))) throw Error('missing_sandbox');

  const devices = SANDBOXES.map(name => {
    const row = byName.get(name)!;
    const connected = live.get(row.device_id);
    if (connected && (connected.name !== name || connected.platform !== 'linux/docker'))
      throw Error('forged_hello');
    const last = connected?.lastSeen ?? row.last_seen ?? 0;
    const age = Math.min(86400, Math.max(0, Math.floor((now - last) / 1000)));
    const state = row.paused ? 'paused' : !connected ? 'offline' :
      age > 300 ? 'stale' : 'online';
    return { name, status: state, last_seen_age_seconds: age,
      command_execution: 'not_verified' };
  });
  const healthy = devices.filter(d => d.status === 'online').length;
  const state = healthy === 3 ? 'online' : healthy > 0 ? 'partial' : 'unavailable';
  const ready = devices[0].status === 'online';
  const workspaces = WORKSPACES.map(([name, branch]) => ({
    name, root: '/workspace/projects/' + name, branch,
    git_verified: false,
    state: ready ? 'reachable_not_git_verified' : 'not_ready',
  }));
  return { schema: 1, source: 'hermes_brc_mcp',
    observed_at: new Date(now).toISOString(), status: state,
    execution_verified: false, native_host_access: false, onboarding_enabled: false,
    devices, workspaces };
}

/** Atomic replacement in the already present, relay-owned /state bind mount. */
export function publishLiveObservation(
  hub: DeviceHub, store: SqliteStore, ownerId: string, now = Date.now(),
): void {
  if (process.getuid?.() === 0) throw Error('root_observer_forbidden');
  strictParent('/state');
  const snapshot = sanitizedLiveObservation(hub, store, ownerId, now);
  const payload = Buffer.from(JSON.stringify(snapshot) + '\n', 'utf8');
  if (payload.length > 16384) throw Error('observer_oversize');
  try {
    const current = fs.lstatSync(OBSERVER_FILE);
    if (!current.isFile() || current.isSymbolicLink() ||
        current.uid !== process.getuid?.() || (current.mode & 0o022)) {
      throw Error('observer_target_untrusted');
    }
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
  }
  const temp = '/state/.hermes-brc-observation-' + randomUUID();
  let created = false;
  try {
    const fd = fs.openSync(temp, fs.constants.O_WRONLY | fs.constants.O_CREAT |
      fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o640);
    created = true;
    try {
      fs.writeFileSync(fd, payload);
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    // The relay is the sole authorized writer in its private owner UID volume.
    fs.renameSync(temp, OBSERVER_FILE);
    created = false;
    const dirfd = fs.openSync('/state', fs.constants.O_RDONLY);
    try { fs.fsyncSync(dirfd); } finally { fs.closeSync(dirfd); }
  } finally {
    if (created) { try { fs.unlinkSync(temp); } catch { /* bounded cleanup */ } }
  }
}
