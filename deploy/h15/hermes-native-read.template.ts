/* H15 #454: owner-scoped ORIGINAL Windows read-only MCP relay candidate.
 * Offline patch only. Never auto-register/enable an owner PC or its D:\ roots.
 * Agent hello is not OS proof. The paired-device token, OS ACL and native
 * Win32 handle validation must all pass separately before live activation.
 */
import { createHash } from 'node:crypto';
import type { DeviceHub } from '../device-hub.js';
import type { SqliteStore } from '../store/sqlite.js';
import type { InvokeContext } from './invoke.js';

const DEVICE_NAME = 'H15 Windows native read-only';
const NAMES = ['native_file_stat', 'native_file_read'] as const;
const PROJECTS = ['hermes', 'your-fitness-coach', 'second-brain', 'ai-development-toolkit'];
const DENY = { content: [{ type: 'text' as const,
  text: '{"status":"refused","reason":"native_read_unavailable"}' }], isError: true };
const ID = /^[A-Za-z0-9_-]{8,128}$/;
const EXT = /\.(?:py|js|jsx|ts|tsx|mjs|cjs|md|mdx|txt|json|toml|yaml|yml|html|css|scss|sql|sh|ps1|go|rs|c|h|cpp|cs|xml)$/i;

export const NATIVE_TOOLS = NAMES.map(name => ({
  name,
  description: name === 'native_file_stat'
    ? 'Read metadata of one owner-approved ORIGINAL Windows project file. No directory listing, writes or shell.'
    : 'Read one allowed ORIGINAL Windows project source file (max 256KiB). Requires separately approved native host agent.',
  inputSchema: { type: 'object', properties: {
    project: { type: 'string', enum: PROJECTS },
    relative: { type: 'string', minLength: name === 'native_file_read' ? 1 : 0,
      maxLength: 1024 },
  }, required: ['project', 'relative'], additionalProperties: false },
  annotations: { title: name, readOnlyHint: true, destructiveHint: false, openWorldHint: false },
}));

function allowedArgs(input: unknown, read: boolean): input is {project: string; relative: string} {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return false;
  const a = input as Record<string, unknown>;
  if (Object.keys(a).sort().join(',') !== 'project,relative' || typeof a.project !== 'string'
      || typeof a.relative !== 'string' || !PROJECTS.includes(a.project)
      || a.relative.length > 1024 || (read && !a.relative)) return false;
  const path = a.relative;
  if (!path && !read) return true; // stat of project root, never a directory listing
  if (path.startsWith('\\') || path.includes('/') || path.includes('\0')
      || [...path].some(c => c.charCodeAt(0) < 32)) return false;
  const parts = path.split('\\');
  if (parts.some(p => !p || p === '.' || p === '..' || p.endsWith(' ')
      || p.endsWith('.') || p.includes(':')
      || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i.test(p)
      || ['.git', '.hg', '.svn', '.ssh', '.aws', '.gnupg', '.vault',
          'vault', 'private-vault', 'secrets', '.secrets', 'node_modules',
          '__pycache__', '.terraform', '.next', '.cache'].includes(p.toLowerCase())
      || p.toLowerCase() === '.env' || p.toLowerCase().startsWith('.env.'))) return false;
  if (/(?:\.pem|\.key|\.pfx|\.p12|\.kdbx|\.sqlite3?|\.db)$/i.test(path)
      || /^(?:id_rsa|id_ed25519|credentials|config\.local)$/i.test(parts[parts.length - 1])) return false;
  return !read || EXT.test(path);
}

function eligibleDevice(hub: DeviceHub, store: SqliteStore, owner: string) {
  const devices = store.listDevices(owner).filter(d => d.name === DEVICE_NAME);
  if (devices.length !== 1) return null;
  const row = devices[0];
  if (row.paused || row.platform !== 'win32' || !ID.test(row.device_id)) return null;
  const online = hub.get(row.device_id);
  if (!online || online.ownerId !== owner || online.info.platform !== 'win32'
      || online.info.name !== DEVICE_NAME || online.info.deviceId !== row.device_id
      || online.tools.length !== 2
      || NAMES.some(n => !online.tools.some(t => t.name === n))
      || online.tools.some(t => !NAMES.includes(t.name as typeof NAMES[number]))) return null;
  return online.info.deviceId;
}
function validatedResult(value: unknown, a: {project: string; relative: string},
                         operation: 'read' | 'stat') {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const r = value as Record<string, unknown>;
  const base = ['status','project','relative','action','kind','size_bytes'];
  const permitted = operation === 'read' ? [...base,'encoding','sha256','data'] : base;
  if (Object.keys(r).sort().join(',') !== permitted.sort().join(',')
      || r.status !== 'ok' || r.project !== a.project || r.relative !== a.relative
      || r.action !== operation || !['file','directory'].includes(r.kind as string)) return null;
  if (r.kind === 'directory') return operation === 'stat' && r.size_bytes === null ? r : null;
  if (!Number.isSafeInteger(r.size_bytes) || (r.size_bytes as number) < 0) return null;
  if (operation === 'stat') return r;
  if ((r.size_bytes as number) > 262144 || r.encoding !== 'base64'
      || typeof r.data !== 'string' || r.data.length > 349528
      || !/^[A-Za-z0-9+/]*={0,2}$/.test(r.data) || r.data.length % 4 !== 0
      || typeof r.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(r.sha256)) return null;
  const buf = Buffer.from(r.data, 'base64');
  if (buf.length !== r.size_bytes || buf.toString('base64') !== r.data
      || createHash('sha256').update(buf).digest('hex') !== r.sha256) return null;
  return r;
}
export async function invokeOwnerNativeRead(
    hub: DeviceHub, store: SqliteStore, ctx: InvokeContext,
    name: string, args: unknown) {
  const read = name === 'native_file_read';
  if (!NAMES.includes(name as typeof NAMES[number]) || !allowedArgs(args, read))
    return DENY;
  const deviceId = eligibleDevice(hub, store, ctx.userId);
  if (!deviceId) return DENY;
  const started = Date.now();
  const safeArgs = { project: args.project, relative: args.relative };
  const argsHash = createHash('sha256').update(JSON.stringify(safeArgs)).digest('hex').slice(0,16);
  let safe = null;
  try {
    const response = await hub.call(deviceId, name, safeArgs, {
      client: { name: ctx.clientId }, timeoutMs: 8000,
    });
    if (!response.isError && response.content.length === 1
        && response.content[0]?.type === 'text'
        && typeof response.content[0].text === 'string'
        && response.content[0].text.length < 370000) {
      const raw = JSON.parse(response.content[0].text);
      safe = validatedResult(raw, safeArgs, read ? 'read' : 'stat');
    }
  } catch { /* Never forward agent error, filepath, output, or credentials. */ }
  try {
    store.audit({ ts: started, user_id: ctx.userId, device_id: deviceId,
      client: ctx.clientId, tool: name, args_hash: argsHash,
      ok: safe ? 1 : 0, ms: Date.now() - started,
      error: safe ? null : 'NATIVE_READ_DENIED' });
  } catch {
    // No audit trail => no sensitive original-host data leaves this relay.
    return DENY;
  }
  return safe ? { content: [{ type: 'text' as const, text: JSON.stringify(safe) }],
    isError: false } : DENY;
}
