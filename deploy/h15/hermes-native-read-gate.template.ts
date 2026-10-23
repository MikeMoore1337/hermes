/* Hermes #454: immutable, OPTIONAL native Windows original-file read gate.
 * Loaded only in pinned-owner BRC relay. No native channel without separately
 * configured owner-paired device ID. Never trust self-reported capabilities
 * alone; pair this with owner-bound device token and OS read-only identity.
 */
declare const process: { env: Record<string, string | undefined> };
const EXPECTED_NAME = 'H15 Windows native read-only';
const ID = /^[A-Za-z0-9_-]{8,128}$/;
const PROJECTS = new Set(['hermes', 'your-fitness-coach', 'second-brain',
                          'ai-development-toolkit']);
const METHODS = new Set(['native_file_stat', 'native_file_read']);
const DENIED = new Set(['.git', 'vault', '.vault', 'private-vault', '.ssh',
                        'secrets', '.secrets', 'credentials', 'node_modules']);
const VALID_SUFFIX = /\.(?:py|js|jsx|ts|tsx|mjs|cjs|md|mdx|txt|json|toml|yaml|yml|html|css|scss|sql|sh|ps1|go|rs|c|h|cpp|cs|xml)$/i;

export function isNativeOriginalReadTool(name: string): boolean {
  return METHODS.has(name);
}
export function nativeDeviceId(): string | null {
  const value = process.env.HERMES_NATIVE_READ_DEVICE_ID ?? '';
  return ID.test(value) ? value : null;
}
export function isNativeOriginalReadRequest(
  tool: string, args: Record<string, unknown>): boolean {
  if (!METHODS.has(tool) || !args || typeof args !== 'object'
      || Object.keys(args).length !== 2
      || !Object.keys(args).every(k => k === 'project' || k === 'relative')) return false;
  const project = args.project, relative = args.relative;
  if (typeof project !== 'string' || !PROJECTS.has(project)
      || typeof relative !== 'string' || relative.length > 1024) return false;
  if (tool === 'native_file_read' && !relative) return false;
  if (!relative) return tool === 'native_file_stat';
  if (relative.startsWith('\\') || relative.includes('/') ||
      relative.includes('\0') || /[\x00-\x1f]/.test(relative)) return false;
  const components = relative.split('\\');
  if (components.some(c => !c || c === '.' || c === '..' ||
      c.endsWith(' ') || c.endsWith('.') || c.includes(':') ||
      DENIED.has(c.toLowerCase()) || c.toLowerCase().startsWith('.env.'))) return false;
  if (tool === 'native_file_read' && !VALID_SUFFIX.test(relative)) return false;
  return true;
}
export function isNativeOriginalDevice(
  requested: string | undefined,
  ownerBound: boolean,
  device: { deviceId?: unknown; name?: unknown; platform?: unknown } | undefined,
  tools: unknown): boolean {
  const configured = nativeDeviceId();
  if (!configured || !requested || requested !== configured || !ownerBound
      || !device || device.deviceId !== configured || device.name !== EXPECTED_NAME
      || device.platform !== 'win32' || !Array.isArray(tools)
      || tools.length !== 2) return false;
  const names = tools.map(t => t && typeof t === 'object' ? t.name : null);
  return names.length === METHODS.size && new Set(names).size === METHODS.size
      && names.every(name => typeof name === 'string' && METHODS.has(name));
}
const deviceProp = {type: 'string', minLength: 8, maxLength: 128,
                    description: 'Owner-paired native original Windows READ device ID'};
function tool(name: string, description: string) {
  return {
    name, description,
    inputSchema: {
      type: 'object',
      properties: {
        project: {type: 'string', enum: [...PROJECTS]},
        relative: {type: 'string', minLength: name === 'native_file_read' ? 1 : 0,
                   maxLength: 1024},
        deviceId: deviceProp,
      },
      required: ['project', 'relative', 'deviceId'],
      additionalProperties: false,
    },
    annotations: {title: 'Original Windows read-only', readOnlyHint: true,
                  destructiveHint: false, openWorldHint: false},
  };
}
export function originalWindowsReadToolCatalog() {
  // Disabled by default even at discovery time, no unconditional grant.
  if (!nativeDeviceId()) return [];
  return [
    tool('native_file_stat', 'Stat one file under approved original Windows project'),
    tool('native_file_read', 'Read one approved original Windows source file (max 256 KiB)'),
  ];
}
