/* Hermes #454: relay-native, owner-scoped read-only workspace catalog. */
type Workspace = { name: string; aliases: string[]; root: string; origin: string; branch: string };
type Device = { name?: unknown; deviceId?: unknown; online?: unknown; paused?: unknown };
const DEVICE_NAME = __HERMES_DEVICE_NAME__;
const DEVICE_ID = __HERMES_DEVICE_ID__;
const WORKSPACES: Workspace[] = __HERMES_CATALOG__;
const ID = /^[A-Za-z0-9_-]{8,128}$/;
export const LIST_WORKSPACES_TOOL = {
  name: 'list_workspaces',
  description: 'List approved development workspaces and actual device connectivity. Does not verify Git.',
  inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  annotations: { title: 'List Hermes workspaces', readOnlyHint: true },
};
export const RESOLVE_WORKSPACE_TOOL = {
  name: 'resolve_workspace',
  description: 'Find a project by name (yfc, toolkit, second brain, hermes). Returns sandbox path and actual device ID, not a native host path. Check Git before writing.',
  inputSchema: { type: 'object', properties: {
    project: { type: 'string', minLength: 1, maxLength: 100 } },
    required: ['project'], additionalProperties: false },
  annotations: { title: 'Resolve Hermes workspace', readOnlyHint: true },
};
function ownerDevice(devices: unknown): Device | null {
  if (!Array.isArray(devices) || devices.length > 25) return null;
  const matches = devices.filter(d => d && typeof d === 'object' && d.name === DEVICE_NAME);
  if (matches.length !== 1) return null;
  if (devices.filter(d => d && typeof d === 'object' && d.deviceId === DEVICE_ID).length !== 1) return null;
  const d: Device = matches[0];
  return typeof d.deviceId === 'string' && ID.test(d.deviceId) && d.deviceId === DEVICE_ID ? d : null;
}
function isReady(d: Device | null): boolean {
  return !!d && d.online === true && d.paused === false;
}
type WorkspaceRoute =
  | { status: 'unchanged' }
  | { status: 'routed'; deviceId: string }
  | { status: 'refused'; reason: string };

// Automatic routing chooses a device; it does not grant filesystem access.
export function routeWorkspaceCall(name: string, args: unknown, devices: unknown): WorkspaceRoute {
  if (!args || typeof args !== 'object' || Array.isArray(args)) return { status: 'unchanged' };
  const a = args as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(a, 'deviceId'))
    return typeof a.deviceId === 'string' && a.deviceId.length > 0
      ? { status: 'unchanged' } : { status: 'refused', reason: 'invalid_device_id' };
  let paths: unknown[];
  switch (name) {
    case 'read_file': case 'write_file': case 'create_directory': case 'list_directory':
    case 'get_file_info': case 'start_search': paths = [a.path]; break;
    case 'edit_block': paths = [a.file_path]; break;
    case 'move_file': paths = [a.source, a.destination]; break;
    case 'read_multiple_files':
      if (!Array.isArray(a.paths) || a.paths.length === 0 || a.paths.length > 64)
        return { status: 'refused', reason: 'workspace_paths_not_routable' };
      paths = a.paths; break;
    case 'write_pdf':
      paths = [a.path];
      if (Object.prototype.hasOwnProperty.call(a, 'outputPath')) paths.push(a.outputPath);
      if (Array.isArray(a.content)) {
        if (a.content.length > 64) return { status: 'refused', reason: 'workspace_paths_not_routable' };
        for (const entry of a.content) {
          if (entry && typeof entry === 'object' && !Array.isArray(entry) &&
              Object.prototype.hasOwnProperty.call(entry, 'sourcePdfPath'))
            paths.push((entry as Record<string, unknown>).sourcePdfPath);
        }
      }
      break;
    default: return { status: 'unchanged' };
  }
  const classify = (path: unknown): 'known' | 'outside' | 'unsafe' => {
    if (typeof path !== 'string') return 'outside';
    if (path.length > 4096 || /[\x00-\x1f\x7f]/.test(path)) return 'unsafe';
    const slashes = path.replace(/\\/g, '/');
    if (!slashes.startsWith('/')) return 'outside';
    const parts: string[] = [];
    const inWorkspace = (value: string) => WORKSPACES.some(w => value === w.root || value.startsWith(w.root + '/'));
    let enteredWorkspace = false;
    for (const part of slashes.split('/')) {
      if (part === '' || part === '.') continue;
      if (part === '..') parts.pop();
      else parts.push(part);
      if (parts.length === 3 && inWorkspace('/' + parts.join('/'))) enteredWorkspace = true;
    }
    const normalized = '/' + parts.join('/');
    if (!inWorkspace(normalized)) return enteredWorkspace ? 'unsafe' : 'outside';
    return path === normalized || path === normalized + '/' ? 'known' : 'unsafe';
  };
  const classifications = paths.map(classify);
  if (classifications.every(x => x === 'outside')) return { status: 'unchanged' };
  if (classifications.some(x => x !== 'known'))
    return { status: 'refused', reason: 'workspace_paths_not_routable' };
  const device = ownerDevice(devices);
  if (!isReady(device) || typeof device?.deviceId !== 'string')
    return { status: 'refused', reason: 'owner_device_unavailable' };
  return { status: 'routed', deviceId: device.deviceId };
}
function norm(s: string): string {
  return s.trim().toLowerCase().replace(/_/g, ' ').replace(/\s+/g, ' ');
}
export function listApprovedWorkspaces(devices: unknown) {
  const d = ownerDevice(devices);
  if (!d) return { schema: 1, status: 'not_connected', workspaces: [] };
  const state = isReady(d) ? 'online' : d.paused === true ? 'paused' : 'offline';
  return { schema: 1, status: 'catalog', workspaces: WORKSPACES.map(w => ({
    name: w.name, aliases: [...w.aliases], root: w.root, origin: w.origin,
    branch: w.branch, scope: 'sandbox', device_status: state, git_verified: false,
    // Online indicates a control-plane heartbeat, not a successful remote exec.
    process_execution_verified: false,
    ...(state === 'online' ? { deviceId: d.deviceId } : {})
  })) };
}
export function resolveApprovedWorkspace(args: unknown, devices: unknown) {
  if (!args || typeof args !== 'object' || Array.isArray(args))
    return { schema: 1, status: 'refused', reason: 'invalid_arguments' };
  const keys = Object.keys(args);
  const project = (args as Record<string, unknown>).project;
  if (keys.length !== 1 || keys[0] !== 'project' || typeof project !== 'string'
      || project.length < 1 || project.length > 100)
    return { schema: 1, status: 'refused', reason: 'invalid_arguments' };
  const found = WORKSPACES.filter(w => w.aliases.some(a => norm(a) === norm(project)));
  if (found.length !== 1)
    return { schema: 1, status: 'refused', reason: 'unknown_workspace' };
  const d = ownerDevice(devices);
  if (!isReady(d))
    return { schema: 1, status: 'refused', reason: 'owner_device_unavailable' };
  const w = found[0];
  return { schema: 1, status: 'resolved', workspace: w.name,
    root: w.root, branch: w.branch, origin: w.origin, scope: 'sandbox',
    deviceId: d!.deviceId, device_status: 'online', git_verified: false,
    process_execution_verified: false, verification_required_before_write: true };
}
