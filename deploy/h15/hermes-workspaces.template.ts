/* Hermes #454: relay-native, owner-scoped read-only workspace catalog. */
type Workspace = { name: string; aliases: string[]; root: string; origin: string; branch: string };
type Device = { name?: unknown; deviceId?: unknown; online?: unknown; paused?: unknown };
const DEVICE_NAME = __HERMES_DEVICE_NAME__;
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
  const d: Device = matches[0];
  return typeof d.deviceId === 'string' && ID.test(d.deviceId) ? d : null;
}
function isReady(d: Device | null): boolean {
  return !!d && d.online === true && d.paused === false;
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
    verification_required_before_write: true };
}
