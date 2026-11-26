/* Hermes #454: relay-native, owner-scoped read-only workspace catalog. */
type Workspace = { name: string; aliases: string[]; root: string; origin: string; branch: string };
type Device = { name?: unknown; deviceId?: unknown; platform?: unknown; online?: unknown; paused?: unknown };
const DEVICE_NAME = __HERMES_DEVICE_NAME__;
const PERSONAL_NAME = 'H454 Windows personal Commander';
const PERSONAL_ID = /^h454-win-personal-[a-f0-9]{32}$/;
const PERSONAL_ALIASES = ['yfc-dev', 'yfc dev', 'your-fitness-coach dev'];
const PERSONAL_ROOT = 'D:\\Pet-projects\\yfc-dev';
const PERSONAL_ORIGIN = 'https://github.com/MikeMoore1337/your-fitness-coach.git';
const WORKSPACES: Workspace[] = __HERMES_CATALOG__;
const SANDBOX_HELPER = __HERMES_SANDBOX_HELPER__;
const ID = /^[A-Za-z0-9_-]{8,128}$/;
const PROJECT_NAME = /^[a-z][a-z0-9-]{1,79}$/;
export const LIST_WORKSPACES_TOOL = {
  name: 'list_workspaces',
  description: 'List approved development workspaces and actual device connectivity. Does not verify Git.',
  inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  annotations: { title: 'List Hermes workspaces', readOnlyHint: true },
};
export const RESOLVE_WORKSPACE_TOOL = {
  name: 'resolve_workspace',
  description: 'Find an approved project by name. YFC dev resolves to its separately authorized original Windows folder; other catalog projects resolve to the sandbox. Check Git before writing.',
  inputSchema: { type: 'object', properties: {
    project: { type: 'string', minLength: 1, maxLength: 100 } },
    required: ['project'], additionalProperties: false },
  annotations: { title: 'Resolve Hermes workspace', readOnlyHint: true },
};
export const CONNECT_SANDBOX_TOOL = {
  name: 'connect_sandbox_project',
  description: 'Connect an existing named MikeMoore1337 Git repository already present in the Windows sandbox. Does not clone, modify the repository, or grant native host access.',
  inputSchema: { type: 'object', properties: {
    project: { type: 'string', minLength: 2, maxLength: 80 } },
    required: ['project'], additionalProperties: false },
  annotations: { title: 'Connect an existing sandbox project', readOnlyHint: true },
};
function ownerDevice(devices: unknown): Device | null {
  if (!Array.isArray(devices) || devices.length > 25) return null;
  const matches = devices.filter(d => d && typeof d === 'object' && d.name === DEVICE_NAME);
  if (matches.length !== 1) return null;
  const d: Device = matches[0];
  return typeof d.deviceId === 'string' && ID.test(d.deviceId) ? d : null;
}
function personalDevice(devices: unknown): Device | null {
  if (!Array.isArray(devices) || devices.length > 25) return null;
  const matches = devices.filter(d => d && typeof d === 'object' && d.name === PERSONAL_NAME);
  if (matches.length !== 1) return null;
  const d: Device = matches[0];
  return d.platform === 'win32' && typeof d.deviceId === 'string' && PERSONAL_ID.test(d.deviceId) ? d : null;
}
function isReady(d: Device | null): boolean {
  return !!d && d.online === true && d.paused === false;
}
function norm(s: string): string {
  return s.trim().toLowerCase().replace(/_/g, ' ').replace(/\s+/g, ' ');
}
function validGitBranch(row: Record<string, unknown>): boolean {
  return (typeof row.branch === 'string' && row.branch.length > 0 && row.branch.length <= 255
          && (row.detached === undefined || row.detached === false))
    || (row.branch === null && row.detached === true);
}
export function listApprovedWorkspaces(devices: unknown) {
  const d = ownerDevice(devices);
  const personal = personalDevice(devices);
  if (!d && !personal) return { schema: 1, status: 'not_connected', workspaces: [] };
  const state = isReady(d) ? 'online' : d?.paused === true ? 'paused' : 'offline';
  const workspaces: Record<string, unknown>[] = d ? WORKSPACES.map(w => ({
    name: w.name, aliases: [...w.aliases], root: w.root, origin: w.origin,
    branch: w.branch, scope: 'sandbox', device_status: state, git_verified: false,
    // Online indicates a control-plane heartbeat, not a successful remote exec.
    process_execution_verified: false,
    ...(state === 'online' ? { deviceId: d.deviceId } : {})
  })) : [];
  if (personal) {
    const personalState = isReady(personal) ? 'online' : personal.paused === true ? 'paused' : 'offline';
    workspaces.push({name:'yfc-dev', aliases:[...PERSONAL_ALIASES], root:PERSONAL_ROOT,
      origin:PERSONAL_ORIGIN, branch:null, scope:'native-personal',
      device_status:personalState, git_verified:false, process_execution_verified:false,
      ...(personalState === 'online' ? {deviceId:personal.deviceId} : {})});
  }
  return { schema: 1, status: 'catalog', workspaces };
}
export function resolveApprovedWorkspace(args: unknown, devices: unknown) {
  if (!args || typeof args !== 'object' || Array.isArray(args))
    return { schema: 1, status: 'refused', reason: 'invalid_arguments' };
  const keys = Object.keys(args);
  const project = (args as Record<string, unknown>).project;
  if (keys.length !== 1 || keys[0] !== 'project' || typeof project !== 'string'
      || project.length < 1 || project.length > 100)
    return { schema: 1, status: 'refused', reason: 'invalid_arguments' };
  if (PERSONAL_ALIASES.some(alias => norm(alias) === norm(project))) {
    const d = personalDevice(devices);
    if (!isReady(d)) return { schema: 1, status: 'refused', reason: 'personal_device_unavailable' };
    return { schema: 1, status:'resolved', workspace:'yfc-dev', root:PERSONAL_ROOT,
      branch:null, origin:PERSONAL_ORIGIN, scope:'native-personal', deviceId:d!.deviceId,
      device_status:'online', git_verified:false, process_execution_verified:false,
      verification_required_before_write:true };
  }
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

// Keep the built-in catalog available even if the sandbox is offline or slow.
export async function addDiscoveredWorkspaces(catalog: Record<string, unknown>,
  devices: unknown, invoke: (tool: string, input: Record<string, unknown>) => Promise<unknown>
): Promise<Record<string, unknown>> {
  const d = ownerDevice(devices);
  const fallback = (reason: string) => ({ ...catalog, discovery_status: reason });
  if (!isReady(d) || !Array.isArray(catalog.workspaces)) return fallback('unavailable');
  const command = `python3 -c 'import base64;exec(compile(base64.b64decode("${SANDBOX_HELPER}"),"sandbox_projects","exec"))' list`;
  let response: unknown;
  try { response = await invoke('start_process', { deviceId: d!.deviceId, command, timeout_ms: 5000 }); }
  catch { return fallback('unavailable'); }
  const outer = response as { ok?: unknown; result?: { isError?: unknown; content?: unknown } };
  if (!outer || outer.ok !== true || !outer.result || outer.result.isError === true || !Array.isArray(outer.result.content))
    return fallback('unavailable');
  const first = outer.result.content[0] as { type?: unknown; text?: unknown } | undefined;
  if (!first || first.type !== 'text' || typeof first.text !== 'string' || first.text.length > 8192)
    return fallback('unavailable');
  const marker = first.text.includes('Initial output:\n') ? 'Initial output:\n' : 'Output:\n';
  const offset = first.text.indexOf(marker);
  let data: Record<string, unknown> | undefined;
  if (offset >= 0) {
    try { data = JSON.parse(first.text.slice(offset + marker.length).trim()); } catch { /* still running */ }
  }
  if (!data) return fallback(/^Process started with PID \d+\b/.test(first.text) ? 'pending' : 'unavailable');
  if (data.status !== 'catalog' || !Array.isArray(data.projects) || data.projects.length > 16 || typeof data.incomplete !== 'boolean')
    return fallback('unavailable');
  const entries = [...catalog.workspaces];
  const known = new Set(entries.map((value: unknown) => (value as { name?: unknown }).name));
  let incomplete = data.incomplete;
  for (const value of data.projects) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) { incomplete = true; continue; }
    const row = value as Record<string, unknown>;
    const name = row.workspace;
    const repository = row.repository ?? name;
    if (typeof name !== 'string' || !PROJECT_NAME.test(name) || row.status !== 'verified'
        || typeof repository !== 'string' || !PROJECT_NAME.test(repository)
        || row.root !== `/workspace/projects/${name}` || row.origin !== `https://github.com/MikeMoore1337/${repository}.git`
        || !validGitBranch(row)
        || typeof row.head !== 'string' || !/^[a-f0-9]{40}$/.test(row.head)) {
      incomplete = true; continue;
    }
    if (known.has(name)) continue;
    known.add(name);
    entries.push({ name, aliases: [name], root: row.root, origin: row.origin, branch: row.branch,
      head: row.head, detached: row.detached === true, scope: 'sandbox', deviceId: d!.deviceId, device_status: 'online',
      git_verified: true, process_execution_verified: true, verification_required_before_write: true });
  }
  return { ...catalog, workspaces: entries, discovery_status: incomplete ? 'incomplete' : 'complete' };
}

// A sandbox project lives on the existing sandbox volume, so discovery is
// checked against the actual Git repository on every resolution and does not
// depend on relay process memory or an unverified guessed path.
export async function sandboxProjectAction(args: unknown,
  devices: unknown, invoke: (tool: string, input: Record<string, unknown>) => Promise<unknown>
): Promise<Record<string, unknown>> {
  if (!args || typeof args !== 'object' || Array.isArray(args)
      || Object.keys(args).length !== 1 || typeof (args as Record<string, unknown>).project !== 'string')
    return { schema: 1, status: 'refused', reason: 'invalid_arguments' };
  const name = (args as { project: string }).project;
  if (!PROJECT_NAME.test(name)) return { schema: 1, status: 'refused', reason: 'invalid_project_name' };
  const d = ownerDevice(devices);
  if (!isReady(d)) return { schema: 1, status: 'refused', reason: 'owner_device_unavailable' };
  const command = `python3 -c 'import base64;exec(compile(base64.b64decode("${SANDBOX_HELPER}"),"sandbox_projects","exec"))' inspect ${name}`;
  let response: unknown;
  try { response = await invoke('start_process', { deviceId: d!.deviceId, command, timeout_ms: 5000 }); }
  catch { return { schema: 1, status: 'refused', reason: 'sandbox_call_failed' }; }
  const outer = response as { ok?: unknown; result?: { isError?: unknown; content?: unknown } };
  if (!outer || outer.ok !== true || !outer.result || !Array.isArray(outer.result.content))
    return { schema: 1, status: 'refused', reason: 'sandbox_call_failed' };
  const first = outer.result.content[0] as { type?: unknown; text?: unknown } | undefined;
  if (!first || first.type !== 'text' || typeof first.text !== 'string' || first.text.length > 8192)
    return { schema: 1, status: 'refused', reason: 'sandbox_response_invalid' };
  const marker = first.text.includes('Initial output:\n') ? 'Initial output:\n' : 'Output:\n';
  const offset = first.text.indexOf(marker);
  let data: Record<string, unknown> | undefined;
  if (offset >= 0) {
    try { data = JSON.parse(first.text.slice(offset + marker.length).trim()); } catch { /* still running */ }
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    if (outer.result.isError === true) return { schema: 1, status: 'refused', reason: 'sandbox_call_failed' };
    const pid = /^Process started with PID (\d+)\b/.exec(first.text)?.[1];
    return pid
      ? { schema: 1, status: 'pending', reason: 'sandbox_process_running',
          process_id: Number(pid), deviceId: d!.deviceId }
      : { schema: 1, status: 'refused', reason: 'sandbox_response_invalid' };
  }
  if (data.status !== 'verified') {
    const reasons = ['invalid_name', 'project_not_found', 'invalid_project', 'origin_mismatch',
      'git_unavailable', 'git_failed', 'invalid_git_state', 'operation_failed'];
    const reason = typeof data.reason === 'string' && reasons.includes(data.reason) ? data.reason : 'project_not_verified';
    return { schema: 1, status: 'refused', reason };
  }
  if (outer.result.isError === true) return { schema: 1, status: 'refused', reason: 'sandbox_call_failed' };
  const repository = data.repository ?? name;
  if (data.workspace !== name || data.root !== `/workspace/projects/${name}`
      || typeof repository !== 'string' || !PROJECT_NAME.test(repository)
      || data.origin !== `https://github.com/MikeMoore1337/${repository}.git`
      || !validGitBranch(data) || typeof data.head !== 'string' || !/^[a-f0-9]{40}$/.test(data.head))
    return { schema: 1, status: 'refused', reason: 'sandbox_response_invalid' };
  return { schema: 1, ...data, status: 'resolved', deviceId: d!.deviceId,
    device_status: 'online', git_verified: true, process_execution_verified: true };
}
