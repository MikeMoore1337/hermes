// Stdio adapter for the pinned Commander bundle inside the Linux sandbox.
// The trusted parent supplies a single mounted project; no bearer reaches here.
import path from 'node:path';
import { realpath } from 'node:fs/promises';
import { createInterface } from 'node:readline';

const write = process.stdout.write.bind(process.stdout);
process.stdout.write = () => true;
console.log = () => {};
console.error = () => {};
const MAX_FRAME = 1024 * 1024;
const ROOT = '/workspace';
const allowed = new Set([
  'read_file', 'read_multiple_files', 'write_file', 'edit_block',
  'create_directory', 'list_directory', 'move_file', 'get_file_info',
  'start_search', 'get_more_search_results', 'stop_search', 'list_searches',
  'start_process', 'read_process_output', 'interact_with_process',
  'force_terminate', 'list_sessions',
]);
let terminalManager;

function send(frame) {
  const text = JSON.stringify(frame);
  if (Buffer.byteLength(text, 'utf8') > MAX_FRAME) throw Error('FRAME_DENIED');
  write(text + '\n');
}

function within(value) {
  return value === ROOT || value.startsWith(ROOT + '/');
}

async function checkPath(value) {
  if (typeof value !== 'string' || value.length > 2048 || !value.startsWith('/') ||
      value.includes('\0') || value.split('/').some(part => part === '..') ||
      !within(path.posix.normalize(value))) throw Error('PATH_DENIED');
  let current = path.posix.normalize(value);
  while (true) {
    try {
      if (!within(await realpath(current))) throw Error('PATH_DENIED');
      return;
    } catch (error) {
      if (error.code !== 'ENOENT' || current === ROOT) throw error;
      current = path.posix.dirname(current);
    }
  }
}

async function authorize(name, args) {
  if (!allowed.has(name) || !args || typeof args !== 'object' || Array.isArray(args))
    throw Error('CALL_DENIED');
  let paths = [];
  if (['read_file', 'write_file', 'create_directory', 'list_directory', 'get_file_info', 'start_search'].includes(name)) paths = [args.path];
  if (name === 'read_multiple_files') paths = args.paths;
  if (name === 'edit_block') paths = [args.file_path];
  if (name === 'move_file') paths = [args.source, args.destination];
  if (!Array.isArray(paths) || paths.length > 32 || (name === 'read_file' && args.isUrl === true))
    throw Error('CALL_DENIED');
  for (const item of paths) await checkPath(item);
  return args;
}

async function main() {
  if (process.platform !== 'linux' || process.argv.length !== 2 || process.getuid() === 0)
    throw Error('START_DENIED');
  process.env.BRC_HOME = '/tmp/brc';
  const base = '/opt/commander/bundle/packages/agent/dist';
  const { callTool, listTools } = await import(base + '/dispatcher.js');
  const { configManager } = await import(base + '/core/config-manager.js');
  ({ terminalManager } = await import(base + '/core/terminal-manager.js'));
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  let initialized = false;
  for await (const line of lines) {
    if (Buffer.byteLength(line, 'utf8') > MAX_FRAME) throw Error('FRAME_DENIED');
    const frame = JSON.parse(line);
    if (!initialized) {
      if (!frame || Object.keys(frame).sort().join(',') !== 'roots,type' ||
          frame.type !== 'initialize' || !Array.isArray(frame.roots) ||
          frame.roots.length !== 1 || frame.roots[0] !== ROOT) throw Error('INIT_DENIED');
      await configManager.init();
      await configManager.setValue('telemetryEnabled', false);
      await configManager.setValue('allowedDirectories', [ROOT]);
      const tools = listTools().filter(tool => allowed.has(tool.name));
      if (tools.length !== allowed.size || new Set(tools.map(tool => tool.name)).size !== tools.length)
        throw Error('TOOLS_DENIED');
      send({ type: 'ready', tools });
      initialized = true;
      continue;
    }
    if (!frame || Object.keys(frame).sort().join(',') !== 'args,id,name,type' ||
        frame.type !== 'call' || typeof frame.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(frame.id))
      throw Error('FRAME_DENIED');
    try {
      const args = await authorize(frame.name, frame.args);
      send({ type: 'result', id: frame.id, result: await callTool(frame.name, args) });
    } catch {
      send({ type: 'result', id: frame.id, result: { isError: true,
        content: [{ type: 'text', text: 'H454_PERSONAL_CALL_DENIED' }] } });
    }
  }
}

async function finish(code) {
  if (terminalManager) {
    for (const session of terminalManager.listActiveSessions()) terminalManager.forceTerminate(session.pid);
    await new Promise(resolve => setTimeout(resolve, 1200));
  }
  process.exit(code);
}

main().then(() => finish(0), () => finish(2));
