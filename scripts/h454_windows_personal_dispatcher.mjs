// Local stdio adapter for an owner-configured Windows Commander bundle.
// A trusted parent owns the authenticated transport and supplies the roots;
// this process never receives a relay bearer or opens a network listener.
import path from 'node:path';
import { lstat, realpath } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

const wireWrite = process.stdout.write.bind(process.stdout);
process.stdout.write = () => true;
console.log = () => {};
console.error = () => {};
const MAX_FRAME = 1024 * 1024;
const allowed = new Set([
  'read_file', 'read_multiple_files', 'write_file', 'write_pdf', 'edit_block',
  'create_directory', 'list_directory', 'move_file', 'get_file_info',
  'start_search', 'get_more_search_results', 'stop_search', 'list_searches',
  'start_process', 'read_process_output', 'interact_with_process',
  'force_terminate', 'list_sessions',
]);
const blocked = new Set(['.git', '.hg', '.svn', '.ssh', '.aws', '.gnupg', '.kube', '.artifacts',
  '.terraform', '.next', '.cache', 'node_modules', '__pycache__', 'vault', '.vault',
  'private-vault', 'secrets', '.secrets', 'credentials', '.env', '.env.local', '.env.production']);
const sensitive = /^\.?(?:secrets?|credentials?|tokens?|passwords?|api[-_]?keys?|service[-_]?accounts?|private[-_]?keys?|config[._-]local)(?:[._-]|$)/i;
const reserved = /^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$/i;
let terminalManager;

function send(value) {
  const text = JSON.stringify(value);
  if (Buffer.byteLength(text, 'utf8') > MAX_FRAME) throw new Error('FRAME_TOO_LARGE');
  wireWrite(text + '\n');
}

function cleanAbsolute(value) {
  if (typeof value !== 'string' || value.length > 2048 || !/^[A-Za-z]:[\\/]/.test(value)) throw new Error('PATH_DENIED');
  const trimmed = value.replace(/[\\/]+$/, '');
  if (trimmed.length <= 2) throw new Error('PATH_DENIED');
  const parts = trimmed.slice(3).split(/[\\/]/);
  if (parts.some(part => !part || part === '.' || part === '..' || /[<>:"|?*\x00-\x1f]/.test(part)
      || /[ .]$/.test(part) || reserved.test(part))) throw new Error('PATH_DENIED');
  return path.win32.normalize(trimmed);
}

function under(root, value) {
  const a = root.toLowerCase();
  const b = value.toLowerCase();
  return b === a || b.startsWith(a + '\\');
}

function checkComponents(root, value) {
  if (!under(root, value)) throw new Error('PATH_DENIED');
  const relative = value.slice(root.length).replace(/^\\/, '');
  if (relative.split('\\').some(part => {
    const lower = part.toLowerCase();
    return blocked.has(lower) || lower.startsWith('.env.') || sensitive.test(lower)
      || ['.pem', '.key', '.pfx', '.p12', '.kdbx'].some(suffix => lower.endsWith(suffix));
  })) throw new Error('PATH_DENIED');
}

async function canonicalExistingAncestor(value) {
  let current = value;
  const rest = [];
  while (true) {
    try { return path.win32.join(await realpath(current), ...rest); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      const parent = path.win32.dirname(current);
      if (parent === current) throw new Error('PATH_DENIED');
      rest.unshift(path.win32.basename(current));
      current = parent;
    }
  }
}

async function checkPath(value, roots) {
  const requested = cleanAbsolute(value);
  const root = roots.find(item => under(item, requested));
  if (!root) throw new Error('PATH_DENIED');
  checkComponents(root, requested);
  const resolved = cleanAbsolute(await canonicalExistingAncestor(requested));
  checkComponents(root, resolved);
  try {
    const info = await lstat(requested);
    if (info.isSymbolicLink() || (info.isFile() && info.nlink !== 1)) throw new Error('PATH_DENIED');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

async function authorize(name, args, roots) {
  if (!allowed.has(name) || !args || typeof args !== 'object' || Array.isArray(args)) throw new Error('CALL_DENIED');
  let paths = [];
  if (['read_file', 'write_file', 'create_directory', 'list_directory', 'get_file_info', 'start_search'].includes(name)) paths = [args.path];
  if (name === 'read_multiple_files') paths = args.paths;
  if (name === 'edit_block') paths = [args.file_path];
  if (name === 'move_file') paths = [args.source, args.destination];
  if (name === 'write_pdf') paths = (await import('./h454_personal_pdf.mjs')).personalPdfPaths(args);
  if (!Array.isArray(paths) || paths.length > 32) throw new Error('CALL_DENIED');
  if (name === 'read_file' && args.isUrl === true) throw new Error('CALL_DENIED');
  if (name === 'list_directory' && args.depth !== undefined && args.depth !== 1) throw new Error('CALL_DENIED');
  if (name === 'start_search') {
    const keys = new Set(['path', 'pattern', 'searchType', 'filePattern', 'ignoreCase', 'maxResults',
      'includeHidden', 'contextLines', 'timeout_ms', 'earlyTermination', 'literalSearch', 'origin']);
    if (Object.keys(args).some(key => !keys.has(key)) || typeof args.pattern !== 'string'
        || !args.pattern.length || args.pattern.length > 256 || args.pattern.includes('\0')
        || !['files', 'content'].includes(args.searchType ?? 'files')
        || (args.filePattern !== undefined && (typeof args.filePattern !== 'string' || args.filePattern.length > 256))
        || ['ignoreCase', 'includeHidden', 'earlyTermination', 'literalSearch'].some(key =>
          args[key] !== undefined && typeof args[key] !== 'boolean')
        || (args.maxResults !== undefined && (!Number.isInteger(args.maxResults) || args.maxResults < 1 || args.maxResults > 128))
        || (args.timeout_ms !== undefined && (!Number.isInteger(args.timeout_ms) || args.timeout_ms < 100 || args.timeout_ms > 10000))
        || (args.contextLines !== undefined && (!Number.isInteger(args.contextLines) || args.contextLines < 0 || args.contextLines > 3))
        || (args.origin !== undefined && !['ui', 'llm'].includes(args.origin))
        || (args.searchType === 'content' && /\.(?:xlsx|xlsm|xlsb|xls|docx)/i.test((args.filePattern ?? '') + '|' + args.path)))
      throw new Error('CALL_DENIED');
  }
  if (name === 'get_more_search_results' || name === 'stop_search') {
    const keys = name === 'stop_search' ? ['sessionId'] : ['sessionId', 'offset', 'length'];
    if (Object.keys(args).some(key => !keys.includes(key)) || typeof args.sessionId !== 'string'
        || !/^[A-Za-z0-9_-]{1,128}$/.test(args.sessionId)
        || (args.offset !== undefined && (!Number.isInteger(args.offset) || Math.abs(args.offset) > 10000))
        || (args.length !== undefined && (!Number.isInteger(args.length) || args.length < 1 || args.length > 128)))
      throw new Error('CALL_DENIED');
  }
  if (name === 'list_searches' && Object.keys(args).length) throw new Error('CALL_DENIED');
  for (const value of paths) await checkPath(value, roots);
  if (name === 'move_file' && !(await lstat(args.source)).isFile()) throw new Error('CALL_DENIED');
  if (name === 'start_search') return { ...args, maxResults: args.maxResults ?? 128,
    timeout_ms: args.timeout_ms ?? 10000, contextLines: args.contextLines ?? 0 };
  return name === 'list_directory' ? { ...args, depth: 1 } : args;
}

async function main() {
  if (process.platform !== 'win32' || process.argv.length !== 3) throw new Error('START_DENIED');
  const entry = cleanAbsolute(process.argv[2]);
  if (path.win32.basename(entry) !== 'dispatcher.js') throw new Error('START_DENIED');
  const base = path.win32.dirname(entry);
  const { callTool, listTools } = await import(pathToFileURL(entry).href);
  const { configManager } = await import(pathToFileURL(path.win32.join(base, 'core', 'config-manager.js')).href);
  ({ terminalManager } = await import(pathToFileURL(path.win32.join(base, 'core', 'terminal-manager.js')).href));
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  let roots = null;
  for await (const line of lines) {
    if (Buffer.byteLength(line, 'utf8') > MAX_FRAME) throw new Error('FRAME_TOO_LARGE');
    let frame;
    try { frame = JSON.parse(line); } catch { throw new Error('FRAME_INVALID'); }
    if (roots === null) {
      if (!frame || Object.keys(frame).sort().join(',') !== 'roots,type' || frame.type !== 'initialize'
          || !Array.isArray(frame.roots) || frame.roots.length < 1 || frame.roots.length > 16) throw new Error('INIT_DENIED');
      roots = [];
      for (const item of frame.roots) {
        const root = cleanAbsolute(item);
        const final = cleanAbsolute(await realpath(root));
        if (root.toLowerCase() !== final.toLowerCase() || roots.some(existing => under(existing, root) || under(root, existing))) throw new Error('INIT_DENIED');
        roots.push(root);
      }
      await configManager.init();
      await configManager.setValue('telemetryEnabled', false);
      await configManager.setValue('allowedDirectories', roots);
      const tools = listTools().filter(tool => allowed.has(tool.name)).map(tool => tool.name === 'write_pdf'
        ? { ...tool, description: 'Create or modify a PDF from basic Markdown and local PNG/JPEG images without a browser. Page insertion and deletion require a new output file. Supports page format, dimensions, margins and landscape; HTML/CSS and other options are not supported.' }
        : tool);
      if (tools.length !== allowed.size || new Set(tools.map(tool => tool.name)).size !== tools.length) throw new Error('TOOLS_DENIED');
      send({ type: 'ready', tools });
      continue;
    }
    if (!frame || Object.keys(frame).sort().join(',') !== 'args,id,name,type' || frame.type !== 'call'
        || typeof frame.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(frame.id)) throw new Error('FRAME_INVALID');
    try {
      const args = await authorize(frame.name, frame.args, roots);
      const result = frame.name === 'write_pdf'
        ? await (await import('./h454_personal_pdf.mjs')).createPersonalPdf(args)
        : await callTool(frame.name, args);
      send({ type: 'result', id: frame.id, result });
    } catch (error) {
      send({ type: 'result', id: frame.id, result: { isError: true,
        content: [{ type: 'text', text: error?.message?.startsWith('H454_PDF_')
          ? error.message : 'H454_PERSONAL_CALL_DENIED' }] } });
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
