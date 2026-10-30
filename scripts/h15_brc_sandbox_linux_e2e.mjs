#!/usr/bin/env node
// Genuine patched BRC tool dispatcher exercised under kernel/container OS
// constraints. Runs only in a disposable Docker CI namespace (#371).
import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import { setTimeout as pause } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';

const source = '/opt/brc/packages/agent/dist/dispatcher.js';
const { listTools, callTool } = await import(pathToFileURL(source).href);
const failures = [];
function assert(value, label) {
  if (!value) failures.push(label);
  else console.log(label + '=PASS');
}
assert(process.getuid?.() === 65534, 'OS_NON_ROOT');
assert(process.env.BRC_HOME?.startsWith('/workspace/'), 'OS_ISOLATED_HOME');

const deniedTools = ['get_config', 'get_recent_tool_calls', 'set_config_value',
  'prepare_file_transfer', 'send_file_transfer', 'receive_file_transfer'];
const listed = new Set(listTools().map((tool) => tool.name));
for (const tool of deniedTools) {
  const result = await callTool(tool, {});
  assert(!listed.has(tool) && result.isError === true, 'MCP_DENIED_' + tool.toUpperCase());
}

// The candidate deliberately retains REAL file read/write, but the kernel's
// read-only source mount must reject a write despite an empty allowedDirs ACL.
const allowed = await callTool('write_file', {
  path: '/workspace/allowed.txt', content: 'approved-workspace-data',
  mode: 'rewrite',
});
assert(allowed.isError !== true &&
       fs.readFileSync('/workspace/allowed.txt', 'utf8').includes('approved-workspace-data'),
       'MCP_WORKSPACE_WRITE');

// The filesystem may use epoch zero when birthtime is unavailable. Exercise
// the real dispatcher/formatter with controlled stats, not host metadata.
const metadataPath = '/workspace/birthtime-fixture.txt';
fs.writeFileSync(metadataPath, 'preserve-content');
const originalStat = fsPromises.stat;
let reportedBirthtime = new Date('2020-01-02T03:04:05.000Z');
try {
  fsPromises.stat = async (...args) => {
    const stats = await originalStat(...args);
    if (args[0] === metadataPath) Object.defineProperty(stats, 'birthtime', {value: reportedBirthtime});
    return stats;
  };
  const known = await callTool('get_file_info', {path: metadataPath});
  const knownText = known.content.map(item => item.text || '').join('\n');
  assert(known.isError !== true && knownText.includes('created: "2020-01-02T03:04:05.000Z"') &&
    !knownText.includes('createdStatus:'), 'MCP_FILE_INFO_KNOWN_BIRTHTIME_UNCHANGED');
  reportedBirthtime = new Date(0);
  const unknown = await callTool('get_file_info', {path: metadataPath});
  const unknownText = unknown.content.map(item => item.text || '').join('\n');
  assert(unknown.isError !== true && /^created: null$/m.test(unknownText) &&
    /^createdStatus: unavailable_or_epoch$/m.test(unknownText) &&
    /^size: 16$/m.test(unknownText), 'MCP_FILE_INFO_EPOCH_AMBIGUOUS');
  reportedBirthtime = new Date(-1);
  const beforeEpoch = await callTool('get_file_info', {path: metadataPath});
  const beforeEpochText = beforeEpoch.content.map(item => item.text || '').join('\n');
  assert(beforeEpoch.isError !== true && beforeEpochText.includes('created: "1969-12-31T23:59:59.999Z"') &&
    !beforeEpochText.includes('createdStatus:'), 'MCP_FILE_INFO_PRE_EPOCH_UNCHANGED');
  reportedBirthtime = new Date(0);
  const guarded = await callTool('write_file', {path: metadataPath, content: 'unsafe'});
  assert(guarded.isError === true && fs.readFileSync(metadataPath, 'utf8') === 'preserve-content',
    'MCP_FILE_INFO_WRITE_GUARD_UNCHANGED');
} finally {
  fsPromises.stat = originalStat;
}

const editPath = '/workspace/edit-conflict.txt';
const editBefore = 'same\nsame\nunique-before\n';
fs.writeFileSync(editPath, editBefore);
const conflict = await callTool('edit_block', {
  file_path: editPath, old_string: 'same', new_string: 'wrong', expected_replacements: 1,
});
assert(conflict.isError === true && fs.readFileSync(editPath, 'utf8') === editBefore,
       'MCP_EDIT_CONFLICT_ERROR_NO_WRITE');
const edited = await callTool('edit_block', {
  file_path: editPath, old_string: 'unique-before', new_string: 'unique-after', expected_replacements: 1,
});
assert(edited.isError !== true &&
       fs.readFileSync(editPath, 'utf8') === 'same\nsame\nunique-after\n',
       'MCP_EDIT_UNIQUE_SUCCESS');

// Drive the real compiled search manager with a controlled, real child process.
// Timing/output are synthetic; SIGTERM, result retention and MCP flags are real.
const originalSpawn = childProcess.spawn;
const searchText = result => result.content.map(item => item.text || '').join('\n');
async function finishSearch(started) {
  const id = searchText(started).match(/session: (\S+)/)?.[1];
  if (!id) throw Error('SEARCH_SESSION_ID_MISSING');
  for (let i = 0; i < 100; i++) {
    const result = await callTool('get_more_search_results', {sessionId:id,offset:0,length:10});
    if (/Status: (COMPLETED|INCOMPLETE)|encountered an error:/.test(searchText(result))) {
      await callTool('stop_search', {sessionId:id});
      return result;
    }
    await pause(20);
  }
  throw Error('SEARCH_DID_NOT_FINISH');
}
const searchArgs = {path:'/workspace',pattern:'timeout-fixture',searchType:'content',
  filePattern:'timeout-fixture.txt',literalSearch:true};
try {
  for (const partial of [false,true]) {
    const match = {type:'match',data:{path:{text:'/workspace/timeout-fixture.txt'},
      line_number:1,lines:{text:'partial-marker\n'}}};
    const program = (partial ? `process.stdout.write(${JSON.stringify(JSON.stringify(match)+'\n')});` : '') +
      'setInterval(()=>{},1000);';
    childProcess.spawn = (_binary,_args,options) => originalSpawn(process.execPath,['-e',program],options);
    syncBuiltinESMExports();
    const started = await callTool('start_search', {...searchArgs,timeout_ms:partial?500:1});
    if (!partial) assert(started.isError === true && searchText(started).includes('INCOMPLETE'),
      'MCP_SEARCH_INITIAL_TIMEOUT_ERROR');
    const result = await finishSearch(started);
    assert(result.isError === true && !searchText(result).includes('✅ Search completed.'),
      partial?'MCP_SEARCH_PARTIAL_TIMEOUT_ERROR':'MCP_SEARCH_EMPTY_TIMEOUT_ERROR');
    if (partial) assert(searchText(result).includes('partial-marker') &&
      searchText(result).includes('INCOMPLETE'), 'MCP_SEARCH_TIMEOUT_RETAINS_PARTIAL_RESULTS');
  }
} finally {
  childProcess.spawn = originalSpawn;
  syncBuiltinESMExports();
}
fs.mkdirSync('/workspace/search-complete');
fs.writeFileSync('/workspace/search-complete/plain.txt','real-ripgrep-marker\n');
for (const [pattern,expected] of [['real-ripgrep-marker','real-ripgrep-marker'],['absent-marker','No matches found.']]) {
  const result = await finishSearch(await callTool('start_search', {...searchArgs,
    path:'/workspace/search-complete',filePattern:'plain.txt',pattern,timeout_ms:5000}));
  assert(result.isError !== true && searchText(result).includes(expected) &&
    searchText(result).includes('✅ Search completed.'),
    pattern==='absent-marker'?'MCP_SEARCH_TRUE_NO_MATCH_SUCCESS':'MCP_SEARCH_REAL_RIPGREP_SUCCESS');
}

const forbidden = await callTool('write_file', {
  path: '/opt/brc/package.json', content: 'unapproved-tampering',
  mode: 'rewrite',
});
assert(forbidden.isError === true, 'MCP_READONLY_SOURCE_WRITE_DENIED');
const outside = await callTool('read_file', { path: '/host-private/owner-secret.txt' });
assert(outside.isError === true, 'MCP_UNMOUNTED_SECRET_READ_DENIED');

// Run the SAME general-purpose shell tool that would be dangerous if its OS
// identity had production privileges. Even a Node subprocess must be isolated.
const childProgram = String.raw`
import fs from 'node:fs';
import net from 'node:net';
import { writeFileSync } from 'node:fs';
const canWrite = (p) => {
  try { fs.writeFileSync(p, 'tamper'); return true; }
  catch { return false; }
};
const networkBlocked = await new Promise((resolve) => {
  const sock = net.connect({ host: '1.1.1.1', port: 443 });
  sock.once('connect', () => { sock.destroy(); resolve(false); });
  sock.once('error', () => resolve(true));
  sock.setTimeout(1500, () => { sock.destroy(); resolve(false); });
});
const report = {
  workspaceWritable: canWrite('/workspace/subprocess-ok.txt'),
  mountedSourceReadOnly: !canWrite('/opt/brc/package.json'),
  ownerHostSecretUnreachable: !fs.existsSync('/host-private/owner-secret.txt'),
  rootHomeUnreadable: (() => { try { fs.readdirSync('/root'); return false; } catch { return true; } })(),
  egressBlocked: networkBlocked
};
writeFileSync('/workspace/child-result.json', JSON.stringify(report));
`;
fs.writeFileSync('/workspace/child-worker.mjs', childProgram);
const started = await callTool('start_process', {
  command: 'node /workspace/child-worker.mjs',
  shell: '/bin/sh',
  timeout_ms: 10000,
});
assert(started.isError !== true, 'MCP_REAL_TERMINAL_DISPATCH');
let child = null;
for (let i = 0; i < 40; i++) {
  if (fs.existsSync('/workspace/child-result.json')) {
    child = JSON.parse(fs.readFileSync('/workspace/child-result.json', 'utf8'));
    break;
  }
  await pause(250);
}
assert(child !== null, 'MCP_CHILD_PROCESS_FINISHED');
if (child) for (const [k, value] of Object.entries(child)) {
  assert(value === true, 'OS_SHELL_' + k.toUpperCase());
}
if (failures.length) {
  console.error('OS_SANDBOX_NEGATIVE_FAILED=' + failures.join(','));
  process.exitCode = 1;
} else console.log('HERMES_BRC_LINUX_OS_SANDBOX_E2E=PASS');
// The resident search manager keeps a maintenance interval alive.
await new Promise(resolve => process.stdout.write('', resolve));
process.exit(failures.length ? 1 : 0);
