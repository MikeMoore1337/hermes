#!/usr/bin/env node
// Genuine patched BRC tool dispatcher exercised under kernel/container OS
// constraints. Runs only in a disposable Docker CI namespace (#371).
import fs from 'node:fs';
import { setTimeout as pause } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';

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
