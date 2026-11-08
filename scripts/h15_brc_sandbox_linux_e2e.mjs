#!/usr/bin/env node
// Genuine patched BRC tool dispatcher exercised under kernel/container OS
// constraints. Runs only in a disposable Docker CI namespace (#371).
import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import { setTimeout as pause } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { EventEmitter } from 'node:events';

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

const binaryPath = '/workspace/unsupported-binary.bin';
fs.writeFileSync(binaryPath, Buffer.from([0, 255, 0, 17, 0, 128, 4, 0]));
const binary = await callTool('read_file', {path: binaryPath});
const binaryText = binary.content.map(item => item.text || '').join('\n');
assert(binary.isError === true && binaryText.includes('Cannot read binary file as text:'),
       'MCP_BINARY_READ_IS_ERROR');
const textRead = await callTool('read_file', {path: '/workspace/allowed.txt'});
assert(textRead.isError !== true && textRead.content.some(item => item.text?.includes('approved-workspace-data')),
       'MCP_TEXT_READ_UNCHANGED');
const mixedRead = await callTool('read_multiple_files', {paths: ['/workspace/allowed.txt', binaryPath]});
const mixedText = mixedRead.content.map(item => item.text || '').join('\n');
assert(mixedRead.isError === true && mixedText.includes('approved-workspace-data') &&
       mixedText.includes(`${binaryPath}: Error - Cannot read binary file as text:`),
       'MCP_MIXED_READ_REPORTS_BINARY_ERROR');
const cleanRead = await callTool('read_multiple_files', {paths: ['/workspace/allowed.txt']});
assert(cleanRead.isError !== true && cleanRead.content.some(item => item.text?.includes('approved-workspace-data')),
       'MCP_MULTIPLE_TEXT_READ_UNCHANGED');
const imagePath = '/workspace/supported-image.png';
fs.writeFileSync(imagePath, Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9oQ0WQAAAABJRU5ErkJggg==', 'base64'));
const image = await callTool('read_file', {path: imagePath});
assert(image.isError !== true && image.content.some(item => item.type === 'image' && item.mimeType === 'image/png'),
       'MCP_IMAGE_READ_UNCHANGED');
const allFailed = await callTool('read_multiple_files', {
  paths: ['/workspace/h454-missing-first', '/workspace/h454-missing-second'],
});
assert(allFailed.isError === true && allFailed.content.some(item =>
  item.text?.includes('Error -')), 'MCP_MULTIPLE_ALL_FAILED_IS_ERROR');
const imageWithError = await callTool('read_multiple_files', {
  paths: [imagePath, '/workspace/h454-missing-third'],
});
assert(imageWithError.isError === true &&
  imageWithError.content.some(item => item.type === 'image' && item.mimeType === 'image/png') &&
  imageWithError.content.some(item => item.text?.includes('Error -')),
  'MCP_MULTIPLE_IMAGE_FAILURE_IS_ERROR');
const emptyBatch = await callTool('read_multiple_files', {paths:[]});
assert(emptyBatch.isError === true && emptyBatch.content.some(item =>
  item.text?.includes('HERMES_EMPTY_FILE_BATCH')), 'MCP_MULTIPLE_EMPTY_BATCH_REFUSED');
assert((await callTool('read_multiple_files', {paths:'invalid'})).isError === true,
  'MCP_MULTIPLE_INVALID_SCHEMA_REFUSED');

// OS-level isolation, not an arbitrary /tmp denylist, is the security boundary.
// On Debian 12, an unprivileged sandbox user must not read root-owned shadow.
// A symlink within /workspace must not elevate the effective OS credentials.
const h454ReadLink = '/workspace/h454-os-denied-symlink';
const h454Protected = '/etc/shadow';
fs.symlinkSync(h454Protected, h454ReadLink);
try {
  const protectedDirect = await callTool('read_file', {path:h454Protected});
  const protectedLink = await callTool('read_file', {path:h454ReadLink});
  const protectedMixed = await callTool('read_multiple_files', {
    paths:[imagePath,h454Protected,h454ReadLink],
  });
  assert(protectedDirect.isError === true && protectedLink.isError === true &&
    protectedMixed.isError === true && protectedMixed.content.some(item =>
      item.type === 'image' && item.mimeType === 'image/png'),
    'MCP_OS_PROTECTED_READ_AND_SYMLINK_DENIED_IMAGE_PRESERVED');
} finally {
  fs.unlinkSync(h454ReadLink);
}

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

// Hold a real edit after its read so conflicting MCP mutations overlap.
const racePath = '/workspace/mutation-race.txt';
fs.writeFileSync(racePath, 'before\n');
const originalReadFile = fsPromises.readFile;
let readObserved, releaseRead, held = false;
const readStarted = new Promise(resolve => { readObserved = resolve; });
const readGate = new Promise(resolve => { releaseRead = resolve; });
let firstEdit;
try {
  fsPromises.readFile = async (...args) => {
    const value = await originalReadFile(...args);
    if (!held && args[0] === racePath && args[1]?.signal) {
      held = true;
      readObserved();
      await readGate;
    }
    return value;
  };
  firstEdit = callTool('edit_block', {
    file_path: racePath, old_string: 'before', new_string: 'A-after', expected_replacements: 1,
  });
  await Promise.race([readStarted, pause(5000).then(() => { throw Error('MUTATION_BARRIER_TIMEOUT'); })]);
  for (const [name, args] of [
    ['edit_block', {file_path: racePath, old_string: 'before', new_string: 'B-after', expected_replacements: 1}],
    ['write_file', {path: '/workspace/blocked.txt', content: 'wrong', mode: 'rewrite'}],
    ['move_file', {source: racePath, destination: '/workspace/blocked-move.txt'}],
    ['create_directory', {path: '/workspace/blocked-dir'}],
    ['write_pdf', {path: '/workspace/blocked.pdf', content: 'wrong'}],
  ]) {
    const blocked = await callTool(name, args);
    const text = blocked.content.map(item => item.text || '').join('\n');
    assert(blocked.isError === true && text.includes('HERMES_FILE_MUTATION_BUSY'),
      'MCP_MUTATION_BUSY_' + name.toUpperCase());
  }
  const info = await callTool('get_file_info', {path: racePath});
  assert(info.isError !== true, 'MCP_READ_DURING_MUTATION');
} finally {
  releaseRead();
  fsPromises.readFile = originalReadFile;
}
const firstResult = await firstEdit;
assert(firstResult.isError !== true && fs.readFileSync(racePath, 'utf8') === 'A-after\n' &&
  !fs.existsSync('/workspace/blocked.txt') && !fs.existsSync('/workspace/blocked-move.txt') &&
  !fs.existsSync('/workspace/blocked-dir') && !fs.existsSync('/workspace/blocked.pdf'),
  'MCP_MUTATION_FIRST_WRITE_PRESERVED');
const invalidEdit = await callTool('edit_block', {});
const afterError = await callTool('write_file', {path:'/workspace/unlocked.txt', content:'ok', mode:'rewrite'});
assert(invalidEdit.isError === true && afterError.isError !== true &&
  fs.readFileSync('/workspace/unlocked.txt', 'utf8') === 'ok', 'MCP_MUTATION_GUARD_RELEASED_ON_ERROR');

// Synthetic session objects exercise the actual manager without signalling any OS process.
const terminalPath = source.replace('/dispatcher.js', '/core/terminal-manager.js');
const { terminalManager } = await import(pathToFileURL(terminalPath).href);

// Synthetic stream chunks exercise the compiled manager and MCP formatter;
// no OS process or production session is signalled.
const timingSpawn = childProcess.spawn;
let timingChild;
let timingChunks = 130;
try {
  childProcess.spawn = () => {
    timingChild = new EventEmitter();
    timingChild.pid = 2147483600;
    timingChild.stdout = new EventEmitter();
    timingChild.stderr = new EventEmitter();
    timingChild.stdin = {destroyed:false, write:()=>true};
    setImmediate(() => {
      for (let i = 0; i < timingChunks; i++) {
        (i % 2 ? timingChild.stderr : timingChild.stdout).emit('data', Buffer.from('event\n'));
      }
      timingChild.stdout.emit('data', Buffer.from('>>> '));
    });
    return timingChild;
  };
  syncBuiltinESMExports();
  const timing = await terminalManager.executeCommand('synthetic', 1000, '/bin/sh', true);
  const recorded = JSON.stringify(timing.timingInfo?.outputEvents);
  assert(timing.timingInfo?.outputEvents?.length === 128 && timing.timingInfo.outputEventsTruncated === true &&
    !timing.timingInfo.outputEvents.some(event => event.matchedPattern), 'TIMING_BOUNDED_BEFORE_REPLY');
  timingChild.stdout.emit('data', Buffer.from('late>'));
  timingChild.stderr.emit('data', Buffer.from('late-error\n'));
  assert(JSON.stringify(timing.timingInfo?.outputEvents) === recorded, 'TIMING_STABLE_AFTER_REPLY');
  timingChild.emit('exit', 0);

  const mcpTiming = await callTool('start_process', {
    command:'node -e "0"', shell:'/bin/sh', timeout_ms:1000, verbose_timing:true,
  });
  assert(mcpTiming.isError !== true && mcpTiming.content.some(item =>
    item.text?.includes('HERMES_TIMING_EVENTS_TRUNCATED') && item.text.includes('128 recorded')),
    'MCP_TIMING_TRUNCATION_DISCLOSED');
  timingChild.emit('exit', 0);

  timingChunks = 2;
  const brief = await terminalManager.executeCommand('synthetic', 1000, '/bin/sh', true);
  assert(brief.timingInfo?.outputEvents?.length === 3 && !brief.timingInfo.outputEventsTruncated &&
    brief.timingInfo.outputEvents[2].matchedPattern === 'quick_pattern', 'TIMING_SHORT_TRACE_UNCHANGED');
  timingChild.emit('exit', 0);
} finally {
  childProcess.spawn = timingSpawn;
  syncBuiltinESMExports();
}

// Accelerate only the synthetic poll clock; real interaction still uses 50 ms.
const interval = globalThis.setInterval;
const captureSnapshot = terminalManager.captureOutputSnapshot;
const sendInput = terminalManager.sendInputToProcess;
const getSince = terminalManager.getOutputSinceSnapshot;
let syntheticPolls = 0;
try {
  globalThis.setInterval = (fn, _delay, ...args) => interval(fn, 1, ...args);
  terminalManager.captureOutputSnapshot = () => ({});
  terminalManager.sendInputToProcess = () => true;
  terminalManager.getOutputSinceSnapshot = () => 'x'.repeat(++syntheticPolls);
  const interacted = await callTool('interact_with_process', {
    pid:2147483601, input:'synthetic', timeout_ms:6500, verbose_timing:true,
  });
  assert(interacted.isError !== true && interacted.content.some(item =>
    item.text?.includes('HERMES_TIMING_EVENTS_TRUNCATED') && item.text.includes('128 recorded')),
    'MCP_INTERACTION_TIMING_TRUNCATION_DISCLOSED');
} finally {
  globalThis.setInterval = interval;
  terminalManager.captureOutputSnapshot = captureSnapshot;
  terminalManager.sendInputToProcess = sendInput;
  terminalManager.getOutputSinceSnapshot = getSince;
}

const absentTermination = await callTool('force_terminate', {pid:2147483647});
const absentText = absentTermination.content.map(item => item.text || '').join('\n');
assert(absentTermination.isError === true && absentText.includes('No active session or unable to initiate'),
  'MCP_TERMINATE_MISSING_IS_ERROR');
const fakePids = [2147483646, 2147483645, 2147483644, 2147483643, 2147483642, 2147483641];
if (fakePids.some(pid => terminalManager.sessions.has(pid))) throw Error('SYNTHETIC_PID_OCCUPIED');
const oldSignals = [], replacementSignals = [], sameSignals = [], rejectedSignals = [];
const oldSession = {process:{kill:signal => {oldSignals.push(signal); return true;}}};
const replacementSession = {process:{kill:signal => {replacementSignals.push(signal); return true;}}};
const sameSession = {process:{kill:signal => {sameSignals.push(signal); return true;}}};
const failingSession = {process:{kill:signal => {if (signal === 'SIGKILL') throw Error('synthetic failure'); return true;}}};
const refusedSession = {process:{kill:() => {throw Error('synthetic refusal');}}};
const rejectedSession = {process:{kill:signal => {rejectedSignals.push(signal); return false;}}};
const rejectedEscalationSession = {process:{kill:signal => signal !== 'SIGKILL'}};
const originalConsoleError = console.error;
const originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
let escalationLogs = 0;
try {
  Object.defineProperty(process, 'platform', {value:'win32'});
  console.error = (...args) => {
    if (args[0] === 'HERMES_TERMINATION_ESCALATION_FAILED') escalationLogs++;
    else originalConsoleError(...args);
  };
  terminalManager.sessions.set(fakePids[0], oldSession);
  const initiated = await callTool('force_terminate', {pid:fakePids[0]});
  terminalManager.sessions.set(fakePids[0], replacementSession);
  terminalManager.sessions.set(fakePids[1], sameSession);
  const sameInitiated = await callTool('force_terminate', {pid:fakePids[1]});
  terminalManager.sessions.set(fakePids[2], failingSession);
  const failingInitiated = await callTool('force_terminate', {pid:fakePids[2]});
  terminalManager.sessions.set(fakePids[3], refusedSession);
  const refused = await callTool('force_terminate', {pid:fakePids[3]});
  terminalManager.sessions.set(fakePids[4], rejectedSession);
  const rejected = await callTool('force_terminate', {pid:fakePids[4]});
  terminalManager.sessions.set(fakePids[5], rejectedEscalationSession);
  const rejectedEscalation = await callTool('force_terminate', {pid:fakePids[5]});
  await pause(1200);
  assert(initiated.isError !== true && oldSignals.join(',') === 'SIGINT' && replacementSignals.length === 0,
    'MCP_TERMINATE_REPLACEMENT_SESSION_UNTOUCHED');
  assert(initiated.content.some(item => item.text?.includes('descendants may remain')),
    'MCP_TERMINATE_SCOPE_DISCLOSED');
  assert(sameInitiated.isError !== true && sameSignals.join(',') === 'SIGINT,SIGKILL',
    'MCP_TERMINATE_SAME_SESSION_ESCALATES');
  assert(failingInitiated.isError !== true && rejectedEscalation.isError !== true && escalationLogs === 2,
    'MCP_TERMINATE_ESCALATION_ERRORS_CONTAINED');
  assert(refused.isError === true, 'MCP_TERMINATE_REFUSAL_IS_ERROR');
  assert(rejected.isError === true && rejectedSignals.join(',') === 'SIGINT',
    'MCP_TERMINATE_FALSE_SIGNAL_IS_ERROR');
} finally {
  console.error = originalConsoleError;
  Object.defineProperty(process, 'platform', originalPlatform);
  for (const pid of fakePids) terminalManager.sessions.delete(pid);
}
terminalManager.sessions.set(fakePids[0], {process:{pid:fakePids[0]}});
try {
  const forged = await callTool('force_terminate', {pid:fakePids[0]});
  assert(forged.isError === true, 'MCP_TERMINATE_UNTRACKED_GROUP_REFUSED');
} finally { terminalManager.sessions.delete(fakePids[0]); }

const failedProcess = await callTool('start_process', {command:'exit 7',shell:'/bin/sh',timeout_ms:3000});
const failedText = failedProcess.content.map(item => item.text || '').join('\n');
const failedPid = Number(failedText.match(/Process started with PID (\d+)/)?.[1]);
assert(failedProcess.isError === true && failedText.includes('Process exited with code 7.'),
  'MCP_TERMINAL_START_EXIT_FAILURE');
if (!Number.isSafeInteger(failedPid) || failedPid <= 1) throw Error('FAILED_PROCESS_PID');
const failedOutput = await callTool('read_process_output', {pid:failedPid,timeout_ms:100});
assert(failedOutput.isError === true && failedOutput.content.some(item =>
  item.text?.includes('Process failed or was terminated (exit code 7)')),
  'MCP_TERMINAL_OUTPUT_EXIT_FAILURE');
const successfulProcess = await callTool('start_process', {command:'exit 0',shell:'/bin/sh',timeout_ms:3000});
assert(successfulProcess.isError !== true && successfulProcess.content.some(item =>
  item.text?.includes('Process exited with code 0.')), 'MCP_TERMINAL_START_EXIT_SUCCESS');
const missingCommand = await callTool('start_process', {
  command:'/hermes-fixture-command-does-not-exist',shell:'/bin/sh',timeout_ms:3000,
});
assert(missingCommand.isError === true && missingCommand.content.some(item =>
  item.text?.includes('Process exited with code 127.')), 'MCP_TERMINAL_MISSING_COMMAND_IS_ERROR');

// Two real isolated sessions: killing one group must not affect the other.
const treeWorker = '/workspace/h454-session-worker.mjs';
const childPidFile = '/workspace/h454-session-child.pid';
fs.writeFileSync(treeWorker, `import {spawn} from 'node:child_process';
import {writeFileSync} from 'node:fs';
const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});
writeFileSync('${childPidFile}',String(child.pid),{flag:'wx'});
setInterval(()=>{},1000);`);
const pidFrom = result => Number(result.content.map(item => item.text || '').join('\n').match(/Process started with PID (\d+)/)?.[1]);
const running = pid => {
  try { return !/^\d+ \(.*\) Z /.test(fs.readFileSync(`/proc/${pid}/stat`, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT' || error.code === 'ESRCH') return false; throw error; }
};
const readFileSync = fs.readFileSync;
try {
  fs.readFileSync = () => { throw Object.assign(new Error('process vanished'), {code:'ESRCH'}); };
  assert(!running(2147483600), 'MCP_PROCESS_VANISHED_DURING_STAT');
} finally { fs.readFileSync = readFileSync; }
const usesSupervisor = fs.existsSync('/usr/bin/python3') ||
  (process.arch === 'x64' && fs.existsSync('/usr/bin/perl'));
if (process.env.H454_EXPECT_PERL_SUPERVISOR === '1') {
  assert(process.arch === 'x64' && !fs.existsSync('/usr/bin/python3') &&
    fs.existsSync('/usr/bin/perl') && fs.existsSync('/usr/bin/setsid'),
    'MCP_PERL_ONLY_SUPERVISOR_FIXTURE');
}
let firstPid, secondPid, descendantPid;
try {
  const first = await callTool('start_process', {command:`node ${treeWorker}`,shell:'/bin/sh',timeout_ms:500});
  const second = await callTool('start_process', {command:'sleep 30',shell:'/bin/sh',timeout_ms:500});
  firstPid = pidFrom(first); secondPid = pidFrom(second);
  if (first.isError || second.isError || !Number.isSafeInteger(firstPid) || !Number.isSafeInteger(secondPid) ||
      firstPid <= 1 || secondPid <= 1 || firstPid === secondPid) throw Error('SESSION_START_FAILED');
  for (let i=0; i<50 && !fs.existsSync(childPidFile); i++) await pause(50);
  descendantPid = Number(fs.readFileSync(childPidFile, 'utf8'));
  if (!Number.isSafeInteger(descendantPid) || descendantPid <= 1 || !running(descendantPid))
    throw Error('DESCENDANT_NOT_RUNNING');

  if (!usesSupervisor) assert(first.content.some(item =>
    item.text?.includes('Termination is limited to the process group; detached descendants may remain.')),
    'MCP_TERMINAL_GROUP_ONLY_WARNING');
  const target = terminalManager.sessions.get(firstPid).process;
  const originalKill = process.kill, originalChildKill = target.kill;
  try {
    if (usesSupervisor) target.kill = () => { throw Error('synthetic denied signal'); };
    else process.kill = (pid, signal) => {
        if (pid === -firstPid && signal === 'SIGKILL') throw Error('synthetic denied signal');
        return originalKill(pid, signal);
      };
    const refused = await callTool('force_terminate', {pid:firstPid});
    assert(refused.isError === true && running(descendantPid), 'MCP_GROUP_SIGNAL_FAILURE_IS_ERROR');
  } finally { process.kill = originalKill; target.kill = originalChildKill; }

  const terminated = await callTool('force_terminate', {pid:firstPid});
  for (let i=0; i<60 && running(descendantPid); i++) await pause(50);
  assert(terminated.isError !== true && !running(descendantPid), 'MCP_TERMINATE_REAL_CHILD_GROUP');
  assert(running(secondPid), 'MCP_TERMINATE_OTHER_SESSION_UNTOUCHED');
} finally {
  for (const pid of [firstPid, secondPid]) {
    if (Number.isSafeInteger(pid) && pid > 1 && terminalManager.sessions.has(pid))
      await callTool('force_terminate', {pid});
  }
}

let interactivePid;
try {
  const started = await callTool('start_process', {
    command:'read answer; printf "H454_INTERACTIVE_%s\\n" "$answer"; sleep 2',
    shell:'/bin/sh', timeout_ms:500,
  });
  interactivePid = pidFrom(started);
  if (!Number.isSafeInteger(interactivePid) || interactivePid <= 1) throw Error('INTERACTIVE_START');
  const response = await callTool('interact_with_process', {pid:interactivePid,input:'fixture',timeout_ms:1500});
  assert(response.isError !== true && response.content.some(item => item.text?.includes('H454_INTERACTIVE_fixture')),
    'MCP_TERMINAL_INTERACTIVE_INPUT');
} finally {
  if (Number.isSafeInteger(interactivePid) && interactivePid > 1 && terminalManager.sessions.has(interactivePid))
    await callTool('force_terminate', {pid:interactivePid});
}

if (fs.existsSync('/usr/bin/setsid')) {
  const escapedFile = '/workspace/h454-session-escaped.pid', worker = '/workspace/h454-escaped-worker.mjs';
  const code = `require('node:fs').writeFileSync('${escapedFile}',String(process.pid),{flag:'wx'});setInterval(()=>{},1000)`;
  fs.writeFileSync(worker, `import {spawn} from 'node:child_process';
spawn('/usr/bin/setsid',[process.execPath,'-e',${JSON.stringify(code)}],{stdio:'ignore'});
setInterval(()=>{},1000);`);
  let session, escaped;
  try {
    const started = await callTool('start_process', {command:`node ${worker}`,shell:'/bin/sh',timeout_ms:500});
    session = pidFrom(started);
    if (!Number.isSafeInteger(session) || session <= 1) throw Error('ESCAPED_SESSION_START');
    for (let i=0; i<60 && !fs.existsSync(escapedFile); i++) await pause(50);
    escaped = Number(fs.readFileSync(escapedFile, 'utf8'));
    if (!Number.isSafeInteger(escaped) || escaped <= 1 || !running(escaped)) throw Error('ESCAPED_CHILD_START');
    const result = await callTool('force_terminate', {pid:session});
    if (usesSupervisor) {
      for (let i=0; i<60 && running(escaped); i++) await pause(50);
      assert(result.isError !== true && !running(escaped), 'MCP_TERMINATE_DETACHED_CHILD_WITH_SUPERVISOR');
    } else {
      await pause(200);
      assert(result.content.some(item => item.text?.includes('descendants may remain')),
        'MCP_TERMINATE_NO_SUPERVISOR_LIMIT_DISCLOSED');
    }
  } finally {
    if (Number.isSafeInteger(session) && session > 1 && terminalManager.sessions.has(session))
      await callTool('force_terminate', {pid:session});
    if (Number.isSafeInteger(escaped) && escaped > 1 && running(escaped)) process.kill(escaped, 'SIGKILL');
  }
}

if (usesSupervisor && fs.existsSync('/usr/bin/setsid')) {
  const stopWorker = '/workspace/h454-stopped-worker.mjs';
  const stopMarker = '/workspace/h454-stopped-descendant.pid';
  const child = "require('node:fs').writeFileSync(" + JSON.stringify(stopMarker) +
    ", String(process.pid), {flag:'wx'});setInterval(()=>{},1000)";
  fs.writeFileSync(stopWorker, "import {spawn} from 'node:child_process';\n" +
    "spawn('/usr/bin/setsid',[process.execPath,'-e'," + JSON.stringify(child) +
    "],{stdio:'ignore'});\nsetInterval(()=>{},1000);");
  let stoppedPid, detachedPid, otherPid;
  try {
    const first = await callTool('start_process', {
      command:'node '+stopWorker,shell:'/bin/sh',timeout_ms:500,
    });
    const second = await callTool('start_process', {
      command:'sleep 30',shell:'/bin/sh',timeout_ms:500,
    });
    stoppedPid = pidFrom(first); otherPid = pidFrom(second);
    assert(first.isError !== true && second.isError !== true &&
      Number.isSafeInteger(stoppedPid) && stoppedPid > 1 &&
      Number.isSafeInteger(otherPid) && otherPid > 1, 'MCP_STOPPED_SESSIONS_STARTED');
    for (let i=0; i<80 && !fs.existsSync(stopMarker); i++) await pause(50);
    detachedPid = Number(fs.readFileSync(stopMarker, 'utf8'));
    assert(Number.isSafeInteger(detachedPid) && detachedPid > 1 &&
      running(detachedPid), 'MCP_STOPPED_DETACHED_READY');
    process.kill(stoppedPid, 'SIGSTOP');
    let stopped = false;
    for (let i=0; i<30; i++) {
      const state = fs.readFileSync('/proc/'+stoppedPid+'/stat', 'utf8').split(') ')[1]?.[0];
      if (state === 'T' || state === 't') { stopped=true; break; }
      await pause(20);
    }
    assert(stopped, 'MCP_STOPPED_SUPERVISOR_STOPPED');
    const ended = await callTool('force_terminate', {pid:stoppedPid});
    const message = ended.content.map(item=>item.text||'').join('\n');
    assert(ended.isError !== true && message.includes('initiated termination') &&
      !message.includes('all descendants exited'), 'MCP_TERMINATION_IS_INITIATION_ONLY');
    for (let i=0; i<80 && running(detachedPid); i++) await pause(50);
    assert(!running(detachedPid) && running(otherPid),
      'MCP_STOPPED_SUPERVISOR_DETACHED_REAP_AND_ISOLATION');
  } finally {
    if (Number.isSafeInteger(stoppedPid) && stoppedPid > 1) {
      try { process.kill(stoppedPid, 'SIGCONT'); }
      catch (err) { if (err.code !== 'ESRCH') throw err; }
      if (terminalManager.sessions.has(stoppedPid))
        await callTool('force_terminate', {pid:stoppedPid});
    }
    if (Number.isSafeInteger(otherPid) && otherPid > 1 && terminalManager.sessions.has(otherPid))
      await callTool('force_terminate', {pid:otherPid});
    if (Number.isSafeInteger(detachedPid) && detachedPid > 1 && running(detachedPid))
      process.kill(detachedPid, 'SIGKILL');
  }
}

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

// Symlinks and lexical traversal must never grant access beyond the OS
// sandbox: source is a separate read-only mount, host-private is unmounted.
const hostLink = '/workspace/host-only-symlink';
fs.symlinkSync('/host-private/owner-secret.txt', hostLink);
const hostLinkRead = await callTool('read_file', {path: hostLink});
assert(hostLinkRead.isError === true, 'MCP_UNMOUNTED_SYMLINK_SECRET_READ_DENIED');

const readonlySource = '/opt/brc/package.json';
const beforeSource = fs.readFileSync(readonlySource);
const sourceLink = '/workspace/read-only-source-link';
fs.symlinkSync(readonlySource, sourceLink);
await callTool('write_file', {
  path: sourceLink, content: 'attempted-symlink-source-tampering', mode: 'rewrite',
});
assert(fs.readFileSync(readonlySource).equals(beforeSource),
  'OS_SYMLINK_SOURCE_CANNOT_BE_MODIFIED');

const traversalWrite = await callTool('write_file', {
  path: '/workspace/../opt/brc/package.json',
  content: 'attempted-traversal-tampering', mode: 'rewrite',
});
assert(traversalWrite.isError === true &&
       fs.readFileSync(readonlySource).equals(beforeSource),
       'OS_TRAVERSAL_SOURCE_WRITE_DENIED');


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
