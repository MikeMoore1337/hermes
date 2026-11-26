// Trusted local launcher for the personal Windows file adapter. The caller
// chooses the pinned dispatcher and private state directory; no relay bearer
// or remote argument is accepted by this launcher.
import path from 'node:path';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { fileURLToPath } from 'node:url';

function absoluteLocal(value) {
  if (typeof value !== 'string' || value.length > 2048 || !/^[A-Za-z]:[\\/]/.test(value)) return false;
  const parts = value.slice(3).split(/[\\/]/);
  return parts.length > 0 && parts.every(part => part && part !== '.' && part !== '..'
    && !/[<>:"|?*\x00-\x1f]/.test(part) && !/[ .]$/.test(part));
}

try {
  const [, , dispatcher, stateDirectory] = process.argv;
  if (process.platform !== 'win32' || process.argv.length !== 4
      || !process.execArgv.includes('--preserve-symlinks-main')
      || !process.execArgv.includes('--preserve-symlinks')
      || !absoluteLocal(dispatcher) || path.win32.basename(dispatcher) !== 'dispatcher.js'
      || !absoluteLocal(stateDirectory)) throw new Error('START_DENIED');

  // The upstream system-info module probes Python using execSync at import.
  // This file-only adapter does not execute commands; the trusted terminal
  // broker handles those separately. Avoid synchronous child processes here.
  const child = createRequire(import.meta.url)('node:child_process');
  child.execSync = () => { throw new Error('H454_ADAPTER_SYNC_PROCESS_UNAVAILABLE'); };
  syncBuiltinESMExports();
  process.env.BRC_HOME = stateDirectory;
  const adapter = fileURLToPath(new URL('./h454_windows_personal_dispatcher.mjs', import.meta.url));
  process.argv.splice(1, 3, adapter, dispatcher);
  await import(new URL('./h454_windows_personal_dispatcher.mjs', import.meta.url).href);
} catch {
  process.stderr.write('H454_PERSONAL_ADAPTER_LAUNCH_DENIED\n');
  process.exitCode = 2;
}
