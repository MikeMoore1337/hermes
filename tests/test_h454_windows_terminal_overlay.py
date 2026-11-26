"""Terminal overlay preserves existing output handling and rejects drift."""
from hashlib import sha256
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from scripts import h454_windows_terminal_overlay as overlay


PROCESS = ("processStateMessage = `\\n✅ Process completed with exit code ${result.exitCode}${runtimeStr}`;\n"
           "isError: result.isComplete && result.exitCode !== 0\n").encode()
MANAGER = ("import { spawn } from 'child_process';\n"
           "export const MAX_HERMES_TIMING_EVENTS = 128;\n"
           "        const childProcess = spawn(spawnConfig.executable, spawnConfig.args, spawnOptions);\n"
           "        try {\n            if (!session.process.kill('SIGINT')) {\n"
           "childProcess.on('close', (code) => {\n"
           "if (!resolved)\n                waitTimer = setTimeout\n").encode()
REFERENCE = ("const h454LinuxSessions = new WeakMap();\n"
             "export const MAX_HERMES_TIMING_EVENTS\n"
             "        let h454Mode = null;\n"
             "        const childProcess = spawn(spawnConfig.executable, spawnConfig.args, spawnOptions);\n"
             "        let output = '';\n"
             "    forceTerminate(pid) {\n"
             "            if (process.platform === 'linux') {\n"
             "                return session.process.kill('SIGTERM');\n"
             "            }\n"
             "            if (!session.process.kill('SIGINT')) {\n"
             "    listActiveSessions() {\n").encode()


class WindowsTerminalOverlayTests(unittest.TestCase):
    def hashes(self, process=PROCESS, manager=MANAGER, reference=REFERENCE):
        return mock.patch.multiple(overlay, PROCESS_SHA256=sha256(process).hexdigest(),
                                   MANAGER_SHA256=sha256(manager).hexdigest(),
                                   REFERENCE_SHA256=sha256(reference).hexdigest())

    def test_pinned_source_adds_supervisor_and_preserves_close_and_timer(self):
        with self.hashes():
            tools, manager = overlay.build(PROCESS, MANAGER, REFERENCE)
        self.assertIn(b'Process failed or was terminated', tools)
        self.assertIn(b'h454LinuxSessions', manager)
        self.assertIn(b"childProcess.on('close', (code) => {", manager)
        self.assertIn(b'if (!resolved)\n                waitTimer = setTimeout', manager)

    def test_unpinned_source_is_refused(self):
        with self.assertRaisesRegex(overlay.OverlayDenied, 'source_hash_mismatch'):
            overlay.build(b'changed', MANAGER, REFERENCE)

    def test_ambiguous_anchor_is_refused_even_if_pinned(self):
        duplicate = MANAGER + b'export const MAX_HERMES_TIMING_EVENTS = 128;\n'
        with self.hashes(manager=duplicate), self.assertRaisesRegex(overlay.OverlayDenied, 'source_drift'):
            overlay.build(PROCESS, duplicate, REFERENCE)

    def test_cli_never_overwrites_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = []
            for i, data in enumerate((PROCESS, MANAGER, REFERENCE)):
                path = root / str(i)
                path.write_bytes(data)
                sources.append(path)
            output = root / 'existing'
            output.mkdir()
            sentinel = output / 'terminal-manager.js'
            sentinel.write_text('preserve')
            argv = ['overlay', '--process', str(sources[0]), '--manager', str(sources[1]),
                    '--reference', str(sources[2]), '--output-dir', str(output)]
            with self.hashes(), mock.patch.object(sys, 'argv', argv), mock.patch('sys.stderr', new_callable=io.StringIO):
                self.assertEqual(overlay.main(), 2)
            self.assertEqual(sentinel.read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()
