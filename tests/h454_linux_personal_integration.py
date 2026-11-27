"""Explicit Linux-only integration checks; requires a disposable BRC runtime."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from device_fabric import linux_personal_worker as worker
from device_fabric.linux_personal_sandbox import SandboxDenied, open_project, start


class SandboxIntegrationTests(unittest.TestCase):
    def test_original_directory_write_and_outside_symlink_denial(self):
        self.assertNotEqual(os.geteuid(), 0)
        with tempfile.TemporaryDirectory(prefix='h454-personal-test-') as base:
            root, bundle = Path(base) / 'project', Path(base) / 'bundle'
            root.mkdir()
            bundle.mkdir()
            outside = Path(base) / 'outside'
            outside.write_text('outside-fixture')
            (root / 'escape').symlink_to(outside)
            executable = bundle / 'run'
            executable.write_text('#!/bin/sh\n'
                'printf ok > /workspace/result\n'
                '! cat /workspace/escape >/dev/null 2>&1 || exit 2\n'
                '! cat /etc/shadow >/dev/null 2>&1 || exit 3\n'
                'printf DONE\n')
            executable.chmod(0o755)
            process = start(str(root), str(bundle), ['/opt/commander/run'])
            output, _ = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(output, b'DONE')
            self.assertEqual((root / 'result').read_text(), 'ok')
            self.assertEqual(outside.read_text(), 'outside-fixture')

    def test_project_open_rejects_symlinked_ancestor(self):
        with tempfile.TemporaryDirectory(prefix='h454-personal-test-') as base:
            actual = Path(base) / 'actual'
            actual.mkdir()
            (actual / 'project').mkdir()
            (Path(base) / 'link').symlink_to(actual, target_is_directory=True)
            with self.assertRaises(SandboxDenied):
                open_project(str(Path(base) / 'link' / 'project'))


class LinuxPersonalSessionIntegrationTests(unittest.TestCase):
    def test_real_dispatcher_write_terminal_and_denial_via_fixture_relay(self):
        class Socket:
            def __init__(self):
                self.sent = []
                self.frames = [
                    {'type': 'welcome', 'protocol': 1, 'relayVersion': 'fixture', 'serverTime': 1},
                    {'type': 'call', 'id': 'w', 'tool': 'write_file', 'args': {
                        'path': '/workspace/probe.txt', 'content': 'fixture-data', 'mode': 'rewrite'}},
                    {'type': 'call', 'id': 't', 'tool': 'start_process', 'args': {
                        'command': 'pwd', 'timeout_ms': 5000}},
                    {'type': 'call', 'id': 'x', 'tool': 'read_file', 'args': {'path': '/etc/shadow'}},
                ]
            def __enter__(self): return self
            def __exit__(self, *_args): return None
            def send(self, data): self.sent.append(json.loads(data))
            def recv(self, *, timeout):
                if not self.frames:
                    raise TimeoutError()
                return json.dumps(self.frames.pop(0))

        runtime = os.environ['H454_TEST_BRC_RUNTIME']
        socket, claims = Socket(), []
        with tempfile.TemporaryDirectory(prefix='h454-project-e2e-') as project:
            outcome = worker.serve_once(target='yfc-vps',
                device_id='h454-linux-personal-yfc-' + 'a' * 32, bearer='brc_dev_' + 'b' * 64,
                project=project, bundle=runtime, connector=lambda *_a, **_k: socket,
                is_active=lambda: True, claim_call=lambda ident: claims.append(ident) or True)
            self.assertEqual(outcome, 'idle_timeout')
            self.assertEqual(claims, ['w', 't', 'x'])
            self.assertEqual((Path(project) / 'probe.txt').read_text(), 'fixture-data')
        results = {frame['id']: frame['result'] for frame in socket.sent if frame['type'] == 'result'}
        self.assertIsNot(results['w'].get('isError'), True)
        self.assertIn('/workspace', json.dumps(results['t']))
        self.assertIs(results['x'].get('isError'), True)


if __name__ == '__main__':
    unittest.main()
