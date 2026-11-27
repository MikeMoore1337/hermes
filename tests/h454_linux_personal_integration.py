"""Explicit Linux-only integration checks; requires a disposable BRC runtime."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from device_fabric import linux_personal_worker as worker
from device_fabric import windows_personal_commander_bundle as bundle_check
from device_fabric.linux_native_replay import LinuxReadReplay
from device_fabric.linux_personal_sandbox import SandboxDenied, open_project, start
from scripts.h454_linux_personal_service import ServiceDenied, _read


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

    def test_private_state_read_rejects_broad_modes_and_symlinks(self):
        with tempfile.TemporaryDirectory(prefix='h454-private-state-') as base:
            value, link = Path(base) / 'state', Path(base) / 'link'
            value.write_bytes(b'fixture')
            value.chmod(0o600)
            self.assertEqual(_read(value, owner=os.geteuid(), modes=(0o600,), maximum=32), b'fixture')
            link.symlink_to(value)
            with self.assertRaises(ServiceDenied):
                _read(link, owner=os.geteuid(), modes=(0o600,), maximum=32)
            value.chmod(0o644)
            with self.assertRaises(ServiceDenied):
                _read(value, owner=os.geteuid(), modes=(0o600,), maximum=32)

    def test_git_trust_covers_only_the_mounted_project(self):
        with tempfile.TemporaryDirectory(prefix='h454-git-scope-') as base:
            project, bundle = Path(base) / 'project', Path(base) / 'bundle'
            project.mkdir()
            bundle.mkdir()
            nested = project / 'nested'
            nested.mkdir()
            for root in (project, nested):
                subprocess.run(['git', '-C', str(root), 'init', '-q'], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            executable = bundle / 'run'
            executable.write_text('#!/bin/sh\n'
                'GIT_TEST_ASSUME_DIFFERENT_OWNER=1 git -C /workspace status --short --branch || exit 2\n'
                'if GIT_TEST_ASSUME_DIFFERENT_OWNER=1 git -C /workspace/nested status >/dev/null 2>&1; '
                'then exit 3; fi\n')
            executable.chmod(0o755)
            process = start(str(project), str(bundle), ['/opt/commander/run'])
            output, _ = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0)
            self.assertIn(b'## ', output)


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
        manifest = bundle_check.manifest(Path(runtime))
        digest = hashlib.sha256(manifest).hexdigest()
        socket, claims = Socket(), []
        with tempfile.TemporaryDirectory(prefix='h454-project-e2e-') as project:
            outcome = worker.serve_once(target='yfc-vps',
                device_id='h454-linux-personal-yfc-' + 'a' * 32, bearer='brc_dev_' + 'b' * 64,
                project=project, bundle=runtime, connector=lambda *_a, **_k: socket,
                is_active=lambda: True, claim_call=lambda ident: claims.append(ident) or True,
                verify_bundle=lambda: bundle_check.verify(Path(runtime), manifest, digest) == digest)
            self.assertEqual(outcome, 'idle_timeout')
            self.assertEqual(claims, ['w', 't', 'x'])
            self.assertEqual((Path(project) / 'probe.txt').read_text(), 'fixture-data')
        results = {frame['id']: frame['result'] for frame in socket.sent if frame['type'] == 'result'}
        self.assertIsNot(results['w'].get('isError'), True)
        self.assertIn('/workspace', json.dumps(results['t']))
        self.assertIs(results['x'].get('isError'), True)

    def test_interactive_terminal_accepts_input_and_can_be_terminated(self):
        class Socket:
            def __init__(self):
                self.sent = []
                self.step = 0
                self.pid = None
            def __enter__(self): return self
            def __exit__(self, *_args): return None
            def send(self, data): self.sent.append(json.loads(data))
            def recv(self, *, timeout):
                self.step += 1
                if self.step == 1:
                    frame = {'type': 'welcome', 'protocol': 1, 'relayVersion': 'fixture', 'serverTime': 1}
                elif self.step == 2:
                    frame = {'type': 'call', 'id': 'start', 'tool': 'start_process',
                             'args': {'command': 'python3 -i', 'timeout_ms': 1000}}
                elif self.step == 3:
                    text = json.dumps(self.sent[-1].get('result', {}))
                    match = re.search(r'Process (\d+)', text)
                    if not match:
                        raise ValueError('fixture process id absent')
                    self.pid = int(match.group(1))
                    frame = {'type': 'call', 'id': 'input', 'tool': 'interact_with_process',
                             'args': {'pid': self.pid, 'input': "print('H454_INTERACTIVE_OK')", 'timeout_ms': 5000}}
                elif self.step == 4:
                    frame = {'type': 'call', 'id': 'stop', 'tool': 'force_terminate', 'args': {'pid': self.pid}}
                else:
                    raise TimeoutError()
                return json.dumps(frame)

        runtime, socket = os.environ['H454_TEST_BRC_RUNTIME'], Socket()
        with tempfile.TemporaryDirectory(prefix='h454-terminal-e2e-') as project:
            result = worker.serve_once(target='yfc-vps',
                device_id='h454-linux-personal-yfc-' + 'a' * 32, bearer='brc_dev_' + 'b' * 64,
                project=project, bundle=runtime, connector=lambda *_a, **_k: socket,
                is_active=lambda: True, claim_call=lambda _ident: True, verify_bundle=lambda: True)
        self.assertEqual(result, 'idle_timeout')
        results = {frame['id']: frame['result'] for frame in socket.sent if frame['type'] == 'result'}
        self.assertIsNot(results['input'].get('isError'), True)
        self.assertIn('H454_INTERACTIVE_OK', json.dumps(results['input']))
        self.assertIsNot(results['stop'].get('isError'), True)

    def test_write_is_not_replayed_after_worker_restart(self):
        class Socket:
            def __init__(self, content):
                self.sent = []
                self.frames = [
                    {'type': 'welcome', 'protocol': 1, 'relayVersion': 'fixture', 'serverTime': 1},
                    {'type': 'call', 'id': 'same-call', 'tool': 'write_file', 'args': {
                        'path': '/workspace/probe.txt', 'content': content, 'mode': 'rewrite'}},
                ]
            def __enter__(self): return self
            def __exit__(self, *_args): return None
            def send(self, data): self.sent.append(json.loads(data))
            def recv(self, *, timeout):
                if not self.frames:
                    raise TimeoutError()
                return json.dumps(self.frames.pop(0))

        runtime = os.environ['H454_TEST_BRC_RUNTIME']
        with tempfile.TemporaryDirectory(prefix='h454-replay-e2e-') as base:
            project, state = Path(base) / 'project', Path(base) / 'state'
            project.mkdir()
            state.mkdir(mode=0o700)
            claims_path = state / 'claims'
            fd = os.open(claims_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(b'H454-READ-REPLAY-v1\n')
            def session(content):
                socket, replay = Socket(content), LinuxReadReplay(claims_path)
                try:
                    return worker.serve_once(target='yfc-vps',
                        device_id='h454-linux-personal-yfc-' + 'a' * 32, bearer='brc_dev_' + 'b' * 64,
                        project=str(project), bundle=runtime, connector=lambda *_a, **_k: socket,
                        is_active=lambda: True, claim_call=replay.claim, verify_bundle=lambda: True)
                finally:
                    replay.close()
            self.assertEqual(session('first'), 'idle_timeout')
            with self.assertRaises(worker.LinuxPersonalWorkerDenied):
                session('must-not-write')
            self.assertEqual((project / 'probe.txt').read_text(), 'first')


if __name__ == '__main__':
    unittest.main()
