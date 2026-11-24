"""Durable read-only replay reservations on disposable Linux state."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

if sys.platform == 'linux':
    from device_fabric.linux_native_replay import LinuxReadReplay, ReplayDenied, _MAGIC


@unittest.skipUnless(sys.platform == 'linux', 'Linux file descriptor semantics')
class LinuxNativeReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / 'claims'
        self.path.write_bytes(_MAGIC)
        self.path.chmod(0o600)

    def test_duplicate_is_denied_after_new_process(self):
        with LinuxReadReplay(self.path) as ledger:
            self.assertTrue(ledger.claim('request-1'))
        code = ('from pathlib import Path; from device_fabric.linux_native_replay import LinuxReadReplay; '
                'import sys; j=LinuxReadReplay(Path(sys.argv[1])); '
                'print("denied" if not j.claim("request-1") else "executed")')
        proc = subprocess.run([sys.executable, '-B', '-c', code, str(self.path)],
                              capture_output=True, text=True, check=True)
        self.assertEqual(proc.stdout.strip(), 'denied')
        self.assertNotIn(b'request-1', self.path.read_bytes())

    def test_concurrent_claim_has_one_winner(self):
        def claim(_):
            with LinuxReadReplay(self.path) as ledger:
                return ledger.claim('same-id')
        with ThreadPoolExecutor(max_workers=8) as workers:
            self.assertEqual(sum(workers.map(claim, range(8))), 1)

    def test_missing_corrupt_and_unsafe_files_are_denied(self):
        for data in (b'', _MAGIC + b'partial', b'X' * len(_MAGIC)):
            self.path.write_bytes(data)
            with self.assertRaises(ReplayDenied):
                LinuxReadReplay(self.path)
        self.path.unlink()
        with self.assertRaises(ReplayDenied):
            LinuxReadReplay(self.path)
        self.path.write_bytes(_MAGIC)
        self.path.chmod(0o644)
        with self.assertRaises(ReplayDenied):
            LinuxReadReplay(self.path)
        self.path.unlink()
        self.path.symlink_to(self.directory / 'other')
        with self.assertRaises(ReplayDenied):
            LinuxReadReplay(self.path)

    def test_invalid_id_does_not_change_file(self):
        with LinuxReadReplay(self.path) as ledger:
            for value in ('', 'bad/identifier', 'x' * 129):
                with self.assertRaises(ReplayDenied):
                    ledger.claim(value)
        self.assertEqual(self.path.read_bytes(), _MAGIC)

    def test_fsync_error_denies_effect_and_never_reuses_written_id(self):
        with LinuxReadReplay(self.path) as ledger:
            with patch('device_fabric.linux_native_replay.os.fsync', side_effect=OSError):
                with self.assertRaises(ReplayDenied):
                    ledger.claim('request-1')
        with LinuxReadReplay(self.path) as ledger:
            self.assertFalse(ledger.claim('request-1'))

    def test_full_ledger_refuses_new_ids(self):
        with patch('device_fabric.linux_native_replay._MAX_RECORDS', 1):
            with LinuxReadReplay(self.path) as ledger:
                self.assertTrue(ledger.claim('request-1'))
                with self.assertRaises(ReplayDenied):
                    ledger.claim('request-2')

    @unittest.skipUnless(getattr(os, 'geteuid', lambda: -1)() == 0,
                         'root-owned isolated source fixture required')
    def test_preopened_ledger_works_under_landlock_without_opening_other_files(self):
        root_parent = tempfile.TemporaryDirectory(dir='/var/lib')
        self.addCleanup(root_parent.cleanup)
        root = Path(root_parent.name) / 'root'
        root.mkdir()
        (root / 'safe.py').write_bytes(b'safe')
        (root / '.env').write_bytes(b'secret')
        script = textwrap.dedent('''
            import resource, sys
            from pathlib import Path
            from device_fabric.linux_native_files import LinuxNativeFiles
            from device_fabric.linux_native_landlock import ReadSnapshot
            from device_fabric import linux_native_landlock as boundary
            from device_fabric.linux_native_replay import LinuxReadReplay
            boundary._trusted_source_fs = lambda _fd: True
            resource.setrlimit(resource.RLIMIT_NOFILE, (32768, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
            with LinuxReadReplay(Path(sys.argv[1])) as ledger, LinuxNativeFiles(root=Path(sys.argv[2]), project='hermes') as files:
                with ReadSnapshot(files) as snap:
                    snap.seal(replay_ledger=ledger)
                    assert ledger.claim('test-id') is True
                    assert ledger.claim('test-id') is False
                    assert files.read_file('safe.py')['size_bytes'] == 4
                    for path in (sys.argv[1], str(Path(sys.argv[2]) / '.env')):
                        try: open(path, 'rb')
                        except PermissionError: pass
                        else: raise AssertionError('landlock path opened')
            print('LANDLOCK_REPLAY=PASS')
        ''')
        proc = subprocess.run([sys.executable, '-B', '-c', script, str(self.path), str(root)],
                              capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), 'LANDLOCK_REPLAY=PASS')

    @unittest.skipUnless(getattr(os, 'geteuid', lambda: -1)() == 0,
                         'root-owned isolated provisioning fixture required')
    def test_provision_creates_private_nonroot_journal_once(self):
        from scripts.h454_native_linux_replay_provision import provision
        parent = Path('/var/lib') / ('replay-test-' + os.urandom(8).hex())
        parent.mkdir(mode=0o700)
        self.addCleanup(lambda: __import__('shutil').rmtree(parent))
        provision(parent=parent, uid=65534, gid=65534)
        state = parent / 'hermes-commander-replay'
        journal = state / 'claims'
        self.assertEqual((state.stat().st_uid, state.stat().st_mode & 0o777), (65534, 0o700))
        self.assertEqual((journal.stat().st_uid, journal.stat().st_mode & 0o777), (65534, 0o600))
        self.assertEqual(journal.read_bytes(), _MAGIC)
        with self.assertRaises(FileExistsError):
            provision(parent=parent, uid=65534, gid=65534)
        self.assertEqual(journal.read_bytes(), _MAGIC)


if __name__ == '__main__':
    unittest.main()
