"""Durable read-only replay reservations on disposable Linux state."""
from pathlib import Path
import subprocess
import sys
import tempfile
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

    def test_shared_instance_concurrent_claim_has_one_winner(self):
        with LinuxReadReplay(self.path) as ledger:
            with ThreadPoolExecutor(max_workers=8) as workers:
                self.assertEqual(sum(workers.map(lambda _: ledger.claim('same-id'), range(8))), 1)

    def test_two_open_instances_observe_each_others_appends(self):
        with LinuxReadReplay(self.path) as first, LinuxReadReplay(self.path) as second:
            self.assertTrue(first.claim('from-first'))
            self.assertTrue(second.claim('from-second'))
            self.assertFalse(first.claim('from-second'))
            self.assertFalse(second.claim('from-first'))

    def test_open_instance_observes_another_process_append(self):
        code = ('from pathlib import Path; from device_fabric.linux_native_replay import LinuxReadReplay; '
                'import sys; j=LinuxReadReplay(Path(sys.argv[1])); '
                'print(j.claim("other-process"))')
        with LinuxReadReplay(self.path) as ledger:
            result = subprocess.run([sys.executable, '-B', '-c', code, str(self.path)],
                                    capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout.strip(), 'True')
            self.assertFalse(ledger.claim('other-process'))

    def test_duplicate_record_across_read_chunks_is_refused(self):
        with self.path.open('ab') as stream:
            for index in range(2049):
                stream.write(index.to_bytes(32, 'big'))
            stream.write((0).to_bytes(32, 'big'))
        with self.assertRaises(ReplayDenied):
            LinuxReadReplay(self.path)

    def test_existing_fifty_thousand_claims_do_not_block_new_claim(self):
        with self.path.open('ab') as stream:
            for index in range(50_000):
                stream.write(index.to_bytes(32, 'big'))
        with LinuxReadReplay(self.path) as ledger:
            self.assertTrue(ledger.claim('after-existing-claims'))
        with LinuxReadReplay(self.path) as ledger:
            self.assertFalse(ledger.claim('after-existing-claims'))

    def test_same_size_in_place_tampering_is_refused(self):
        with LinuxReadReplay(self.path) as ledger:
            self.assertTrue(ledger.claim('original'))
            with self.path.open('r+b') as stream:
                stream.seek(len(_MAGIC))
                stream.write(b'X' * 32)
            with self.assertRaises(ReplayDenied):
                ledger.claim('new-request')

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
        with patch('device_fabric.linux_native_replay._MAX_BYTES', len(_MAGIC) + 32):
            with LinuxReadReplay(self.path) as ledger:
                self.assertTrue(ledger.claim('request-1'))
                self.assertFalse(ledger.claim('request-1'))
                with self.assertRaises(ReplayDenied):
                    ledger.claim('request-2')

if __name__ == '__main__':
    unittest.main()
