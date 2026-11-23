"""Bounded Hermes reconnect migration against disposable synthetic files."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_hermes_bounded_reconnect as update


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class HermesBoundedReconnectTests(unittest.TestCase):
    def setUp(self):
        self.old = (b'[Unit]\nStartLimitIntervalSec=300\nStartLimitBurst=3\n'
                    b'[Service]\nRestart=on-success\nRestartSec=5s\n')
        self.new = self.old.replace(update.OLD_LINE, update.NEW_LINE).replace(
            b'StartLimitIntervalSec=300\n', b'StartLimitIntervalSec=60\n')
        self.pins = (patch.object(update, 'OLD', sha(self.old)), patch.object(update, 'NEW', sha(self.new)))
        for item in self.pins: item.start(); self.addCleanup(item.stop)

    def test_candidate_changes_only_restart_policy_and_rejects_drift(self):
        self.assertEqual(update.candidate(self.old), self.new)
        for changed in (self.old + b'# drift\n', self.old.replace(b'StartLimitBurst=3', b'StartLimitBurst=9'),
                        self.old.replace(update.OLD_LINE, update.OLD_LINE * 2)):
            with self.subTest(changed=changed), self.assertRaises(update.Hold):
                update.candidate(changed)

    def test_effective_policy_must_remain_bounded_and_service_active(self):
        values = {
            'ActiveState': 'active', 'LoadState': 'loaded', 'UnitFileState': 'disabled',
            'FragmentPath': str(update.UNIT), 'DropInPaths': '', 'NeedDaemonReload': 'no',
            'Restart': 'always', 'RestartUSec': '2s',
            'StartLimitIntervalUSec': '1min', 'StartLimitBurst': '3',
        }
        def output():
            return ''.join(f'{key}={value}\n' for key, value in values.items()).encode('ascii')
        with patch.object(update, 'run', side_effect=lambda *_args: output()):
            update.service_state('new')
            for key, bad in [('Restart', 'no'), ('StartLimitBurst', '9'),
                             ('DropInPaths', '/tmp/override.conf'), ('ActiveState', 'failed')]:
                original = values[key]
                values[key] = bad
                with self.subTest(key=key), self.assertRaises(update.Hold):
                    update.service_state('new')
                values[key] = original

    @unittest.skipUnless(os.name == 'posix', 'Linux unit transaction')
    def test_install_and_rollback_keep_unit_limits_and_never_stop_services(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); unit = root/'hermes-commander-native.service'; unit.write_bytes(self.old)
            receipt = root/'receipt'
            def checked(path, **_kwargs): return path.read_bytes()
            with (patch.object(update, 'UNIT', unit), patch.object(update, 'RECEIPT', receipt),
                  patch.object(update, 'preflight'), patch.object(update, 'root_directory'),
                  patch.object(update, 'checked', side_effect=checked),
                  patch.object(update, 'service_state') as state,
                  patch.object(update, 'run', return_value=b'') as run):
                update.install()
                self.assertEqual(unit.read_bytes(), self.new)
                self.assertEqual((receipt/'original.unit').read_bytes(), self.old)
                self.assertEqual(state.call_args_list[0].args, ('old',))
                self.assertEqual(state.call_args_list[-1].args, ('new',))
                update.rollback()
                self.assertEqual(unit.read_bytes(), self.old)
                commands = [x.args for x in run.call_args_list]
                self.assertTrue(all('stop' not in x and 'restart' not in x for x in commands))

    @unittest.skipUnless(os.name == 'posix', 'Linux unit transaction')
    def test_reload_failure_restores_original_and_keeps_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); unit = root/'hermes-commander-native.service'; unit.write_bytes(self.old)
            receipt = root/'receipt'; calls = []
            def checked(path, **_kwargs): return path.read_bytes()
            def run(*args):
                calls.append(args)
                if len(calls) == 2: raise update.Hold('synthetic reload failure')
                return b''
            with (patch.object(update, 'UNIT', unit), patch.object(update, 'RECEIPT', receipt),
                  patch.object(update, 'preflight'), patch.object(update, 'root_directory'),
                  patch.object(update, 'checked', side_effect=checked), patch.object(update, 'service_state'),
                  patch.object(update, 'run', side_effect=run)):
                with self.assertRaises(update.Hold): update.install()
                self.assertEqual(unit.read_bytes(), self.old)
                self.assertEqual((receipt/'original.unit').read_bytes(), self.old)
                self.assertEqual(len(calls), 3)

    @unittest.skipUnless(os.name == 'posix', 'Linux unit transaction')
    def test_interruption_after_swap_restores_original(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); unit = root/'hermes-commander-native.service'; unit.write_bytes(self.old)
            receipt = root/'receipt'; original_swap = update.swap; calls = []
            def checked(path, **_kwargs): return path.read_bytes()
            def swap_then_fail(raw):
                original_swap(raw); calls.append(raw)
                if len(calls) == 1: raise OSError('synthetic failure after rename')
            with (patch.object(update, 'UNIT', unit), patch.object(update, 'RECEIPT', receipt),
                  patch.object(update, 'preflight'), patch.object(update, 'root_directory'),
                  patch.object(update, 'checked', side_effect=checked), patch.object(update, 'service_state'),
                  patch.object(update, 'swap', side_effect=swap_then_fail), patch.object(update, 'run', return_value=b'')):
                with self.assertRaises(OSError): update.install()
                self.assertEqual(unit.read_bytes(), self.old)
                self.assertEqual(calls, [self.new, self.old])
