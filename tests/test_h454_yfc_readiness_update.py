"""A unit upgrade must preserve pairing and allow a pinned rollback."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_yfc_readiness_update as update


def sha(value):
    return hashlib.sha256(value).hexdigest()


def local_checked(path, **kwargs):
    return _checked(path, uid=os.getuid(), **kwargs)


_checked = update.checked


class ReadinessUpdateTests(unittest.TestCase):
    def setUp(self):
        self.old = {
            update.NATIVE: b'[Unit]\nAfter=network-online.target local-fs.target hermes-commander-audit.socket\n',
            update.TUNNEL: b'[Service]\nNoNewPrivileges=yes\n',
        }
        marker = b'After=network-online.target local-fs.target hermes-commander-audit.socket\n'
        self.new = {
            update.NATIVE: self.old[update.NATIVE].replace(marker, marker +
                b'Requires=hermes-commander-tunnel.service\nAfter=hermes-commander-tunnel.service\n'),
            update.TUNNEL: self.old[update.TUNNEL].replace(b'NoNewPrivileges=yes\n',
                update.POST + b'NoNewPrivileges=yes\n'),
        }
        self.pins = {name: sha(value) for name, value in self.old.items()}
        self.new_pins = {name: sha(value) for name, value in self.new.items()}

    def test_exact_old_units_generate_exact_pinned_candidates(self):
        with patch.object(update,'OLD',self.pins), patch.object(update,'NEW',self.new_pins):
            self.assertEqual(update.candidates(self.old),self.new)
            tampered = dict(self.old, **{update.NATIVE:self.old[update.NATIVE] + b'# change\n'})
            with self.assertRaises(update.Hold):
                update.candidates(tampered)
            with patch.dict(update.NEW,{update.TUNNEL:'0'*64}):
                with self.assertRaises(update.Hold):
                    update.candidates(self.old)

    def test_controlled_restart_resets_budget_and_waits_for_pinned_tls(self):
        events=[]
        def run(*args, **_kwargs):
            events.append(args)
            return b''
        with (patch.object(update,'run',side_effect=run),
              patch.object(update,'tls_ready',side_effect=lambda:events.append('tls')),
              patch.object(update,'service_state')):
            update.start_services()
        self.assertEqual(events,[('/usr/bin/systemctl','daemon-reload'),
            ('/usr/bin/systemctl','reset-failed',update.TUNNEL,update.NATIVE),
            ('/usr/bin/systemctl','start',update.TUNNEL), 'tls',
            ('/usr/bin/systemctl','start',update.NATIVE)])

    @unittest.skipUnless(os.name == 'posix', 'Linux unit installer')
    def test_install_then_rollback_restores_units_and_keeps_credential_untouched(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); units=root/'units'; units.mkdir()
            credential=root/'device.json'; credential.write_bytes(b'synthetic credential')
            for name, content in self.old.items():
                (units/name).write_bytes(content)
                os.chmod(units/name,0o644)
            with (patch.object(update,'OLD',self.pins), patch.object(update,'NEW',self.new_pins),
                  patch.object(update,'UNITS',units), patch.object(update,'CHECKPOINT',root/'receipt'),
                  patch.object(update,'preflight'), patch.object(update,'service_state'),
                  patch.object(update,'root_directory'), patch.object(update,'checked',side_effect=local_checked),
                  patch.object(update,'stop_services'),
                  patch.object(update,'start_services')):
                update.execute()
                self.assertEqual({n:(units/n).read_bytes() for n in self.new},self.new)
                self.assertEqual(update.saved(),self.old)
                update.restore(update.saved())
                self.assertEqual({n:(units/n).read_bytes() for n in self.old},self.old)
                self.assertEqual(credential.read_bytes(),b'synthetic credential')
                update.execute()
                self.assertEqual({n:(units/n).read_bytes() for n in self.new},self.new)
                self.assertEqual(credential.read_bytes(),b'synthetic credential')

    @unittest.skipUnless(os.name == 'posix', 'Linux unit installer')
    def test_checkpoint_and_mid_update_failure_restore_both_units(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            units = root/'units'; units.mkdir()
            receipt = root/'receipt'
            for name, content in self.old.items():
                (units/name).write_bytes(content)
                os.chmod(units/name,0o644)
            with (patch.object(update,'OLD',self.pins), patch.object(update,'NEW',self.new_pins),
                  patch.object(update,'UNITS',units), patch.object(update,'CHECKPOINT',receipt),
                  patch.object(update,'preflight'), patch.object(update,'service_state'), patch.object(update,'root_directory'),
                  patch.object(update,'checked',side_effect=local_checked),
                  patch.object(update,'stop_services') as stop, patch.object(update,'start_services') as start):
                original_replace = update.replace_unit
                calls = []
                def fails_once(path, value):
                    calls.append(path.name)
                    if len(calls) == 2:
                        raise OSError('synthetic interruption')
                    original_replace(path,value)
                with patch.object(update,'replace_unit',side_effect=fails_once):
                    with self.assertRaises(OSError):
                        update.execute()
                self.assertEqual({n:(units/n).read_bytes() for n in self.old}, self.old)
                self.assertEqual(update.saved(),self.old)
                self.assertEqual(calls,[update.TUNNEL,update.NATIVE,update.TUNNEL])
                self.assertEqual(stop.call_count,2)
                start.assert_called_once()

    @unittest.skipUnless(os.name == 'posix', 'Linux unit installer')
    def test_unknown_unit_blocks_rollback_before_stopping_services(self):
        with tempfile.TemporaryDirectory() as folder:
            units=Path(folder)
            for name, content in self.old.items():
                (units/name).write_bytes(content)
                os.chmod(units/name,0o644)
            (units/update.NATIVE).write_bytes(b'unexpected change')
            with (patch.object(update,'OLD',self.pins), patch.object(update,'NEW',self.new_pins),
                  patch.object(update,'UNITS',units), patch.object(update,'checked',side_effect=local_checked),
                  patch.object(update,'stop_services') as stop):
                with self.assertRaises(update.Hold):
                    update.restore(self.old)
                stop.assert_not_called()

    @unittest.skipUnless(os.name == 'posix', 'Linux unit installer')
    def test_leftover_replacement_blocks_before_stopping_services(self):
        with tempfile.TemporaryDirectory() as folder:
            units=Path(folder)
            (units/('.h454-readiness-'+update.NATIVE)).write_bytes(b'interrupted')
            with (patch.object(update,'UNITS',units), patch.object(update,'stop_services') as stop):
                with self.assertRaises(update.Hold):
                    update.restore(self.old)
                stop.assert_not_called()


if __name__ == '__main__':
    unittest.main()
