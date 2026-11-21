"""Audit setup tests use only synthetic paths and mocked system commands."""
from contextlib import nullcontext
import hashlib
from pathlib import Path
import os
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import h454_native_audit_setup as setup


class AuditSetupTests(unittest.TestCase):
    def test_uncertain_account_creation_requires_recovery(self):
        with patch.object(setup,'ensure_lock'), \
             patch.object(setup.paired,'host_lock',return_value=nullcontext()), \
             patch.object(setup,'plan',return_value={}), \
             patch.object(setup,'_run',side_effect=TimeoutError('synthetic private detail')), \
             patch.object(setup,'_identity_absent',return_value=False), \
             patch.object(setup,'_rollback') as rollback:
            with self.assertRaises(setup.AuditSetupHold) as error:
                setup.install()
        self.assertEqual(error.exception.phase,'AUDIT_CLEANUP')
        self.assertNotIn('synthetic private detail',str(error.exception))
        rollback.assert_called_once()


    def test_socket_must_be_root_owned_and_group_limited(self):
        directory=SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0)
        endpoint=SimpleNamespace(st_mode=stat.S_IFSOCK|0o660,st_uid=0,st_gid=1234)
        identity=SimpleNamespace(pw_gid=1234)
        with patch.object(Path,'lstat',side_effect=[directory,endpoint]):
            self.assertTrue(setup._audit_socket_protected(identity))
        endpoint.st_mode=stat.S_IFSOCK|0o666
        with patch.object(Path,'lstat',side_effect=[directory,endpoint]):
            self.assertFalse(setup._audit_socket_protected(identity))

    def test_state_directory_requires_exact_private_owner(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);root.chmod(0o700)
            identity=SimpleNamespace(pw_uid=os.geteuid(),pw_gid=os.getegid())
            with patch.object(setup,'MANIFEST',root/'manifest.json'):
                self.assertTrue(setup._state_directory_matches(identity))
                root.chmod(0o755)
                self.assertFalse(setup._state_directory_matches(identity))

    def test_plan_rejects_changed_unit_and_group_members(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);unit=root/'units';unit.mkdir()
            manifest=root/'manifest.json';manifest.write_bytes(b'manifest')
            gid=os.getegid()
            if gid==0:
                gid=65534;os.chown(manifest,-1,gid)
            state={'ActiveState':'active','UnitFileState':'disabled','LoadState':'loaded',
                   'FragmentPath':str(unit/'hermes-commander-native.service'),
                   'User':'hermes-commander-native','Group':'hermes-commander-native',
                   'DropInPaths':'','NeedDaemonReload':'no'}
            identity=SimpleNamespace(pw_uid=11,pw_gid=gid,pw_name='hermes-commander-native',pw_shell='/usr/sbin/nologin')
            group=SimpleNamespace(gr_mem=[])
            def checked(path,*_args,**_kwargs):
                return b'manifest' if path.name=='manifest.json' else b'unit'
            with patch.object(setup,'UNIT_DIR',unit),patch.object(setup,'UNIT_SEARCH_DIRS',(unit,)), \
                 patch.object(setup,'MANIFEST',manifest), \
                 patch.object(setup,'SOCKET_DIR',root/'socket'), \
                 patch.object(setup.os,'geteuid',return_value=0), \
                 patch.object(setup.socket,'gethostname',return_value='vps1777112993'), \
                 patch.object(setup,'owned_directory'),patch.object(setup,'_identity_absent',return_value=True), \
                 patch.object(setup,'_state_directory_matches',return_value=True), \
                 patch.object(setup.pwd,'getpwnam',return_value=identity), \
                 patch.object(setup.pwd,'getpwall',return_value=[identity]), \
                 patch.object(setup.grp,'getgrgid',return_value=group), \
                 patch.object(setup,'checked_file',side_effect=checked), \
                 patch.object(setup,'MANIFEST_SHA',hashlib.sha256(b'manifest').hexdigest()), \
                 patch.object(setup,'ACTIVE_SHA',hashlib.sha256(b'unit').hexdigest()), \
                 patch.object(setup,'raw_show',return_value=state):
                self.assertEqual(setup.plan()['status'],'H454_AUDIT_SETUP_PLAN_PASS')
                group.gr_mem=['unexpected-user']
                with self.assertRaises(setup.AuditSetupHold):setup.plan()
                group.gr_mem=[];state['ActiveState']='inactive'
                with self.assertRaises(setup.AuditSetupHold):setup.plan()


if __name__ == '__main__':
    unittest.main()
