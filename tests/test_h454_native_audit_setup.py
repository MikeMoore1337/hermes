"""Audit setup tests use only synthetic paths and mocked system commands."""
from contextlib import nullcontext
import hashlib
from pathlib import Path
import os
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import h454_native_audit_setup as setup


class AuditSetupTests(unittest.TestCase):
    def test_yfc_plan_requires_exact_host_receipt_inactive_unit_and_trust(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); unit=root/'units'; unit.mkdir()
            receipt=root/'receipt'; host=root/'host-key'; manifest=root/'state'/'manifest.json'
            identity=SimpleNamespace(pw_uid=11,pw_gid=12,pw_name='hermes-commander-native',pw_shell='/usr/sbin/nologin',pw_dir='/nonexistent')
            state={'ActiveState':'inactive','UnitFileState':'disabled','LoadState':'loaded',
                   'FragmentPath':str(unit/'hermes-commander-native.service'),
                   'User':'hermes-commander-native','Group':'hermes-commander-native',
                   'DropInPaths':'','NeedDaemonReload':'no'}
            values={receipt:b'receipt',host:b'host',unit/'hermes-commander-native.service':b'unit'}
            with patch.multiple(setup,UNIT_DIR=unit,UNIT_SEARCH_DIRS=(unit,),YFC_RECEIPT=receipt, \
                                YFC_HOST_KEY=host,MANIFEST=manifest,SOCKET_DIR=root/'socket'), \
                 patch.object(setup.os,'geteuid',return_value=0),patch.object(setup,'owned_directory'), \
                 patch.object(setup,'_identity_absent',return_value=True), \
                 patch.object(setup,'_service_group_exclusive',return_value=True) as exclusive, \
                 patch.multiple(setup.pwd,getpwnam=Mock(return_value=identity),getpwall=Mock(return_value=[identity])), \
                 patch.object(setup,'_run',return_value=SimpleNamespace(stdout=b'hermes-commander-native L')) as run, \
                 patch.object(setup,'checked_file',side_effect=lambda path,*a,**k:values[path]), \
                 patch.multiple(setup,YFC_RECEIPT_SHA=hashlib.sha256(b'receipt').hexdigest(), \
                                YFC_HOST_KEY_SHA=hashlib.sha256(b'host').hexdigest(), \
                                YFC_ACTIVE_SHA=hashlib.sha256(b'unit').hexdigest()), \
                 patch.object(setup,'load_private_relay') as trust,patch.object(setup,'raw_show',return_value=state):
                self.assertEqual(setup.plan_yfc()['status'],'H454_YFC_AUDIT_SETUP_PLAN_PASS')
                for path in values:
                    good=values[path]; values[path]=b'changed'
                    with self.subTest(path=path.name),self.assertRaises(setup.AuditSetupHold):setup.plan_yfc()
                    values[path]=good
                state['ActiveState']='active'
                with self.assertRaises(setup.AuditSetupHold):setup.plan_yfc()
                state['ActiveState']='inactive'
                exclusive.return_value=False
                with self.assertRaises(setup.AuditSetupHold):setup.plan_yfc()
                exclusive.return_value=True
                run.return_value.stdout=b'hermes-commander-native P'
                with self.assertRaises(setup.AuditSetupHold):setup.plan_yfc()
                run.return_value.stdout=b'hermes-commander-native L'
                manifest.parent.mkdir()
                with self.assertRaises(setup.AuditSetupHold):setup.plan_yfc()
                manifest.parent.rmdir()
                trust.side_effect=ValueError('bad trust')
                with self.assertRaises(setup.AuditSetupHold):setup.plan_yfc()

    def test_yfc_install_selects_only_inactive_pinned_worker(self):
        with patch.object(setup,'_install',return_value={'status':'ok'}) as install:
            self.assertEqual(setup.install_yfc(),{'status':'ok'})
        install.assert_called_once_with(setup.plan_yfc,active_sha=setup.YFC_ACTIVE_SHA,expected_state='inactive',lock_factory=setup.yfc_host_lock)

    def test_yfc_uncertain_account_creation_requires_recovery(self):
        with patch.object(setup,'ensure_lock'), \
             patch.object(setup,'yfc_host_lock',return_value=nullcontext()), \
             patch.object(setup,'plan_yfc',return_value={}), \
             patch.object(setup,'_run',side_effect=TimeoutError('private detail')), \
             patch.object(setup,'_identity_absent',return_value=False), \
             patch.object(setup,'_rollback') as rollback:
            with self.assertRaises(setup.AuditSetupHold) as error:
                setup.install_yfc()
        self.assertEqual(error.exception.phase,'AUDIT_CLEANUP')
        self.assertNotIn('private detail',str(error.exception))
        rollback.assert_called_once()

    def test_yfc_lock_works_without_state_directory_and_refuses_concurrent_or_wrong_host(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); lock_dir=root/'lock'; lock_dir.mkdir(mode=0o777); lock_dir.chmod(0o1777)
            lock=lock_dir/'lifecycle.lock'; lock.touch(mode=0o600); lock.chmod(0o600)
            host=root/'host.pub'; host.write_bytes(b'host'); host.chmod(0o644)
            real_fstat=os.fstat; real_lstat=Path.lstat
            def root_fstat(fd):
                value=real_fstat(fd)
                return SimpleNamespace(st_mode=value.st_mode,st_uid=0,st_nlink=value.st_nlink,
                                       st_size=value.st_size,st_dev=value.st_dev,st_ino=value.st_ino)
            def root_lstat(path,*args,**kwargs):
                value=real_lstat(path,*args,**kwargs)
                return SimpleNamespace(st_mode=value.st_mode,st_uid=0) if path==lock_dir else value
            with patch.object(setup.paired,'LOCK',lock),patch.object(setup,'YFC_HOST_KEY',host), \
                 patch.object(setup,'YFC_HOST_KEY_SHA',hashlib.sha256(b'host').hexdigest()), \
                 patch.object(setup,'owned_directory'),patch.object(setup.os,'geteuid',return_value=0), \
                 patch.object(setup.os,'fstat',side_effect=root_fstat),patch.object(Path,'lstat',root_lstat), \
                 patch.object(setup,'checked_file',side_effect=lambda path,*a,**k:path.read_bytes()):
                with setup.yfc_host_lock():
                    with self.assertRaises(setup.AuditSetupHold):
                        with setup.yfc_host_lock(): pass
                host.write_bytes(b'other')
                with self.assertRaises(setup.AuditSetupHold):
                    with setup.yfc_host_lock(): pass
                host.write_bytes(b'host'); lock.chmod(0o644)
                with self.assertRaises(setup.AuditSetupHold):
                    with setup.yfc_host_lock(): pass

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
