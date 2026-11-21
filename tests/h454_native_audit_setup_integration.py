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

    def test_shared_lock_creation_never_replaces_existing_inode(self):
        with tempfile.TemporaryDirectory() as folder:
            directory=Path(folder);directory.chmod(0o1777);lock=directory/'guard.lock'
            with patch.object(setup.paired,'LOCK',lock):
                setup.ensure_lock();first=lock.lstat()
                self.assertEqual(stat.S_IMODE(first.st_mode),0o600)
                setup.ensure_lock();second=lock.lstat()
                self.assertEqual((first.st_dev,first.st_ino),(second.st_dev,second.st_ino))

    def test_cleanup_does_not_remove_changed_unit(self):
        with tempfile.TemporaryDirectory() as folder:
            unit=Path(folder)/'synthetic.service';unit.write_bytes(b'changed');unit.chmod(0o644)
            node=unit.lstat()
            expected=hashlib.sha256(b'original').hexdigest()
            with patch.object(setup,'_run') as command, \
                 self.assertRaises(setup.AuditSetupHold):
                setup._rollback([(unit,node.st_dev,node.st_ino,expected)],
                    account_uid=None,account_gid=None,start_attempted=False)
            command.assert_not_called()
            self.assertEqual(unit.read_bytes(),b'changed')

    def test_failed_probe_removes_only_created_units_and_account(self):
        with tempfile.TemporaryDirectory() as folder:
            unit=Path(folder);calls=[]
            identity=SimpleNamespace(pw_uid=1234,pw_gid=1235,pw_name=setup.ACCOUNT,
                pw_shell='/usr/sbin/nologin',pw_dir='/nonexistent')
            group=SimpleNamespace(gr_gid=1235,gr_mem=[])
            def run(args,**_kwargs):
                calls.append(tuple(args))
                output=b'hermes-commander-audit L\n' if args[:2]==['/usr/bin/passwd','-S'] else b''
                return SimpleNamespace(stdout=output,returncode=0)
            def cleanup(args,**_kwargs):
                calls.append(tuple(args))
                return SimpleNamespace(returncode=1 if args[0]=='/usr/bin/pgrep' else 0)
            with patch.object(setup,'UNIT_DIR',unit),patch.object(setup,'ensure_lock'), \
                 patch.object(setup.paired,'host_lock',return_value=nullcontext()), \
                 patch.object(setup,'plan',return_value={}),patch.object(setup,'_run',side_effect=run), \
                 patch.object(setup.pwd,'getpwnam',side_effect=[identity,identity,identity,KeyError()]), \
                 patch.object(setup.pwd,'getpwall',side_effect=[[identity],[identity],[]]), \
                 patch.object(setup.grp,'getgrnam',side_effect=[group,group,KeyError()]), \
                 patch.object(setup,'_service_group_exclusive',return_value=True), \
                 patch.object(setup,'_audit_socket_protected',return_value=True), \
                 patch.object(setup,'_socket_probe',side_effect=ValueError('synthetic-secret')), \
                 patch.object(setup.subprocess,'run',side_effect=cleanup):
                with self.assertRaises(setup.AuditSetupHold) as error:setup.install()
            self.assertNotIn('synthetic-secret',str(error.exception))
            self.assertEqual(list(unit.iterdir()),[])
            self.assertIn(('/usr/bin/systemctl','stop',setup.SOCKET_UNIT),calls)
            self.assertIn(('/usr/sbin/userdel',setup.ACCOUNT),calls)

    def test_success_keeps_fixed_socket_without_restarting_worker(self):
        with tempfile.TemporaryDirectory() as folder:
            unit=Path(folder);calls=[]
            identity=SimpleNamespace(pw_uid=1234,pw_gid=1235,pw_name=setup.ACCOUNT,
                pw_shell='/usr/sbin/nologin',pw_dir='/nonexistent')
            def run(args,**_kwargs):
                calls.append(tuple(args))
                output=b'hermes-commander-audit L\n' if args[:2]==['/usr/bin/passwd','-S'] else b''
                return SimpleNamespace(stdout=output,returncode=0)
            with patch.object(setup,'UNIT_DIR',unit),patch.object(setup,'ensure_lock'), \
                 patch.object(setup.paired,'host_lock',return_value=nullcontext()), \
                 patch.object(setup,'plan',return_value={}),patch.object(setup,'_run',side_effect=run), \
                 patch.object(setup.pwd,'getpwnam',return_value=identity), \
                 patch.object(setup.pwd,'getpwall',return_value=[identity]), \
                 patch.object(setup.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=1235,gr_mem=[])), \
                 patch.object(setup,'_service_group_exclusive',return_value=True), \
                 patch.object(setup,'_audit_socket_protected',return_value=True), \
                 patch.object(setup,'_socket_probe') as probe, \
                 patch.object(setup,'checked_file',return_value=b'old unit'), \
                 patch.object(setup,'ACTIVE_SHA',hashlib.sha256(b'old unit').hexdigest()), \
                 patch.object(setup,'raw_show',return_value={'ActiveState':'active'}):
                result=setup.install()
            self.assertEqual(result,{'status':'H454_AUDIT_SOCKET_READY','worker_restarted':False})
            probe.assert_called_once()
            self.assertEqual({p.name for p in unit.iterdir()},{setup.SOCKET_UNIT,setup.AUDIT_UNIT})
            self.assertNotIn(('/usr/bin/systemctl','restart','hermes-commander-native.service'),calls)


if __name__ == '__main__':
    unittest.main()
