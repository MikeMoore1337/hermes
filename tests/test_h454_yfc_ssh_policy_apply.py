import os
import json
import stat
import copy
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts import h454_yfc_ssh_policy_apply as policy


class PolicyTests(unittest.TestCase):
    def test_relay_requires_exact_running_pair_and_static_private_address(self):
        plan={'relay_id':'r','sidecar_id':'s','network_id':'n'}
        relay={'Id':'r','State':{'Running':True},'NetworkSettings':{'Networks':{
            'hermes-brc-internal':{'NetworkID':'n','IPAddress':'172.29.1.2',
                                   'IPAMConfig':{'IPv4Address':'172.29.1.2'}}}}}
        sidecar={'Id':'s','State':{'Running':True},'HostConfig':{'NetworkMode':'container:r'}}
        self.assertEqual(policy._relay_address(plan,relay,sidecar),'172.29.1.2')
        for change in ('dynamic','address_drift','relay_id','sidecar_stopped','sidecar_namespace'):
            r,s=copy.deepcopy(relay),copy.deepcopy(sidecar)
            if change=='dynamic': r['NetworkSettings']['Networks']['hermes-brc-internal']['IPAMConfig']=None
            if change=='address_drift': r['NetworkSettings']['Networks']['hermes-brc-internal']['IPAMConfig']['IPv4Address']='172.29.1.3'
            if change=='relay_id': r['Id']='other'
            if change=='sidecar_stopped': s['State']['Running']=False
            if change=='sidecar_namespace': s['HostConfig']['NetworkMode']='bridge'
            with self.subTest(change=change), self.assertRaises(policy.Hold):
                policy._relay_address(plan,r,s)

    def test_plan_requires_exact_pin_schema_and_canonical_bytes(self):
        plan={'version':1,'target':'yfc-vps','policy_sha256':'a'*64,'base_config_sha256':'b'*64,
              'include_sha256':{'safe.conf':'c'*64},'relay_id':'d'*64,'sidecar_id':'e'*64,
              'network_id':'f'*64,'existing_accounts_checked':58,'installation':False}
        raw=json.dumps(plan,sort_keys=True,separators=(',',':')).encode('ascii')
        fake_dir=SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0)
        with patch.object(type(Path()),'lstat',return_value=fake_dir), patch.object(policy,'read_file',return_value=raw):
            self.assertEqual(policy.read_plan(policy.sha(raw)),plan)
            with self.assertRaises(policy.Hold):
                policy.read_plan('0'*64)
        bad=json.dumps({**plan,'version':True},sort_keys=True,separators=(',',':')).encode('ascii')
        with patch.object(type(Path()),'lstat',return_value=fake_dir), patch.object(policy,'read_file',return_value=bad):
            with self.assertRaises(policy.Hold):
                policy.read_plan(policy.sha(bad))

    def test_policy_rejects_public_or_injected_destinations(self):
        for address in ('8.8.8.8','127.0.0.1','172.29.1.2\nPermitTTY yes','bad'):
            with self.subTest(address=address), self.assertRaises((policy.Hold, ValueError)):
                policy.policy(address)
        raw=policy.policy('172.29.1.2')
        self.assertIn(b'AllowTcpForwarding local\n',raw)
        self.assertIn(b'PermitListen none\n',raw)
        self.assertIn(b'PermitOpen 172.29.1.2:3001\n',raw)
        self.assertIn(b'ForceCommand /usr/sbin/nologin\n',raw)

    def test_prior_match_scopes_cannot_shadow_yfc_by_address_or_pattern(self):
        policy._safe_prior_matches(b'Match User another-user\n', [b'Match all\n'])
        for raw in (b'Match Address 0.0.0.0/0\n', b'Match User *\n',
                    b'Match User hermes-yfc-forward\n', b'Match Group staff\n'):
            with self.subTest(raw=raw), self.assertRaises(policy.Hold):
                policy._safe_prior_matches(raw, [])
        with self.assertRaises(policy.Hold):
            policy._safe_prior_matches(b'', [b'Include /tmp/other.conf\n'])

    def test_effective_target_policy_must_be_complete_unique_and_restricted(self):
        lines=(b'authenticationmethods publickey\nallowtcpforwarding local\n'
               b'allowstreamlocalforwarding no\npermitopen 172.29.1.2:3001\npermitlisten none\n'
               b'passwordauthentication no\nkbdinteractiveauthentication no\npermittty no\n'
               b'x11forwarding no\nallowagentforwarding no\npermittunnel no\npermituserrc no\n'
               b'forcecommand /usr/sbin/nologin\npubkeyauthentication yes\nauthorizedkeyscommand none\n'
               b'authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\nstrictmodes yes\n')
        policy._validate_target(lines,'172.29.1.2')
        for bad in (lines+b'permitopen any\n', lines.replace(b'permitlisten none',b'permitlisten any'),
                    lines.replace(b'authorizedkeyscommand none',b'authorizedkeyscommand /tmp/key')):
            with self.subTest(bad=bad[-80:]), self.assertRaises(policy.Hold):
                policy._validate_target(bad,'172.29.1.2')

    def test_exclusive_create_removes_its_partial_file_on_write_failure(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'candidate'
            with patch.object(policy.os,'fsync',side_effect=[OSError('synthetic'),None]):
                with self.assertRaises(OSError):
                    policy._create(path,b'partial',0o600)
            self.assertFalse(path.exists())
            path.write_bytes(b'foreign')
            with self.assertRaises(FileExistsError):
                policy._create(path,b'new',0o600)
            self.assertEqual(path.read_bytes(),b'foreign')


class TransactionTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root=Path(temp.name)
        self.stage=root/'stage'; self.stage.mkdir(mode=0o700)
        self.includes=root/'includes'; self.includes.mkdir(mode=0o755)
        self.config=root/'sshd_config'; self.config.write_bytes(b'original')
        self.original=self.includes/'existing.conf'; self.original.write_bytes(b'existing')
        self.raw=policy.policy('172.29.1.2')
        self.plan={'base_config_sha256':policy.sha(b'original'),
                   'include_sha256':{'existing.conf':policy.sha(b'existing')},
                   'policy_sha256':policy.sha(self.raw), 'existing_accounts_checked':2}
        self.baseline={'root':b'root-settings','service':b'service-settings'}
        self.users=list(self.baseline)
        self.pin='a'*64
        self.reloads=0
        self.change_user=False
        self.fail_reload=False
        self.real_fstat=os.fstat

    def fake_fstat(self, fd):
        s=self.real_fstat(fd)
        return SimpleNamespace(st_mode=s.st_mode,st_uid=0,st_nlink=s.st_nlink,st_size=s.st_size,
                               st_mtime_ns=s.st_mtime_ns,st_ctime_ns=s.st_ctime_ns,
                               st_dev=s.st_dev,st_ino=s.st_ino)

    def settings(self, _config, user, address='127.0.0.1'):
        if user == policy.ACCOUNT:
            return b'target-settings'
        if self.change_user and user == 'root':
            return b'changed-root-settings'
        return self.baseline[user]

    def fake_run(self, args, timeout=15):
        if args[0]=='/usr/bin/systemctl' and args[1]=='reload':
            self.reloads+=1
            if self.fail_reload:
                raise subprocess.CalledProcessError(1,args)
        if args[0]=='/usr/bin/systemctl' and args[1]=='is-active':
            return b'active\n'
        return b''

    def invoke(self, operation='apply'):
        with patch.object(policy,'STAGE',self.stage), patch.object(policy,'INCLUDES',self.includes), \
             patch.object(policy,'CONFIG',self.config), patch.object(policy,'read_plan',return_value=self.plan), \
             patch.object(policy,'preflight',return_value=(self.raw,'172.29.1.2',self.baseline,123)), \
             patch.object(policy,'_users',return_value=self.users), patch.object(policy,'_trusted_directory'), \
             patch.object(policy,'_settings',side_effect=self.settings), \
             patch.object(policy,'_validate_target'), patch.object(policy,'_running_sshd',return_value=123), \
             patch.object(policy,'run',side_effect=self.fake_run), patch.object(policy.os,'geteuid',return_value=0), \
             patch.object(policy.socket,'gethostname',return_value='vps1777112993'), \
             patch.object(policy.os,'fstat',side_effect=self.fake_fstat):
            return getattr(policy,operation)(self.pin)

    def test_installs_only_new_rule_and_records_exact_inode(self):
        self.assertEqual(self.invoke(),'YFC_SSH_POLICY_INSTALLED_ACCOUNT_ABSENT')
        target=self.includes/policy.NAME
        self.assertEqual(target.read_bytes(),self.raw)
        self.assertEqual(target.stat().st_mode & 0o777,0o644)
        self.assertEqual(self.original.read_bytes(),b'existing')
        self.assertTrue((self.stage/'receipt.json').is_file())
        self.assertFalse((self.stage/'pending.json').exists())
        self.assertEqual(self.reloads,1)
        with self.assertRaises(policy.Hold):
            self.invoke()
        self.assertEqual(self.reloads,1)

    def test_existing_principal_drift_removes_only_new_rule_without_reload(self):
        self.change_user=True
        with self.assertRaises(policy.Hold):
            self.invoke()
        self.assertFalse((self.includes/policy.NAME).exists())
        self.assertFalse((self.stage/'pending.json').exists())
        self.assertEqual(self.original.read_bytes(),b'existing')
        self.assertEqual(self.reloads,0)

    def test_foreign_rule_is_never_overwritten(self):
        target=self.includes/policy.NAME
        target.write_bytes(b'foreign')
        with self.assertRaises(FileExistsError):
            self.invoke()
        self.assertEqual(target.read_bytes(),b'foreign')
        self.assertEqual(self.reloads,0)

    def test_ambiguous_reload_keeps_pending_and_prevents_retry(self):
        self.fail_reload=True
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke()
        self.assertTrue((self.stage/'pending.json').is_file())
        self.assertTrue((self.includes/policy.NAME).is_file())
        self.assertFalse((self.stage/'receipt.json').exists())
        with self.assertRaises(policy.Hold):
            self.invoke()
        self.assertEqual(self.reloads,1)

    def test_unsettled_partial_creation_retains_pending_and_blocks_retry(self):
        real_create=policy._create
        def fail_target(path,data,mode):
            if path.parent==self.includes:
                raise policy.Unsettled('synthetic cleanup failure')
            return real_create(path,data,mode)
        with patch.object(policy,'_create',side_effect=fail_target):
            with self.assertRaises(policy.Unsettled):
                self.invoke()
        self.assertTrue((self.stage/'pending.json').is_file())
        with self.assertRaises(policy.Hold):
            self.invoke()
        self.assertEqual(self.reloads,0)

    def test_rollback_removes_only_receipted_rule_and_preserves_receipt(self):
        self.invoke()
        self.assertEqual(self.invoke('rollback'),'YFC_SSH_POLICY_ROLLED_BACK_RECEIPT_PRESERVED')
        self.assertFalse((self.includes/policy.NAME).exists())
        self.assertEqual(self.original.read_bytes(),b'existing')
        self.assertTrue((self.stage/'receipt.json').is_file())
        self.assertTrue((self.stage/'rollback.json').is_file())
        self.assertFalse((self.stage/'pending.json').exists())
        self.assertEqual(self.reloads,2)

    def test_rollback_refuses_if_forward_account_exists_or_inode_changed(self):
        self.invoke()
        target=self.includes/policy.NAME
        self.users.append(policy.ACCOUNT)
        with self.assertRaises(policy.Hold):
            self.invoke('rollback')
        self.assertTrue(target.is_file())
        self.users.remove(policy.ACCOUNT)
        target.rename(self.stage/'displaced')
        target.write_bytes(self.raw)
        target.chmod(0o644)
        with self.assertRaises(policy.Hold):
            self.invoke('rollback')
        self.assertEqual(target.read_bytes(),self.raw)
        self.assertEqual(self.reloads,1)

    def test_uncertain_rollback_reload_keeps_pending_and_disallows_retry(self):
        self.invoke()
        self.fail_reload=True
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke('rollback')
        self.assertTrue((self.stage/'pending.json').is_file())
        self.assertFalse((self.includes/policy.NAME).exists())
        self.assertTrue((self.stage/'receipt.json').is_file())
        with self.assertRaises(policy.Hold):
            self.invoke('rollback')
        self.assertEqual(self.reloads,2)


if __name__=='__main__':
    unittest.main()
