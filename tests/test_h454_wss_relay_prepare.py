import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from unittest import mock

from scripts import h454_wss_relay_prepare as subject


if os.name == 'posix' and os.geteuid() == 0:
    class RelayPrepareTests(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory(prefix='h454-prepare-')
            self.addCleanup(self.temp.cleanup)
            self.root = Path(self.temp.name)
            self.parent = self.root / 'parent'
            self.parent.mkdir(mode=0o700)
            self.tls = self.root / 'tls'
            self.tls.mkdir(mode=0o700)
            key = self.tls / 'relay.key'
            key.write_bytes(b'synthetic private key')
            os.chown(key, 0, 65534)
            key.chmod(0o440)
            self.proxy = b'synthetic proxy'
            self.reconciler = b'synthetic reconciler'
            self.proxy_sha = hashlib.sha256(self.proxy).hexdigest()
            self.reconciler_sha = hashlib.sha256(self.reconciler).hexdigest()
            self.request_sha = 'a' * 64
            self.ca_sha = 'b' * 64
            self.container_id = 'c' * 64
            self.request = {'account': 'fixture', 'public_key': 'synthetic', 'relay_id': 'd' * 64,
                            'relay_image': 'sha256:' + 'e' * 64, 'network_id': 'f' * 64,
                            'relay_ip': '172.29.0.2'}
            self.relay = {'State': {'Pid': 101}}
            self.manifest = {'ca_sha256': self.ca_sha, 'certificate_sha256': '1' * 64}
            self.sidecar = {'State': {'Status': 'created', 'Running': False}}
            self.stack = ExitStack()
            self.addCleanup(self.stack.close)
            self.stack.enter_context(mock.patch.object(subject, 'PARENT', self.parent))
            self.stack.enter_context(mock.patch.object(subject.identity, 'PARENT', self.root))
            self.stack.enter_context(mock.patch.object(subject.identity, 'NAME', 'tls'))
            self.stack.enter_context(mock.patch.object(subject.authorization, '_registry',
                                                      side_effect=lambda _create: os.open(self.root, os.O_RDONLY)))
            self.stack.enter_context(mock.patch.object(subject.authorization, '_locked',
                                                      side_effect=lambda _fd: os.open('/dev/null', os.O_RDONLY)))
            self.stack.enter_context(mock.patch.object(subject.authorization, '_request', return_value=self.request))
            self.actual_relay = subject._relay
            self.relay_check = self.stack.enter_context(mock.patch.object(subject, '_relay',
                                                    return_value=(self.relay, '172.29.0.1')))
            self.actual_port_free = subject._port_free
            self.port = self.stack.enter_context(mock.patch.object(subject, '_port_free'))
            self.stack.enter_context(mock.patch.object(subject.identity, 'verify', return_value=self.manifest))
            self.stack.enter_context(mock.patch.object(subject.reconcile, '_inspect', return_value=self.sidecar))
            self.snapshot = self.stack.enter_context(mock.patch.object(subject.reconcile, '_snapshot'))
            self.stack.enter_context(mock.patch.object(subject.reconcile, 'profile_sha256', return_value='2' * 64))
            self.docker = self.stack.enter_context(mock.patch.object(subject.reconcile, '_docker', side_effect=self.docker_call))

        def docker_call(self, *args):
            if args[:2] == ('container', 'ls'):
                return b''
            if args[0] == 'create':
                return (self.container_id + '\n').encode('ascii')
            raise AssertionError('unexpected Docker operation')

        def execute(self):
            return subject.prepare(self.request_sha, self.ca_sha, self.proxy_sha, self.reconciler_sha,
                                   self.proxy, self.reconciler)

        def test_prepare_creates_only_pinned_stopped_sidecar_and_private_pins(self):
            digest = self.execute()
            directory = self.parent / subject.NAME
            pins_bytes = (directory / 'pins.json').read_bytes()
            pins = json.loads(pins_bytes)
            self.assertEqual(digest, hashlib.sha256(pins_bytes).hexdigest())
            self.assertEqual(pins['relay_id'], self.request['relay_id'])
            self.assertEqual(pins['sidecar_id'], self.container_id)
            self.assertEqual(pins['gateway_ipv4'], '172.29.0.1')
            self.assertEqual((directory / 'proxy.mjs').read_bytes(), self.proxy)
            self.assertEqual((directory / 'reconcile.py').read_bytes(), self.reconciler)
            self.assertEqual((directory / 'pins.json').stat().st_mode & 0o777, 0o600)
            self.assertFalse((directory / 'prepare.pending').exists())
            self.assertEqual(self.docker.call_count, 2)
            args = self.docker.call_args.args
            self.assertEqual(args[0], 'create')
            self.assertIn('container:' + self.request['relay_id'], args)
            self.assertIn('--read-only', args)
            self.assertEqual(self.port.call_count, 2)
            self.snapshot.assert_called_once()
            with self.assertRaisesRegex(subject.reconcile.Hold, 'REGISTRY_OCCUPIED'):
                self.execute()
            self.assertEqual((directory / 'pins.json').read_bytes(), pins_bytes)

        def test_ambiguous_create_retains_marker_and_never_retries(self):
            def fail_create(*args):
                if args[:2] == ('container', 'ls'):
                    return b''
                raise subprocess.TimeoutExpired('synthetic-docker', 1)
            self.docker.side_effect = fail_create
            with self.assertRaises(subprocess.TimeoutExpired):
                self.execute()
            directory = self.parent / subject.NAME
            self.assertTrue((directory / 'prepare.pending').is_file())
            self.assertFalse((directory / 'pins.json').exists())
            with self.assertRaisesRegex(subject.reconcile.Hold, 'REGISTRY_OCCUPIED'):
                self.execute()
            self.assertEqual(sum(call.args[0] == 'create' for call in self.docker.call_args_list), 1)

        def test_post_create_drift_keeps_marker_and_does_not_start_or_delete(self):
            self.snapshot.side_effect = subject.reconcile.Hold('SIDECAR_PROFILE')
            with self.assertRaisesRegex(subject.reconcile.Hold, 'SIDECAR_PROFILE'):
                self.execute()
            directory = self.parent / subject.NAME
            self.assertTrue((directory / 'prepare.pending').exists())
            self.assertFalse((directory / 'pins.json').exists())
            self.assertEqual([call.args[0] for call in self.docker.call_args_list], ['container', 'create'])

        def test_replaced_pending_marker_is_never_removed(self):
            def replace_marker(*_args):
                marker = self.parent / subject.NAME / 'prepare.pending'
                with marker.open('rb') as old:
                    content = old.read()
                    marker.unlink()
                    marker.write_bytes(content)
                    marker.chmod(0o600)
            self.snapshot.side_effect = replace_marker
            with self.assertRaisesRegex(subject.reconcile.Hold, 'MARKER_DRIFT'):
                self.execute()
            self.assertTrue((self.parent / subject.NAME / 'prepare.pending').exists())

        def test_invalid_source_or_occupied_name_causes_no_install(self):
            with self.assertRaisesRegex(subject.reconcile.Hold, 'SOURCE_DRIFT'):
                subject.prepare(self.request_sha, self.ca_sha, self.proxy_sha, self.reconciler_sha,
                                b'changed', self.reconciler)
            self.assertEqual(list(self.parent.iterdir()), [])
            self.docker.side_effect = lambda *args: (subject.CONTAINER + '\n').encode('ascii')
            with self.assertRaisesRegex(subject.reconcile.Hold, 'CONTAINER_OCCUPIED'):
                self.execute()
            self.assertEqual(list(self.parent.iterdir()), [])

        def test_source_file_hash_and_symlink_are_checked(self):
            source = self.root / 'source'
            source.write_bytes(self.proxy)
            self.assertEqual(subject._source(source, self.proxy_sha), self.proxy)
            with self.assertRaisesRegex(subject.reconcile.Hold, 'SOURCE_DRIFT'):
                subject._source(source, '0' * 64)
            link = self.root / 'link'
            link.symlink_to(source)
            with self.assertRaises(OSError):
                subject._source(link, self.proxy_sha)

        def test_occupied_ipv4_or_ipv6_listener_is_refused(self):
            with mock.patch.object(subject.authorization, '_run', return_value=b'LISTEN 0 8 0.0.0.0:3001 0.0.0.0:*\n'):
                with self.assertRaisesRegex(subject.reconcile.Hold, 'PORT_OCCUPIED'):
                    self.actual_port_free(1)
            with mock.patch.object(subject.authorization, '_run', return_value=b'LISTEN 0 8 [::]:3001 [::]:*\n'):
                with self.assertRaisesRegex(subject.reconcile.Hold, 'PORT_OCCUPIED'):
                    self.actual_port_free(1)
            with mock.patch.object(subject.authorization, '_run', return_value=b'LISTEN 0 8 0.0.0.0:30010 0.0.0.0:*\n'):
                self.actual_port_free(1)

        def test_relay_requires_internal_bridge_and_static_pinned_address(self):
            relay = {'Id': self.request['relay_id'], 'Image': self.request['relay_image'],
                     'Name': '/' + subject.authorization.RELAY_NAME,
                     'State': {'Running': True, 'Paused': False, 'Restarting': False},
                     'NetworkSettings': {'Networks': {subject.authorization.NETWORK_NAME: {
                         'NetworkID': self.request['network_id'], 'IPAddress': self.request['relay_ip'],
                         'IPAMConfig': {'IPv4Address': self.request['relay_ip']}, 'GlobalIPv6Address': ''}}}}
            network = {'Id': self.request['network_id'], 'Name': subject.authorization.NETWORK_NAME,
                       'Driver': 'bridge', 'Internal': True, 'EnableIPv6': False,
                       'IPAM': {'Config': [{'Subnet': '172.29.0.0/24', 'Gateway': '172.29.0.1'}]},
                       'Containers': {self.request['relay_id']: {}}}
            image = {'Id': self.request['relay_image'], 'Config': {'Volumes': None}}
            def inspect(kind, _identity):
                return {'container': relay, 'network': network, 'image': image}[kind]
            with mock.patch.object(subject.authorization, 'snapshot', return_value=self.request), \
                 mock.patch.object(subject.reconcile, '_inspect', side_effect=inspect):
                self.assertEqual(self.actual_relay(self.request)[1], '172.29.0.1')
                relay['NetworkSettings']['Networks'][subject.authorization.NETWORK_NAME]['IPAMConfig'] = None
                with self.assertRaisesRegex(subject.reconcile.Hold, 'RELAY'):
                    self.actual_relay(self.request)
                relay['NetworkSettings']['Networks'][subject.authorization.NETWORK_NAME]['IPAMConfig'] = {
                    'IPv4Address': self.request['relay_ip']}
                network['Internal'] = False
                with self.assertRaisesRegex(subject.reconcile.Hold, 'NETWORK'):
                    self.actual_relay(self.request)

        def test_cli_requires_explicit_approval(self):
            output = io.StringIO()
            arguments = ['prepare', '--request-sha256', self.request_sha, '--ca-sha256', self.ca_sha,
                         '--proxy-sha256', self.proxy_sha, '--reconciler-sha256', self.reconciler_sha]
            with mock.patch.object(sys, 'argv', arguments), redirect_stdout(output):
                self.assertEqual(subject.main(), 2)
            self.assertEqual(output.getvalue(), 'H454_SIDECAR_PREPARE=HOLD\nH454_SIDECAR_PREPARE_REASON=APPROVAL\n')


if __name__ == '__main__':
    unittest.main()
