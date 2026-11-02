import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from scripts import h454_wss_relay_reconcile as subject


if os.name == 'posix' and os.geteuid() == 0:
    class RelayReconcileTests(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory(prefix='h454-reconcile-')
            self.root = Path(self.temp.name)
            self.directory = self.root / 'operator'
            self.tls = self.root / 'tls'
            self.directory.mkdir(mode=0o700)
            self.tls.mkdir(mode=0o700)
            self.files = {'proxy.mjs': b'synthetic proxy', 'ca.crt': b'synthetic ca',
                          'relay.crt': b'synthetic certificate', 'relay.key': b'synthetic private key'}
            for name, data in self.files.items():
                path = (self.directory if name == 'proxy.mjs' else self.tls) / name
                path.write_bytes(data)
                path.chmod(0o440 if name == 'relay.key' else 0o444)
                if name == 'relay.key':
                    os.chown(path, 0, 65534)
            digest = lambda name: hashlib.sha256(self.files[name]).hexdigest()
            self.pins = {'version': 1, 'relay_id': 'a' * 64, 'relay_name': 'synthetic-relay',
                         'relay_image': 'sha256:' + 'b' * 64, 'network_id': 'c' * 64,
                         'network_name': 'synthetic-network', 'relay_ipv4': '172.29.0.2',
                         'gateway_ipv4': '172.29.0.1', 'sidecar_id': 'd' * 64,
                         'sidecar_name': 'synthetic-sidecar', 'sidecar_image': 'sha256:' + 'e' * 64,
                         'profile_sha256': 'f' * 64, 'proxy_sha256': digest('proxy.mjs'),
                         'ca_sha256': digest('ca.crt'), 'certificate_sha256': digest('relay.crt'),
                         'key_sha256': digest('relay.key'), 'tls_directory': str(self.tls)}
            self.config = self.directory / 'pins.json'
            self.write_pins()
            self.relay = {'Id': self.pins['relay_id'], 'Name': '/synthetic-relay',
                          'Image': self.pins['relay_image'],
                          'State': {'Running': True, 'Paused': False, 'Restarting': False, 'Pid': 101},
                          'NetworkSettings': {'Networks': {'synthetic-network': {
                              'NetworkID': self.pins['network_id'], 'IPAddress': '172.29.0.2',
                              'IPAMConfig': {'IPv4Address': '172.29.0.2'}, 'GlobalIPv6Address': ''}}}}
            self.network = {'Id': self.pins['network_id'], 'Name': 'synthetic-network', 'Driver': 'bridge',
                            'Internal': True, 'EnableIPv6': False,
                            'IPAM': {'Config': [{'Subnet': '172.29.0.0/24', 'Gateway': '172.29.0.1'}]},
                            'Containers': {self.pins['relay_id']: {}}}
            mounts = [('/run/h454-wss/proxy.mjs', self.directory / 'proxy.mjs'),
                      ('/run/h454-wss/relay.key', self.tls / 'relay.key'),
                      ('/run/h454-wss/relay.crt', self.tls / 'relay.crt')]
            self.sidecar = {'Id': self.pins['sidecar_id'], 'Name': '/synthetic-sidecar',
                            'Image': self.pins['sidecar_image'],
                            'State': {'Running': True, 'Paused': False, 'Restarting': False, 'Dead': False,
                                      'Status': 'running', 'Pid': 102},
                            'Config': {'User': '65534:65534', 'Entrypoint': ['node'],
                                       'Cmd': ['/run/h454-wss/proxy.mjs'],
                                       'Env': ['H454_SSH_SOURCE_IPV4=172.29.0.1']},
                            'HostConfig': {'NetworkMode': 'container:' + self.pins['relay_id'],
                                           'ReadonlyRootfs': True, 'Privileged': False, 'CapDrop': ['ALL'],
                                           'SecurityOpt': ['no-new-privileges'],
                                           'PidsLimit': 32, 'Memory': 134_217_728,
                                           'RestartPolicy': {'Name': 'unless-stopped'},
                                           'PortBindings': {}, 'PublishAllPorts': False},
                            'Mounts': [{'Type': 'bind', 'RW': False, 'Destination': dest, 'Source': str(src)}
                                       for dest, src in mounts]}
            self.pins['profile_sha256'] = subject.profile_sha256(self.sidecar)
            self.write_pins()

        def tearDown(self):
            self.temp.cleanup()

        def write_pins(self):
            self.config.write_text(json.dumps(self.pins), encoding='ascii')
            self.config.chmod(0o600)

        def inspect(self, kind, identity):
            objects = {('container', self.pins['relay_id']): self.relay,
                       ('container', self.pins['sidecar_id']): self.sidecar,
                       ('network', self.pins['network_id']): self.network}
            return copy.deepcopy(objects[kind, identity])

        def test_snapshot_accepts_only_pinned_read_only_private_profile(self):
            with mock.patch.object(subject, '_inspect', side_effect=self.inspect):
                subject._snapshot(self.pins, self.directory, self.tls)
                self.sidecar['HostConfig']['Privileged'] = True
                self.pins['profile_sha256'] = subject.profile_sha256(self.sidecar)
                with self.assertRaisesRegex(subject.Hold, 'SIDECAR'):
                    subject._snapshot(self.pins, self.directory, self.tls)
                self.sidecar['HostConfig']['Privileged'] = False
                self.pins['profile_sha256'] = subject.profile_sha256(self.sidecar)
                self.relay['NetworkSettings']['Networks']['synthetic-network']['IPAMConfig'] = None
                with self.assertRaisesRegex(subject.Hold, 'RELAY_NETWORK'):
                    subject._snapshot(self.pins, self.directory, self.tls)

        def test_running_sidecar_is_only_checked(self):
            with mock.patch.object(subject, '_inspect', side_effect=self.inspect), \
                 mock.patch.object(subject, '_namespace') as namespace, \
                 mock.patch.object(subject, '_tls') as tls, mock.patch.object(subject, '_docker') as docker:
                self.assertEqual(subject.reconcile(self.config), 'READY')
            namespace.assert_called_once()
            tls.assert_called_once()
            docker.assert_not_called()
            self.assertFalse((self.directory / subject.MARKER).exists())

        def test_exited_sidecar_starts_once_after_checks_and_clears_marker(self):
            exited = copy.deepcopy(self.sidecar)
            exited['State'].update(Running=False, Status='exited', Pid=0)
            with mock.patch.object(subject, '_snapshot', side_effect=[(self.relay, exited), (self.relay, self.sidecar)]), \
                 mock.patch.object(subject, '_namespace'), mock.patch.object(subject, '_tls'), \
                 mock.patch.object(subject, '_docker', return_value=(self.pins['sidecar_id'] + '\n').encode()) as docker:
                self.assertEqual(subject.reconcile(self.config), 'RESTARTED')
            docker.assert_called_once_with('start', self.pins['sidecar_id'])
            self.assertFalse((self.directory / subject.MARKER).exists())

        def test_ambiguous_start_retains_marker_and_prevents_retry(self):
            exited = copy.deepcopy(self.sidecar)
            exited['State'].update(Running=False, Status='exited', Pid=0)
            with mock.patch.object(subject, '_snapshot', return_value=(self.relay, exited)), \
                 mock.patch.object(subject, '_docker', side_effect=TimeoutError('private detail')) as docker:
                with self.assertRaises(TimeoutError):
                    subject.reconcile(self.config)
                with self.assertRaisesRegex(subject.Hold, 'PENDING'):
                    subject.reconcile(self.config)
            docker.assert_called_once()
            self.assertTrue((self.directory / subject.MARKER).is_file())

        def test_symlink_and_duplicate_pins_are_refused_before_start(self):
            proxy = self.directory / 'proxy.mjs'
            proxy.unlink()
            proxy.symlink_to(self.tls / 'ca.crt')
            with mock.patch.object(subject, '_docker') as docker, self.assertRaises(OSError):
                subject.reconcile(self.config)
            docker.assert_not_called()
            with self.assertRaisesRegex(subject.Hold, 'PINS'):
                subject._pins(b'{"version":1,"version":1}')

        def test_files_and_network_must_remain_private(self):
            (self.tls / 'relay.key').chmod(0o444)
            with mock.patch.object(subject, '_docker') as docker, self.assertRaisesRegex(subject.Hold, 'FILE'):
                subject.reconcile(self.config)
            docker.assert_not_called()
            self.network['Internal'] = False
            with mock.patch.object(subject, '_inspect', side_effect=self.inspect), \
                 self.assertRaisesRegex(subject.Hold, 'NETWORK'):
                subject._snapshot(self.pins, self.directory, self.tls)

        def test_pinned_profile_cannot_authorize_unbounded_or_unsafe_runtime(self):
            for change in ('memory', 'pids', 'capability', 'environment'):
                with self.subTest(change=change):
                    saved = copy.deepcopy(self.sidecar)
                    if change == 'memory':
                        self.sidecar['HostConfig']['Memory'] = 0
                    elif change == 'pids':
                        self.sidecar['HostConfig']['PidsLimit'] = 0
                    elif change == 'capability':
                        self.sidecar['HostConfig']['CapAdd'] = ['SYS_ADMIN']
                    else:
                        self.sidecar['Config']['Env'].append('NODE_OPTIONS=--require=/tmp/evil')
                    self.pins['profile_sha256'] = subject.profile_sha256(self.sidecar)
                    with mock.patch.object(subject, '_inspect', side_effect=self.inspect), \
                         self.assertRaisesRegex(subject.Hold, 'SIDECAR'):
                        subject._snapshot(self.pins, self.directory, self.tls)
                    self.sidecar = saved

        def test_mount_order_is_irrelevant_but_mount_permissions_are_not(self):
            original = subject.profile_sha256(self.sidecar)
            self.sidecar['Mounts'].reverse()
            self.assertEqual(subject.profile_sha256(self.sidecar), original)
            with mock.patch.object(subject, '_inspect', side_effect=self.inspect):
                subject._snapshot(self.pins, self.directory, self.tls)
                self.sidecar['Mounts'][0]['RW'] = True
                self.pins['profile_sha256'] = subject.profile_sha256(self.sidecar)
                with self.assertRaisesRegex(subject.Hold, 'SIDECAR_MOUNTS'):
                    subject._snapshot(self.pins, self.directory, self.tls)
                self.sidecar['Mounts'][0]['Destination'] = self.sidecar['Mounts'][1]['Destination']
                with self.assertRaisesRegex(subject.Hold, 'SIDECAR_PROFILE'):
                    subject.profile_sha256(self.sidecar)

        def test_directory_under_untrusted_nonsticky_parent_is_refused(self):
            parent = self.root / 'writable'
            parent.mkdir(mode=0o777)
            parent.chmod(0o777)
            child = parent / 'private'
            child.mkdir(mode=0o700)
            with self.assertRaisesRegex(subject.Hold, 'DIRECTORY'):
                subject._directory(child)

        def test_tls_probe_requires_pinned_ca_and_server_name(self):
            certificates = self.root / 'certificates'
            certificates.mkdir()
            script = Path(__file__).resolve().parents[1] / 'scripts' / 'h454_wss_fixture_certificates.sh'
            subprocess.run(['sh', str(script), str(certificates)], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=30, check=True)
            ca = (certificates / 'ca.crt').read_bytes()
            real_connect = socket.create_connection

            def probe(certificate, key, trust, *, succeeds):
                server = socket.socket()
                server.bind(('127.0.0.1', 0))
                server.listen(1)
                server.settimeout(5)
                port = server.getsockname()[1]
                errors = []

                def serve():
                    try:
                        conn, _ = server.accept()
                        with conn:
                            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                            context.load_cert_chain(str(certificates / certificate), str(certificates / key))
                            with context.wrap_socket(conn, server_side=True) as secure:
                                secure.recv(4096)
                                secure.sendall(b'HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n')
                    except ssl.SSLError:
                        if succeeds:
                            errors.append('TLS')
                    except Exception:
                        errors.append('SERVER')
                    finally:
                        server.close()

                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                try:
                    with mock.patch.object(subject.socket, 'create_connection',
                                           side_effect=lambda _address, timeout: real_connect(('127.0.0.1', port), timeout)):
                        if succeeds:
                            subject._tls(self.pins, trust)
                        else:
                            with self.assertRaises(ssl.SSLCertVerificationError):
                                subject._tls(self.pins, trust)
                finally:
                    thread.join(timeout=7)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])

            probe('trusted.crt', 'trusted.key', ca, succeeds=True)
            probe('wrong.crt', 'wrong.key', ca, succeeds=False)
            with mock.patch.dict(os.environ, {'SSL_CERT_FILE': str(certificates / 'fake.crt')}):
                probe('fake.crt', 'fake.key', ca, succeeds=False)


if __name__ == '__main__':
    unittest.main()
