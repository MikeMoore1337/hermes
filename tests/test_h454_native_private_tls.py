"""H454 native WSS/status private TLS, no original host or real bearer."""
from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from device_fabric import native_private_tls as direct
from scripts import h454_native_linux_service as service
from scripts import h454_native_linux_active_unit as unit
from device_fabric.native_install_preview import SCHEMA, SERVICE

RELEASE = 'a' * 40
IDENTITY = 'h454-linux-hermes-' + 'a' * 32
TOKEN = 'brc_dev_' + 'x' * 64
WRONG = 'brc_dev_' + 'y' * 64


class TrustLoading(unittest.TestCase):
    def _manifest(self, ca: bytes, **overrides):
        doc = {'schema':'h454-private-relay-v1','target':'hermes-vps',
               'release_sha':RELEASE,'relay_ipv4':'172.29.251.2',
               'ca_sha256':hashlib.sha256(ca).hexdigest(),
               'server_name':'brc-agent.internal','port':3001}
        doc.update(overrides)
        return json.dumps(doc,sort_keys=True,separators=(',',':')).encode()

    def test_exact_pinned_config_and_ca_only(self):
        # The separate TLS fixture validates the actual cert, here the
        # filesystem adapter is mocked to test canonical schema and SHA.
        ca=b'-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----\n'
        with patch.object(direct,'_guard_dir'), patch.object(direct,'_context'):
            with patch.object(direct,'_read',side_effect=[self._manifest(ca),ca]):
                r=direct.load_private_relay('hermes-vps',RELEASE)
                self.assertEqual(r.relay_ipv4,'172.29.251.2')
                self.assertNotIn('synthetic',repr(r))
            for corrupted in (self._manifest(ca,relay_ipv4='8.8.8.8'),
                              self._manifest(ca,relay_ipv4='127.0.0.1'),
                              self._manifest(ca,server_name='evil.invalid'),
                              self._manifest(ca,port=443),
                              self._manifest(ca,ca_sha256='0'*64),
                              self._manifest(ca)+b'\n'):
                with patch.object(direct,'_read',side_effect=[corrupted,ca]),self.assertRaises(direct.PrivateTLSDenied):
                    direct.load_private_relay('hermes-vps',RELEASE)

    def test_private_ip_and_exact_mode(self):
        for text in ('172.29.251.2','10.20.0.2','192.168.0.2'):
            self.assertTrue(direct._private_ip(text))
        for text in ('0.0.0.0','127.0.0.1','169.254.10.2','8.8.8.8',
                     '172.32.0.1','1.2.3.4','172.29.251.2/32'):
            self.assertFalse(direct._private_ip(text))
        lines = '\n'.join([f'{k}={v}' for k,v in service.EXPECTED_HARDENING.items()]+[
            'IPAddressDeny=any','IPAddressAllow=172.29.251.2/32',
            'CapabilityBoundingSet='])
        self.assertTrue(service._properties_are_hardened(lines,
                       private_relay_ip='172.29.251.2'))
        self.assertFalse(service._properties_are_hardened(lines))
        self.assertFalse(service._properties_are_hardened(lines.replace('IPAddressAllow=172.29.251.2/32',
            'IPAddressAllow=172.29.251.2/32 8.8.8.8/32'),
            private_relay_ip='172.29.251.2'))
        self.assertFalse(service._properties_are_hardened(lines.replace('IPAddressDeny=any','IPAddressDeny='),
            private_relay_ip='172.29.251.2'))

    def test_unix_transport_is_yfc_only_and_denies_all_ip(self):
        ca=b'-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----\n'
        doc=json.loads(self._manifest(ca))
        doc.update(schema='h454-private-relay-unix-v1',target='yfc-vps',relay_socket=direct.UNIX_SOCKET)
        del doc['relay_ipv4']
        encode=lambda obj: json.dumps(obj,sort_keys=True,separators=(',',':')).encode()
        with patch.object(direct, '_guard_dir'), patch.object(direct, '_context'):
            with patch.object(direct, '_read', side_effect=[encode(doc),ca]):
                self.assertEqual(direct.load_private_relay('yfc-vps', RELEASE).relay_ipv4, direct.UNIX_ENDPOINT)
            for key,value in (('target','hermes-vps'),('relay_socket','/tmp/relay.sock'),('port',443)):
                changed=dict(doc, **{key:value})
                with patch.object(direct,'_read',side_effect=[encode(changed),ca]), self.assertRaises(direct.PrivateTLSDenied):
                    direct.load_private_relay('yfc-vps', RELEASE)
        lines='\n'.join([f'{k}={"yes" if k == "PrivateNetwork" else v}' for k,v in service.EXPECTED_HARDENING.items()]+[
            'LimitNOFILE=32768','StandardInput=null','StandardOutput=journal','StandardError=journal',
            'RestrictAddressFamilies=AF_UNIX','IPAddressDeny=any','IPAddressAllow=','CapabilityBoundingSet=',
            'TemporaryFileSystem=/run:ro','BindPaths=','BindReadOnlyPaths='+' '.join(
                f'{p}:{p}:rbind' for p in (direct.UNIX_DIRECTORY,direct.AUDIT_DIRECTORY))])
        self.assertTrue(service._properties_are_hardened(lines,private_relay_ip=direct.UNIX_ENDPOINT,target='yfc-vps'))
        for changed in (lines.replace('PrivateNetwork=yes','PrivateNetwork=no'),
                        lines.replace('IPAddressAllow=','IPAddressAllow=127.0.0.1/32'),
                        lines.replace('RestrictAddressFamilies=AF_UNIX','RestrictAddressFamilies=AF_UNIX AF_INET'),
                        lines.replace('TemporaryFileSystem=/run:ro','TemporaryFileSystem='),
                        lines.replace('BindPaths=','BindPaths=/run/postgresql:/run/postgresql:rbind'),
                        lines.replace('BindReadOnlyPaths=','BindReadOnlyPaths=/run/postgresql:/run/postgresql:rbind ')):
            self.assertFalse(service._properties_are_hardened(changed,private_relay_ip=direct.UNIX_ENDPOINT,target='yfc-vps'))
        self.assertFalse(service._properties_are_hardened(lines,private_relay_ip=direct.UNIX_ENDPOINT,target='hermes-vps'))

    def test_hermes_landlock_requires_private_run_and_only_audit_socket(self):
        values = dict(service.EXPECTED_HARDENING, LimitNOFILE='32768',
            StandardInput='null', StandardOutput='journal', StandardError='journal',
            TemporaryFileSystem='/run:ro', BindPaths='',
            RestrictAddressFamilies='AF_INET AF_INET6 AF_UNIX',
            BindReadOnlyPaths=direct.AUDIT_DIRECTORY+':'+direct.AUDIT_DIRECTORY+':rbind',
            IPAddressDeny='any', IPAddressAllow='172.29.251.2/32', CapabilityBoundingSet='')
        def checked(props):
            text='\n'.join(k+'='+v for k,v in props.items())
            return service._properties_are_hardened(text,private_relay_ip='172.29.251.2',target='hermes-vps')
        self.assertTrue(checked(values))
        for changes in ({'TemporaryFileSystem':''},{'BindPaths':'/run/systemd/private'},
                        {'BindReadOnlyPaths':''},{'BindReadOnlyPaths':values['BindReadOnlyPaths']+' /run/systemd/private'},
                        {'StandardInput':'socket'},{'LimitNOFILE':'1024'},
                        {'RestrictAddressFamilies':'AF_UNIX AF_INET AF_INET6 AF_NETLINK'},
                        {'IPAddressAllow':'0.0.0.0/0'}):
            with self.subTest(changes=changes):
                self.assertFalse(checked(dict(values,**changes)))

    def test_yfc_unix_unit_has_no_ip_egress(self):
        manifest=json.dumps({'schema':SCHEMA,'target':'yfc-vps','release_sha':RELEASE,
            'artifact_sha256':'c'*64,'service_name':SERVICE['yfc-vps'][0],
            'service_identity':SERVICE['yfc-vps'][1],'start_state':'DISABLED',
            'access_mode':'READ_ONLY','roots':[{'project':'your-fitness-coach','path':'/srv/yfc/source'}]},
            sort_keys=True,separators=(',',':')).encode('ascii')
        args=dict(manifest=manifest,target='yfc-vps',release_sha=RELEASE,
            manifest_sha256=hashlib.sha256(manifest).hexdigest(),relay_ipv4=direct.UNIX_ENDPOINT,
            dns_ipv4='',private_relay=True)
        rendered=unit.render_active_unit(**args)
        self.assertIn('PrivateNetwork=yes\n',rendered)
        self.assertIn('RestrictAddressFamilies=AF_UNIX\n',rendered)
        self.assertIn('IPAddressDeny=any\n',rendered)
        self.assertIn('LimitNOFILE=32768\n',rendered)
        self.assertIn('StandardInput=null\n',rendered)
        self.assertIn('TemporaryFileSystem=/run:ro\n',rendered)
        self.assertIn('BindReadOnlyPaths='+direct.UNIX_DIRECTORY+'\n',rendered)
        self.assertNotIn('IPAddressAllow=',rendered)

    def test_websocket_never_uses_public_ip_for_network(self):
        config=direct.PrivateRelay('hermes-vps',RELEASE,'172.29.251.2',b'fake-ca')
        recorded=[]
        fake=type('S',(),{'close':lambda self:None})()
        def underlying(uri,**kw):
            recorded.append((uri,kw))
            return 'synthetic-only'
        with (patch.object(direct.socket,'create_connection',return_value=fake) as connection,
              patch.object(direct,'_context',return_value=object())):
            ws=direct.private_websocket_connector(config,underlying)
            headers={'Authorization':'Bearer '+TOKEN,'X-BRC-Protocol':'1'}
            options={'additional_headers':headers,'open_timeout':10,'close_timeout':3,
                     'compression':None,'proxy':None,'max_size':8192,
                     'ping_interval':20,'ping_timeout':20}
            self.assertEqual(ws(direct.ENDPOINT,**options),'synthetic-only')
            connection.assert_called_once_with(('172.29.251.2',3001),timeout=8)
            self.assertEqual(recorded[0][0],direct.WS_URI)
            self.assertEqual(recorded[0][1]['server_hostname'],'brc-agent.internal')
            self.assertIs(recorded[0][1]['sock'],fake)
            with self.assertRaises(direct.PrivateTLSDenied):
                ws('wss://evil.invalid/ws',**options)
            with self.assertRaises(direct.PrivateTLSDenied):
                ws(direct.ENDPOINT,**dict(options,proxy=True))
            with self.assertRaises(direct.PrivateTLSDenied):
                ws(direct.ENDPOINT,**dict(options,additional_headers={'Authorization':'Bearer '+TOKEN}))
            connection.assert_called_once()

    def test_handshake_timeout_is_distinct_from_bad_certificate(self):
        config=direct.PrivateRelay('hermes-vps',RELEASE,'172.29.251.2',b'fake-ca')
        options={'additional_headers':{'Authorization':'Bearer '+TOKEN,'X-BRC-Protocol':'1'},
                 'open_timeout':10,'close_timeout':3,'compression':None,'proxy':None,
                 'max_size':8192,'ping_interval':20,'ping_timeout':20}
        for error, expected in ((TimeoutError('private detail'), TimeoutError),
                                (ssl.SSLCertVerificationError('private detail'), direct.PrivateTLSDenied)):
            with self.subTest(error=type(error).__name__):
                closed=[]
                raw=type('S',(),{'close':lambda self:closed.append(True)})()
                def underlying(*_args, **_kwargs):
                    raise error
                with (patch.object(direct.socket,'create_connection',return_value=raw),
                      patch.object(direct,'_context',return_value=object())):
                    with self.assertRaises(expected) as caught:
                        direct.private_websocket_connector(config,underlying)(direct.ENDPOINT,**options)
                self.assertEqual(closed,[True])
                self.assertNotIn('private detail',str(caught.exception))


    def test_render_private_hermes_unit_blocks_all_public_egress(self):
        manifest = json.dumps({
            "schema": SCHEMA,
            "target": "hermes-vps",
            "release_sha": RELEASE,
            "artifact_sha256": "c" * 64,
            "service_name": SERVICE["hermes-vps"][0],
            "service_identity": SERVICE["hermes-vps"][1],
            "start_state": "DISABLED",
            "access_mode": "READ_ONLY",
            "roots": [{"project": "hermes", "path": "/srv/hermes/source"}],
        }, sort_keys=True, separators=(",", ":")).encode("ascii")
        params = {
            "manifest": manifest, "target": "hermes-vps",
            "release_sha": RELEASE,
            "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            "relay_ipv4": "172.29.251.2", "dns_ipv4": "",
            "private_relay": True,
        }
        rendered = unit.render_active_unit(**params)
        self.assertIn("IPAddressDeny=any\n", rendered)
        self.assertEqual(
            [line for line in rendered.splitlines() if line.startswith("IPAddressAllow=")],
            ["IPAddressAllow=172.29.251.2/32"],
        )
        self.assertIn("AssertPathExists=" + str(direct.TRUST / direct.CA), rendered)
        self.assertIn("AssertPathExists=" + str(direct.TRUST / direct.CONFIG), rendered)
        self.assertIn("ReadOnlyPaths=" + str(direct.TRUST), rendered)
        self.assertIn("NoNewPrivileges=yes", rendered)
        self.assertIn("RestrictSUIDSGID=no", rendered)
        for ip, dns in (
            ("8.8.8.8", ""), ("127.0.0.1", ""),
            ("172.29.251.2,172.29.251.3", ""),
            ("172.29.251.2", "127.0.0.53"),
        ):
            with self.subTest(ip=ip, dns=dns), self.assertRaises(
                unit.LinuxActiveUnitDenied
            ):
                unit.render_active_unit(**dict(params, relay_ipv4=ip, dns_ipv4=dns))


class LocalCertificateE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        folder=Path(cls.tmp.name)
        cls.ca=folder/'ca.crt';cakey=folder/'ca.key'
        cert=folder/'relay.crt';key=folder/'relay.key'
        csr=folder/'relay.csr';ext=folder/'ext.conf'
        ext.write_text('subjectAltName=DNS:brc-agent.internal\nextendedKeyUsage=serverAuth\n')
        def openssl(*args):
            subprocess.run(['openssl',*map(str,args)],capture_output=True,check=True,timeout=15)
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',cakey,
                '-out',cls.ca,'-days','1','-subj','/CN=synthetic-ca',
                '-addext','basicConstraints=critical,CA:TRUE',
                '-addext','keyUsage=critical,keyCertSign,cRLSign')
        cls.other_ca=folder/'other-ca.crt'
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',folder/'other-ca.key',
                '-out',cls.other_ca,'-days','1','-subj','/CN=other-synthetic-ca',
                '-addext','basicConstraints=critical,CA:TRUE',
                '-addext','keyUsage=critical,keyCertSign,cRLSign')
        openssl('req','-newkey','rsa:2048','-nodes','-keyout',key,'-out',csr,
                '-subj','/CN=brc-agent.internal')
        openssl('x509','-req','-in',csr,'-CA',cls.ca,'-CAkey',cakey,
                '-CAcreateserial','-out',cert,'-days','1','-extfile',ext)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert),str(key))
        cls.server_context=context
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != '/device/native-status' or self.headers.get('Authorization')!='Bearer '+TOKEN:
                    self.send_response(403);self.send_header('Content-Length','0');self.end_headers();return
                content=json.dumps({'schema':'h454-native-device-status-v1',
                    'device_id':IDENTITY,'active':True,'owner_bound':True},
                    separators=(',',':')).encode('ascii')
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(content)))
                self.end_headers();self.wfile.write(content)
            def log_message(self,*args):pass
        cls.server=HTTPServer(('127.0.0.1',0),Handler)
        cls.server.socket=context.wrap_socket(cls.server.socket,server_side=True)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(timeout=3)
        cls.tmp.cleanup()

    def test_authenticated_status_and_revocation_over_real_pinned_tls(self):
        ca=self.ca.read_bytes()
        pinned=direct.PrivateRelay('hermes-vps',RELEASE,'127.0.0.1',ca)
        with patch.object(direct,'PORT',self.server.server_address[1]):
            self.assertTrue(direct.current_bearer(pinned,target='hermes-vps',device_id=IDENTITY,bearer=TOKEN))
            self.assertFalse(direct.current_bearer(pinned,target='hermes-vps',device_id=IDENTITY,bearer=WRONG))
            self.assertTrue(direct.private_revoked_provider(pinned,target='hermes-vps',device_id=IDENTITY,bearer=WRONG,
                base_url=direct.PUBLIC)())
            self.assertFalse(direct.private_revoked_provider(pinned,target='hermes-vps',device_id=IDENTITY,bearer=TOKEN,
                base_url=direct.PUBLIC)())
            with self.assertRaises(direct.PrivateTLSDenied):
                direct.private_revoked_provider(pinned,target='hermes-vps',device_id=IDENTITY,bearer=TOKEN,
                    base_url='http://localhost:3000')

    def test_wrong_ca_cannot_send_bearer(self):
        pinned=direct.PrivateRelay('hermes-vps',RELEASE,'127.0.0.1',b'bad ca data')
        with patch.object(direct,'PORT',self.server.server_address[1]):
            self.assertFalse(direct.current_bearer(pinned,target='hermes-vps',device_id=IDENTITY,bearer=TOKEN))

    def test_yfc_status_over_unix_socket_checks_real_tls_before_bearer(self):
        device='h454-linux-yfc-'+'a'*32
        requests=[]
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(True)
                if self.path != '/device/native-status' or self.headers.get('Authorization') != 'Bearer '+TOKEN:
                    self.send_response(403);self.send_header('Content-Length','0');self.end_headers();return
                body=json.dumps({'schema':'h454-native-device-status-v1','device_id':device,
                    'active':True,'owner_bound':True},separators=(',',':')).encode()
                self.send_response(200);self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*args): pass
        with tempfile.TemporaryDirectory() as folder:
            path=str(Path(folder)/'relay.sock')
            server=socketserver.UnixStreamServer(path,Handler)
            server.socket=self.server_context.wrap_socket(server.socket,server_side=True)
            worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
            try:
                good=direct.PrivateRelay('yfc-vps',RELEASE,direct.UNIX_ENDPOINT,self.ca.read_bytes())
                bad=direct.PrivateRelay('yfc-vps',RELEASE,direct.UNIX_ENDPOINT,self.other_ca.read_bytes())
                with patch.object(direct,'UNIX_SOCKET',path):
                    self.assertTrue(direct.current_bearer(good,target='yfc-vps',device_id=device,bearer=TOKEN))
                    self.assertEqual(len(requests),1)
                    self.assertFalse(direct.current_bearer(bad,target='yfc-vps',device_id=device,bearer=TOKEN))
                    self.assertEqual(len(requests),1)
            finally:
                server.shutdown();server.server_close();worker.join(timeout=3)
