"""Offline synthetic pairing and secret-delivery checks; no live hosts."""
import hashlib
import io
import json
import os
from contextlib import ExitStack, nullcontext
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from device_fabric.native_install_preview import SERVICE, SCHEMA, parse_candidate
from scripts import h454_yfc_owner_enrollment as owner
from scripts import h454_yfc_receive_credential as receiver


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


class EnrollmentBridgeTests(unittest.TestCase):
    def setUp(self):
        service,identity=SERVICE['yfc-vps']
        self.manifest=canonical({'schema':SCHEMA,'target':'yfc-vps','release_sha':receiver.RELEASE,
            'artifact_sha256':'a'*64,'service_name':service,'service_identity':identity,
            'start_state':'DISABLED','access_mode':'READ_ONLY',
            'roots':[{'project':'your-fitness-coach','path':receiver.SNAPSHOT}]})
        self.digest=hashlib.sha256(self.manifest).hexdigest()
        self.candidate=parse_candidate(self.manifest,expected_release=receiver.RELEASE,expected_target='yfc-vps')
        self.secret='brc_dev_'+'X'*55
        self.message=canonical({'device_id':'h454-linux-yfc-'+'b'*32,'token':self.secret})

    def test_pipe_binds_local_roots_and_rejects_foreign_identity_or_extra_fields(self):
        with patch.object(receiver,'MANIFEST_SHA',self.digest):
            payload=receiver.config_from_pipe(self.message,self.candidate)
            actual=json.loads(payload)
            self.assertEqual(actual['roots'],[{'project':'your-fitness-coach','path':receiver.SNAPSHOT}])
            self.assertEqual(actual['token'],self.secret)
            bad=[canonical({'device_id':'h454-linux-hermes-'+'b'*32,'token':self.secret}),
                 canonical({'device_id':'h454-linux-yfc-'+'b'*32,'token':self.secret,'roots':['/']}),
                 self.message+b'\n',self.message.replace(b'"token":',b'"token":"x","token":',1),
                 b'x'*2049]
            for raw in bad:
                with self.subTest(length=len(raw)),self.assertRaises(Exception) as error:
                    receiver.config_from_pipe(raw,self.candidate)
                self.assertNotIn(self.secret,str(error.exception))

    def test_receiver_plan_rejects_active_service_process_or_existing_device(self):
        with tempfile.TemporaryDirectory() as folder,ExitStack() as stack:
            state=Path(folder); manifest=state/'manifest.json'; manifest.write_bytes(self.manifest)
            unit=Path('/etc/systemd/system/hermes-commander-native.service')
            fake_user=SimpleNamespace(pw_uid=992,pw_gid=977,pw_dir='/nonexistent',pw_shell='/usr/sbin/nologin')
            properties={'ActiveState':'inactive','UnitFileState':'disabled','LoadState':'loaded',
                        'DropInPaths':'','NeedDaemonReload':'no','FragmentPath':str(unit),
                        'User':'hermes-commander-native','Group':'hermes-commander-native'}
            real_lstat=Path.lstat
            def stat_for(path,*args,**kwargs):
                value=real_lstat(path,*args,**kwargs)
                if path in (state,manifest):
                    return SimpleNamespace(st_mode=(0o40700 if path==state else 0o100600),st_uid=992,st_gid=977)
                return value
            status={'pgrep':1}
            def run(args,**kwargs): return SimpleNamespace(returncode=status['pgrep'] if args[0].endswith('pgrep') else 0)
            stack.enter_context(patch.multiple(receiver,STATE=state,MANIFEST_SHA=self.digest,
                                UNIT_SHA=hashlib.sha256(b'unit').hexdigest()))
            stack.enter_context(patch.object(receiver.os,'geteuid',return_value=0))
            stack.enter_context(patch.object(receiver.pwd,'getpwnam',return_value=fake_user))
            stack.enter_context(patch.object(Path,'lstat',stat_for))
            stack.enter_context(patch.object(Path,'is_socket',return_value=True))
            stack.enter_context(patch.object(receiver,'checked_file',side_effect=lambda p,*a,**k:self.manifest if p==manifest else b'unit'))
            stack.enter_context(patch.object(receiver,'raw_show',return_value=properties))
            stack.enter_context(patch.object(receiver.subprocess,'run',side_effect=run))
            stack.enter_context(patch.object(receiver,'load_private_relay'))
            stack.enter_context(patch.object(receiver,'_private_key',side_effect=lambda:os.open('/dev/null',os.O_RDONLY)))
            self.assertEqual(receiver.plan()[1],self.candidate)
            properties['ActiveState']='active'
            with self.assertRaises(receiver.Hold): receiver.plan()
            properties['ActiveState']='inactive'; status['pgrep']=0
            with self.assertRaises(receiver.Hold): receiver.plan()
            status['pgrep']=1; (state/'device.json').write_bytes(b'prior')
            with self.assertRaises(receiver.Hold): receiver.plan()

    def test_private_device_publish_is_exclusive_and_retains_existing_data(self):
        with tempfile.TemporaryDirectory() as folder:
            state=Path(folder); state.chmod(0o700); uid=os.getuid(); gid=os.getgid()
            receiver.write_device(state,uid,gid,b'synthetic-payload')
            device=state/'device.json'; before=device.read_bytes()
            self.assertEqual(before,b'synthetic-payload')
            self.assertEqual(device.stat().st_mode & 0o777,0o600)
            self.assertEqual(device.stat().st_nlink,1)
            self.assertFalse((state/receiver.PENDING).exists())
            with self.assertRaises(receiver.Hold): receiver.write_device(state,uid,gid,b'other')
            self.assertEqual(device.read_bytes(),before)

    def test_private_device_pending_and_symlink_fail_without_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            state=Path(folder); state.chmod(0o700); uid=os.getuid(); gid=os.getgid()
            pending=state/receiver.PENDING; pending.write_bytes(b'prior-attempt')
            with self.assertRaises(receiver.Hold): receiver.write_device(state,uid,gid,b'new')
            self.assertEqual(pending.read_bytes(),b'prior-attempt')
            pending.unlink(); target=state/'unrelated'; target.write_bytes(b'unchanged')
            (state/'device.json').symlink_to(target)
            with self.assertRaises(receiver.Hold): receiver.write_device(state,uid,gid,b'new')
            self.assertEqual(target.read_bytes(),b'unchanged')

    def test_line_reader_bounded_and_rejects_closed_stream(self):
        left,right=socket.socketpair()
        try:
            left.sendall(b'GOOD\n'); self.assertEqual(owner._line(right),b'GOOD')
            left.sendall(b'x'*5+b'\n')
            with self.assertRaises(owner.Hold): owner._line(right,limit=3)
        finally: left.close(); right.close()

    def test_owner_socket_preflight_never_reuses_existing_path(self):
        with tempfile.TemporaryDirectory() as folder:
            parent=Path(folder); run=parent/'run'; real=Path.lstat
            def as_root(path,*args,**kwargs):
                value=real(path,*args,**kwargs)
                if path==parent: return SimpleNamespace(st_mode=value.st_mode,st_uid=0)
                return value
            with patch.object(owner,'RUN',run),patch.object(Path,'lstat',as_root):
                owner._run_preflight()
                run.mkdir()
                with self.assertRaises(owner.Hold): owner._run_preflight()

    def test_local_relay_post_has_fixed_scope_and_secrets_only_on_stdin(self):
        calls=[]
        old={'NAME':{'yfc-vps':'YFC'},'RELAY':'d'*64,'_runtime_gate':lambda:None}
        def execute(args,**kwargs):
            calls.append((args,kwargs['input']))
            return SimpleNamespace(returncode=0,stdout=b'{"status":200,"body":"{}"}')
        with patch.object(owner.subprocess,'run',side_effect=execute):
            self.assertEqual(owner._post(old,'/device/start',b'{"client_name":"YFC"}'),(200,b'{}'))
            with self.assertRaises(owner.Hold): owner._post(old,'/admin',b'{}')
            with self.assertRaises(owner.Hold): owner._post(old,'/device/start',b'{"client_name":"OTHER"}')
            with self.assertRaises(owner.Hold): owner._post(old,'/device/poll',canonical({'name':'YFC','platform':'linux','device_code':'a'*32,'device_id':'caller-choice'}))
        self.assertEqual(len(calls),1)
        self.assertNotIn('YFC',' '.join(calls[0][0]))
        self.assertIn(b'YFC',calls[0][1])

    def test_sender_waits_for_both_gates_and_keeps_code_out_of_delivery_pipe(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); run=root/'run'; sock=run/'owner.sock'
            events=[]; delivered=[]; errors=[]
            pending=SimpleNamespace(user_code='ABCD-EFGH',expires_in=300)
            paired=SimpleNamespace(target='yfc-vps',device_id='h454-linux-yfc-'+'b'*32,
                                   token=self.secret,ws_url='wss://mcp.mikemoore.top/ws')
            old={'native_start':lambda target,post:(events.append(('start',target)) or pending),
                 'native_poll':lambda item,post,expected_ws_url:(events.append(('poll',expected_ws_url)) or paired),
                 'ENROLLMENT_WS_URL':'wss://mcp.mikemoore.top/ws',
                 'IDENTITY':{'yfc-vps':receiver.IDENTITY['yfc-vps']},'TOKEN':receiver.TOKEN}
            def serve():
                try: owner.sender(old,send_stdout=delivered.append)
                except Exception as error: errors.append(type(error).__name__)
            with patch.object(owner,'RUN',run),patch.object(owner,'SOCKET',sock), \
                 patch.object(owner,'_new_marker'),patch.object(owner,'_run_preflight'),patch.object(owner,'_peer_root'), \
                 patch.object(owner,'encrypt',return_value=b'C'*512):
                thread=threading.Thread(target=serve); thread.start()
                try:
                    for _ in range(100):
                        if sock.exists(): break
                        time.sleep(.01)
                    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                        client.settimeout(5); client.connect(str(sock))
                        self.assertEqual(events,[])
                        client.sendall(b'START_APPROVED\n')
                        self.assertEqual(owner._line(client),b'ABCD-EFGH')
                        self.assertEqual([x[0] for x in events],['start'])
                        self.assertEqual(delivered,[])
                        client.sendall(b'OWNER_CAS_APPROVED\n')
                        self.assertEqual(owner._line(client),b'OWNER_PAIRED_DELIVERY_PENDING')
                finally:
                    thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
            self.assertEqual(errors,[])
            self.assertEqual([x[0] for x in events],['start','poll'])
            self.assertEqual(delivered,[b'C'*512])
            self.assertNotIn(b'ABCD-EFGH',delivered[0])
            self.assertNotIn(self.secret.encode(),delivered[0])
            state=root/'target'; state.mkdir(mode=0o700)
            with patch.object(receiver,'MANIFEST_SHA',self.digest),patch.object(receiver,'decrypt',return_value=self.message):
                payload=receiver.config_from_pipe(receiver.decrypt(delivered[0]),self.candidate)
            receiver.write_device(state,os.getuid(),os.getgid(),payload)
            self.assertEqual(json.loads((state/'device.json').read_bytes())['token'],self.secret)

    def test_sender_never_polls_when_owner_disconnects_before_cas(self):
        with tempfile.TemporaryDirectory() as folder:
            run=Path(folder)/'run'; sock=run/'owner.sock'; events=[]; errors=[]; delivered=[]
            old={'native_start':lambda target,post:(events.append('start') or SimpleNamespace(user_code='ABCD-EFGH',expires_in=300)),
                 'native_poll':lambda *a,**k:events.append('poll')}
            def serve():
                try: owner.sender(old,send_stdout=delivered.append)
                except Exception as error: errors.append(type(error).__name__)
            with patch.object(owner,'RUN',run),patch.object(owner,'SOCKET',sock), \
                 patch.object(owner,'_new_marker'),patch.object(owner,'_run_preflight'),patch.object(owner,'_peer_root'), \
                 patch.object(owner,'encrypt',return_value=b'C'*512):
                thread=threading.Thread(target=serve); thread.start()
                try:
                    for _ in range(100):
                        if sock.exists(): break
                        time.sleep(.01)
                    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                        client.settimeout(5); client.connect(str(sock)); client.sendall(b'START_APPROVED\n')
                        self.assertEqual(owner._line(client),b'ABCD-EFGH')
                finally: thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
            self.assertEqual(events,['start'])
            self.assertEqual(delivered,[])
            self.assertEqual(errors,['Hold'])

    def test_sender_error_never_echoes_secrets(self):
        error=io.StringIO(); output=io.StringIO()
        with patch.object(sys,'argv',['sender','sender']),patch.object(sys,'stderr',error), \
             patch.object(sys,'stdout',output),patch.object(owner,'_secret_pipe'),patch.object(owner,'_old',return_value={}), \
             patch.object(owner,'sender',side_effect=ValueError(self.secret)):
            self.assertEqual(owner.main(),2)
        self.assertNotIn(self.secret,error.getvalue())
        self.assertNotIn(self.secret,output.getvalue())
        self.assertEqual(error.getvalue().strip(),'H454_YFC_ENROLLMENT_HOLD_NO_AUTO_RETRY')

    def test_secret_channels_reject_terminal_and_regular_file(self):
        read_fd,write_fd=os.pipe()
        try:
            with os.fdopen(read_fd,'rb',closefd=False) as reader,os.fdopen(write_fd,'wb',closefd=False) as writer:
                receiver._secret_pipe(reader); owner._secret_pipe(writer)
            with tempfile.TemporaryFile() as regular:
                with self.assertRaises(receiver.Hold): receiver._secret_pipe(regular)
                with self.assertRaises(owner.Hold): owner._secret_pipe(regular)
            master,slave=os.openpty()
            try:
                with os.fdopen(slave,'r',closefd=False) as tty:
                    with self.assertRaises(receiver.Hold): receiver._secret_pipe(tty)
                    with self.assertRaises(owner.Hold): owner._secret_pipe(tty)
            finally: os.close(master); os.close(slave)
        finally: os.close(read_fd); os.close(write_fd)

    def test_windows_bridge_pins_exact_lf_helper_bytes(self):
        scripts=Path(__file__).resolve().parents[1]/'scripts'
        controller=(scripts/'h454_yfc_enrollment_bridge.ps1').read_text(encoding='utf8')
        for variable,name in (('senderHash','h454_yfc_owner_enrollment.py'),
                              ('receiverHash','h454_yfc_receive_credential.py')):
            match=re.search(r"\$"+variable+r" = '([a-f0-9]{64})'",controller)
            self.assertIsNotNone(match)
            raw=(scripts/name).read_bytes()
            self.assertNotIn(b'\r\n',raw)
            self.assertEqual(hashlib.sha256(raw).hexdigest(),match.group(1))

    def test_actual_rsa_envelope_is_pinned_and_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); root.chmod(0o700); private=root/'transport.key'; public=root/'transport.pub'
            with private.open('wb') as out:
                result=subprocess.run(['/usr/bin/openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:4096'],
                                      stdout=out,stderr=subprocess.DEVNULL,timeout=30,check=False)
            self.assertEqual(result.returncode,0); private.chmod(0o600)
            result=subprocess.run(['/usr/bin/openssl','pkey','-in',str(private),'-pubout'],
                                  stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,check=False)
            self.assertEqual(result.returncode,0); public.write_bytes(result.stdout); public.chmod(0o600)
            pin=hashlib.sha256(result.stdout).hexdigest(); uid=os.getuid()
            ciphertext=owner.encrypt(self.message,path=public,pin=pin,uid=uid)
            self.assertEqual(len(ciphertext),512)
            self.assertNotIn(self.secret.encode(),ciphertext)
            self.assertEqual(receiver.decrypt(ciphertext,private=private,public=public,pin=pin,uid=uid),self.message)
            with self.assertRaises(receiver.Hold):
                receiver.decrypt(bytes([ciphertext[0]^1])+ciphertext[1:],private=private,public=public,pin=pin,uid=uid)
            with self.assertRaises(owner.Hold): owner.encrypt(self.message,path=public,pin='0'*64,uid=uid)
            private.chmod(0o644)
            with self.assertRaises(receiver.Hold): receiver.decrypt(ciphertext,private=private,public=public,pin=pin,uid=uid)
            private.chmod(0o600); fd=os.open(private,os.O_RDONLY)
            try:
                original=root/'original.key'; private.rename(original)
                private.write_bytes(b'foreign'); private.chmod(0o600)
                with self.assertRaises(receiver.Hold): receiver.discard_transport_key(fd,path=private,uid=uid)
                self.assertEqual(private.read_bytes(),b'foreign')
                private.unlink(); original.rename(private)
            finally: os.close(fd)
            state=root/'state'; state.mkdir(mode=0o700)
            read_fd,write_fd=os.pipe(); os.write(write_fd,ciphertext); os.close(write_fd)
            private_key=receiver._private_key; decrypt=receiver.decrypt; discard=receiver.discard_transport_key
            stdout=io.StringIO(); stderr=io.StringIO()
            with os.fdopen(read_fd,'rb') as incoming:
                fake_stdin=SimpleNamespace(buffer=incoming,fileno=incoming.fileno,isatty=incoming.isatty)
                fake_user=SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())
                with patch.object(sys,'argv',['receiver','receive']),patch.object(sys,'stdin',fake_stdin), \
                     patch.object(sys,'stdout',stdout),patch.object(sys,'stderr',stderr), \
                     patch.object(receiver,'yfc_host_lock',return_value=nullcontext()), \
                     patch.object(receiver,'plan',return_value=(fake_user,self.candidate)), \
                     patch.object(receiver,'STATE',state),patch.object(receiver,'MANIFEST_SHA',self.digest), \
                     patch.object(receiver,'_private_key',side_effect=lambda *a,**k:private_key(private=private,public=public,pin=pin,uid=uid)), \
                     patch.object(receiver,'decrypt',side_effect=lambda c:decrypt(c,private=private,public=public,pin=pin,uid=uid)), \
                     patch.object(receiver,'discard_transport_key',side_effect=lambda f:discard(f,path=private,uid=uid)):
                    self.assertEqual(receiver.main(),0)
            self.assertEqual(stdout.getvalue().strip(),'H454_YFC_OWNER_DEVICE_PAIRED_NATIVE_OFF')
            self.assertNotIn(self.secret,stdout.getvalue()+stderr.getvalue())
            self.assertEqual(json.loads((state/'device.json').read_bytes())['token'],self.secret)
            self.assertFalse(private.exists())

    def test_owner_peer_must_be_root_and_have_real_tty(self):
        with tempfile.TemporaryDirectory() as folder:
            path=str(Path(folder)/'test.sock')
            server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); server.bind(path); server.listen(1)
            master,slave=os.openpty()
            code="import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.recv(1)"
            child=subprocess.Popen([sys.executable,'-c',code,path],stdin=slave,stdout=slave,stderr=subprocess.DEVNULL)
            os.close(slave)
            try:
                peer,_=server.accept()
                with peer,patch.object(owner.struct,'unpack',return_value=(child.pid,0,0)):
                    owner._peer_root(peer,tty=True)
                    with patch.object(owner.struct,'unpack',return_value=(child.pid,1234,1234)):
                        with self.assertRaises(owner.Hold): owner._peer_root(peer,tty=True)
                    peer.sendall(b'x')
                self.assertEqual(child.wait(timeout=5),0)
            finally:
                if child.poll() is None: child.kill(); child.wait()
                os.close(master); server.close()

        left,right=socket.socketpair()
        try:
            with patch.object(owner.struct,'unpack',return_value=(os.getpid(),0,0)), \
                 patch.object(owner.os,'isatty',return_value=False):
                with self.assertRaises(owner.Hold): owner._peer_root(right,tty=True)
        finally: left.close(); right.close()


if __name__=='__main__': unittest.main()
