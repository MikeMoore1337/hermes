"""Kernel-level Landlock tests use disposable child processes only."""
import os
import importlib.metadata
import json
from pathlib import Path
import platform
import select
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from unittest.mock import patch

try:
    HAVE_PINNED_WEBSOCKETS = importlib.metadata.version('websockets') == '17.2'
except importlib.metadata.PackageNotFoundError:
    HAVE_PINNED_WEBSOCKETS = False


@unittest.skipUnless(sys.platform == 'linux' and platform.machine().lower() in ('x86_64','aarch64'), 'Linux Landlock required')
class LandlockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import ctypes
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.syscall(444,0,0,1) < 3:
            raise unittest.SkipTest('Landlock ABI 3 unavailable')

    def test_only_local_ext_filesystem_magic_is_accepted(self):
        import ctypes
        from device_fabric import linux_native_landlock as boundary
        class FakeLib:
            def __init__(self, magic):self.magic=magic
            def fstatfs(self, _fd, result):
                ctypes.cast(result,ctypes.POINTER(boundary._StatFs)).contents.type=self.magic
                return 0
        for magic, expected in ((0xEF53,True),(0x65735546,False),(0x6969,False),(0x794c7630,False)):
            with self.subTest(magic=magic),patch.object(boundary.ctypes,'CDLL',return_value=FakeLib(magic)):
                self.assertEqual(boundary._trusted_source_fs(7),expected)

    def test_runtime_fd_exception_is_narrow_and_cloexec(self):
        from device_fabric.linux_native_landlock import _trusted_runtime_fd
        folders=('/usr/lib/x86_64-linux-gnu','/usr/lib/aarch64-linux-gnu','/usr/lib64','/usr/lib')
        candidates=[p for folder in folders for p in Path(folder).glob('libffi.so.*')
                    if p.is_file() and not p.is_symlink()]
        if not candidates:
            self.skipTest('root-owned libffi fixture unavailable')
        fd=os.open(candidates[0],os.O_RDONLY|os.O_CLOEXEC)
        try:
            self.assertTrue(_trusted_runtime_fd(fd))
            with patch('device_fabric.linux_native_landlock.os.access', return_value=False):
                self.assertFalse(_trusted_runtime_fd(fd))
            os.set_inheritable(fd,True)
            self.assertFalse(_trusted_runtime_fd(fd))
        finally:
            os.close(fd)
        with tempfile.TemporaryDirectory() as folder:
            bogus=Path(folder)/candidates[0].name;bogus.write_text('synthetic')
            fd=os.open(bogus,os.O_RDONLY|os.O_CLOEXEC)
            try:self.assertFalse(_trusted_runtime_fd(fd))
            finally:os.close(fd)

    def test_explicit_file_only_and_preopened_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'normal').write_text('synthetic');(root/'secret').write_text('synthetic')
            (root/'hidden').mkdir()
            script=textwrap.dedent('''
                import os,sys
                from device_fabric.linux_native_landlock import restrict_to_open_files
                root=sys.argv[1]; directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
                allowed=os.open(root+'/normal',os.O_PATH)
                restrict_to_open_files(file_fds=(allowed,),directory_fds=(directory,))
                assert set(os.listdir(directory)) == {'normal','secret','hidden'}
                fd=os.open('normal',os.O_RDONLY,dir_fd=directory);os.close(fd)
                for name,flags in (('secret',os.O_RDONLY),('hidden',os.O_RDONLY|os.O_DIRECTORY),
                                   ('created',os.O_WRONLY|os.O_CREAT)):
                    try: fd=os.open(name,flags,0o600,dir_fd=directory)
                    except PermissionError: continue
                    else: os.close(fd);raise AssertionError('unexpected access')
                print('PASS')
            ''')
            proc=subprocess.run([sys.executable,'-B','-c',script,folder],capture_output=True,text=True,timeout=10)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertEqual(proc.stdout.strip(),'PASS')

    def test_existing_thread_is_rejected_before_restriction(self):
        script=textwrap.dedent('''
            import os,sys,threading
            from device_fabric.linux_native_files import NativeLinuxDenied
            from device_fabric.linux_native_landlock import restrict_to_open_files
            directory=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY)
            allowed=os.open(sys.argv[1]+'/normal',os.O_PATH)
            stop=threading.Event(); ready=threading.Event()
            def worker():
                ready.set(); stop.wait()
            thread=threading.Thread(target=worker); thread.start(); ready.wait()
            try:
                try: restrict_to_open_files(file_fds=(allowed,),directory_fds=(directory,))
                except NativeLinuxDenied: pass
                else: raise AssertionError('existing thread accepted')
            finally:
                stop.set(); thread.join()
            print('PASS')
        ''')
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder)/'normal').write_text('synthetic')
            proc=subprocess.run([sys.executable,'-B','-c',script,folder],capture_output=True,text=True,timeout=10)
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertEqual(proc.stdout.strip(),'PASS')

    def test_unexpected_preopened_file_is_rejected_before_restriction(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'normal').write_text('synthetic');(root/'secret').write_text('synthetic')
            script=textwrap.dedent('''
                import os,sys
                from device_fabric.linux_native_files import NativeLinuxDenied
                from device_fabric.linux_native_landlock import restrict_to_open_files
                root=sys.argv[1];directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
                allowed=os.open(root+'/normal',os.O_PATH);extra=os.open(root+'/secret',os.O_RDONLY)
                try: restrict_to_open_files(file_fds=(allowed,),directory_fds=(directory,))
                except NativeLinuxDenied: pass
                else: raise AssertionError('unexpected descriptor accepted')
                check=os.open(root+'/secret',os.O_RDONLY);os.close(check)
                print('PASS')
            ''')
            proc=subprocess.run([sys.executable,'-B','-c',script,folder],capture_output=True,text=True,timeout=10)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertEqual(proc.stdout.strip(),'PASS')

    @unittest.skipUnless(getattr(os, 'geteuid', lambda: -1)() == 0, 'root-owned immutable fixture required')
    def test_snapshot_confines_real_file_adapter_and_search(self):
        with tempfile.TemporaryDirectory(dir='/var/lib') as folder:
            root=Path(folder);(root/'read.md').write_text('synthetic needle')
            os.chmod(root,0o755);os.chmod(root/'read.md',0o644)
            (root/'.env.example').write_text('synthetic secret')
            (root/'unreadable.py').write_text('synthetic secret');os.chmod(root/'unreadable.py',0o600)
            (root/'src').mkdir();(root/'src'/'child.py').write_text('needle')
            (root/'data').mkdir();(root/'data'/'private.md').write_text('synthetic private')
            script=textwrap.dedent('''
                import os,resource,sys
                from pathlib import Path
                from device_fabric.linux_native_files import LinuxNativeFiles,NativeLinuxDenied
                from device_fabric.linux_native_landlock import ReadSnapshot
                from device_fabric import linux_native_landlock as boundary
                from device_fabric.linux_native_search import LinuxNativeSearch
                boundary._trusted_source_fs=lambda _fd: True  # disposable container overlay fixture
                resource.setrlimit(resource.RLIMIT_NOFILE,(32768,resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
                root=Path(sys.argv[1]);files=LinuxNativeFiles(root=root,project='your-fitness-coach')
                with ReadSnapshot(files) as snap:
                    snap.seal()
                    assert files.read_file('read.md')['size_bytes'] == 16
                    assert files.read_file('src/child.py')['size_bytes'] == 6
                    assert [e['name'] for e in files.list_directory()['entries']] == ['read.md','src']
                    assert [e['name'] for e in files.list_directory()['entries']] == ['read.md','src']
                    assert LinuxNativeSearch(files).search('child',mode='names')['matches'][0]['path'] == 'src/child.py'
                    assert Path('/proc/self/status').read_text().startswith('Name:')
                    for name in ('.env.example','data/private.md','unreadable.py'):
                        try: files.read_file(name)
                        except NativeLinuxDenied: pass
                        else: raise AssertionError('protected file accepted')
                    try: os.open('.env.example',os.O_RDONLY,dir_fd=files._root_fd)
                    except PermissionError: pass
                    else: raise AssertionError('kernel allowed protected file')
                    try: os.open('data',os.O_RDONLY|os.O_DIRECTORY,dir_fd=files._root_fd)
                    except PermissionError: pass
                    else: raise AssertionError('kernel allowed protected directory')
                files.close();print('PASS')
            ''')
            proc=subprocess.run(['runuser','-u','nobody','--',sys.executable,'-B','-c',script,folder],capture_output=True,text=True,timeout=15)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertEqual(proc.stdout.strip(),'PASS')

    @unittest.skipUnless(getattr(os, 'geteuid', lambda: -1)() == 0, 'root-owned immutable fixture required')
    def test_yfc_runtime_enters_landlock_before_session(self):
        with tempfile.TemporaryDirectory(dir='/var/lib') as folder:
            root=Path(folder);os.chmod(root,0o755)
            (root/'safe.py').write_text('synthetic');os.chmod(root/'safe.py',0o644)
            (root/'.env.example').write_text('synthetic secret');os.chmod(root/'.env.example',0o644)
            script=textwrap.dedent('''
                import os,resource,sys
                from unittest.mock import patch
                from device_fabric.linux_native_outbound import LocalLinuxDeviceConfig,ENDPOINT
                from scripts import h454_native_linux_runtime as runtime
                from scripts import h454_native_linux_service as service
                from device_fabric.native_private_tls import UNIX_ENDPOINT,UNIX_DIRECTORY,AUDIT_DIRECTORY
                from device_fabric import linux_native_landlock as boundary
                boundary._trusted_source_fs=lambda _fd: True  # disposable container overlay fixture
                resource.setrlimit(resource.RLIMIT_NOFILE,(32768,resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
                device=LocalLinuxDeviceConfig('yfc-vps','h454-linux-yfc-'+'a'*32,'brc_dev_'+'x'*64,ENDPOINT)
                prepared=runtime.PreparedRuntime(device,(('your-fitness-coach',sys.argv[1]),),None)
                props=dict(service.EXPECTED_HARDENING,PrivateNetwork='yes',LimitNOFILE='32768',
                    StandardInput='null',StandardOutput='journal',StandardError='journal',
                    RestrictAddressFamilies='AF_UNIX',TemporaryFileSystem='/run:ro',BindPaths='',
                    BindReadOnlyPaths=' '.join(p+':'+p+':rbind' for p in (UNIX_DIRECTORY,AUDIT_DIRECTORY)),
                    IPAddressDeny='any',IPAddressAllow='',CapabilityBoundingSet='',
                    InaccessiblePaths='-'+sys.argv[1]+'/.git')
                properties='\\n'.join(k+'='+v for k,v in props.items())
                identity=(os.geteuid(),os.getegid())
                def gate():
                    return service.real_os_isolation_verified(private_relay_ip=UNIX_ENDPOINT,
                        target='yfc-vps',expected_identity=identity,git_roots=(sys.argv[1],))
                def session(_device,dispatcher,_connector):
                    files=dispatcher._roots['your-fitness-coach']
                    assert files._landlock_snapshot is not None
                    assert gate()
                    assert files.read_file('safe.py')['size_bytes'] == 9
                    try:os.open('.env.example',os.O_RDONLY,dir_fd=files._root_fd)
                    except PermissionError:pass
                    else:raise AssertionError('session started without Landlock')
                    return 'synthetic-session'
                with patch.object(runtime,'_service_identity'),patch.object(runtime,'run_session',side_effect=session), \\
                     patch.object(service,'_kernel_evidence',return_value=True), \\
                     patch.object(service,'_inet_socket_creation_denied',return_value=True), \\
                     patch.object(service,'_private_run_mount',return_value=True), \\
                     patch.object(service,'_audit_properties',return_value=properties), \\
                     patch.object(service,'_service_identity',side_effect=AssertionError('NSS after confinement')), \\
                     patch.dict(os.environ,{'INVOCATION_ID':'e'*32}):
                    result=runtime.run_once(prepared,connector=lambda *a,**k:None,
                        is_device_revoked=lambda:False,is_os_isolation_verified=gate,landlock_yfc=True)
                assert result == 'synthetic-session';print('PASS')
            ''')
            proc=subprocess.run(['runuser','-u','nobody','--',sys.executable,'-B','-c',script,folder],capture_output=True,text=True,timeout=15)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertEqual(proc.stdout.strip(),'PASS')

    @unittest.skipUnless(getattr(os, 'geteuid', lambda: -1)() == 0 and HAVE_PINNED_WEBSOCKETS,
                         'root-owned fixture and pinned websockets 17.2 required')
    def test_real_websocket_over_unix_after_landlock(self):
        import ssl
        from websockets.sync.server import unix_serve
        with tempfile.TemporaryDirectory(dir='/var/lib') as folder:
            base=Path(folder);os.chmod(base,0o755)
            root=base/'project';root.mkdir(mode=0o755)
            (root/'safe.py').write_text('synthetic');os.chmod(root/'safe.py',0o644)
            (root/'.env.example').write_text('synthetic private');os.chmod(root/'.env.example',0o644)
            ca,key,cert,serverkey,csr,ext=[base/x for x in ('ca.crt','ca.key','relay.crt','relay.key','relay.csr','ext')]
            other,otherkey=base/'other.crt',base/'other.key'
            ext.write_text('subjectAltName=DNS:brc-agent.internal\nextendedKeyUsage=serverAuth\n')
            def openssl(*args):
                subprocess.run(['openssl',*map(str,args)],check=True,capture_output=True,timeout=15)
            for certpath,keypath,name in ((ca,key,'test-ca'),(other,otherkey,'other-ca')):
                openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',keypath,
                    '-out',certpath,'-days','1','-subj','/CN='+name,
                    '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
                os.chmod(certpath,0o644)
            openssl('req','-newkey','rsa:2048','-nodes','-keyout',serverkey,'-out',csr,'-subj','/CN=brc-agent.internal')
            openssl('x509','-req','-in',csr,'-CA',ca,'-CAkey',key,'-CAcreateserial','-out',cert,'-days','1','-extfile',ext)
            tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,serverkey)
            token='brc_dev_'+'x'*64;requests=[];results=[]
            def inspect(_connection,request):
                requests.append(request.headers.get('Authorization') == 'Bearer '+token)
            def handler(connection):
                hello=json.loads(connection.recv(timeout=5))
                if hello.get('type') != 'hello':
                    return
                connection.send(json.dumps({'type':'welcome','protocol':1,'relayVersion':'fixture','serverTime':1}))
                connection.send(json.dumps({'type':'call','id':'fixture-read','tool':'native_file_read',
                    'args':{'project':'your-fitness-coach','relative':'safe.py'}}))
                result=json.loads(connection.recv(timeout=5))
                body=json.loads(result['result']['content'][0]['text'])
                results.append(result['id']=='fixture-read' and body['status']=='ok' and body['result']['size_bytes']==9)
            socket_path=str(base/'relay.sock')
            server=unix_serve(handler,path=socket_path,ssl=tls,process_request=inspect,compression=None)
            os.chmod(socket_path,0o666)
            worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
            script=textwrap.dedent('''
                import os,resource,sys
                from pathlib import Path
                from unittest.mock import patch
                from websockets.sync.client import connect
                from device_fabric.linux_native_outbound import LocalLinuxDeviceConfig,ENDPOINT
                from device_fabric import linux_native_outbound as outbound
                from device_fabric import native_private_tls as tls
                from device_fabric import linux_native_landlock as boundary
                from scripts import h454_native_linux_runtime as runtime
                boundary._trusted_source_fs=lambda _fd: True  # disposable container overlay fixture
                resource.setrlimit(resource.RLIMIT_NOFILE,(32768,resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
                ca=Path(sys.argv[2]).read_bytes();wrong=Path(sys.argv[3]).read_bytes();tls.UNIX_SOCKET=sys.argv[4]
                opts=dict(additional_headers={'Authorization':'Bearer brc_dev_'+'x'*64,'X-BRC-Protocol':'1'},
                    open_timeout=10,close_timeout=3,compression=None,proxy=None,max_size=8192,ping_interval=20,ping_timeout=20)
                good=tls.PrivateRelay('yfc-vps','a'*40,tls.UNIX_ENDPOINT,ca)
                bad=tls.PrivateRelay('yfc-vps','a'*40,tls.UNIX_ENDPOINT,wrong)
                good_connector=tls.private_websocket_connector(good,connect)
                bad_connector=tls.private_websocket_connector(bad,connect)
                device=LocalLinuxDeviceConfig('yfc-vps','h454-linux-yfc-'+'a'*32,'brc_dev_'+'x'*64,ENDPOINT)
                prepared=runtime.PreparedRuntime(device,(('your-fitness-coach',sys.argv[1]),),None)
                outbound.MAX_TOOL_CALLS=1
                with patch.object(runtime,'_service_identity'):
                    outcome=runtime.run_once(prepared,connector=good_connector,
                        is_device_revoked=lambda:False,is_os_isolation_verified=lambda:True,landlock_yfc=True)
                assert outcome=='session_call_budget'
                try:bad_connector(tls.ENDPOINT,**opts)
                except tls.PrivateTLSDenied:pass
                else:raise AssertionError('untrusted CA accepted')
                try:os.open(sys.argv[1]+'/.env.example',os.O_RDONLY)
                except PermissionError:pass
                else:raise AssertionError('protected file readable')
                print('PASS')
            ''')
            try:
                proc=subprocess.run(['runuser','-u','nobody','--',sys.executable,'-B','-c',script,
                    str(root),str(ca),str(other),socket_path],capture_output=True,text=True,timeout=20)
                self.assertEqual(proc.returncode,0,proc.stderr)
                self.assertEqual(proc.stdout.strip(),'PASS')
                self.assertEqual(requests,[True])
                self.assertEqual(results,[True])
            finally:
                server.shutdown();worker.join(timeout=5)

    def test_snapshot_rejects_untrusted_writable_ancestor(self):
        from device_fabric.linux_native_files import LinuxNativeFiles,NativeLinuxDenied
        from device_fabric.linux_native_landlock import ReadSnapshot
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'source.py').write_text('synthetic')
            with LinuxNativeFiles(root=root,project='your-fitness-coach') as files, \
                 patch('device_fabric.linux_native_landlock._trusted_source_fs',return_value=True):
                with self.assertRaises(NativeLinuxDenied):
                    ReadSnapshot(files)

    def test_snapshot_rejects_insufficient_descriptor_budget(self):
        from device_fabric.linux_native_files import LinuxNativeFiles,NativeLinuxDenied
        from device_fabric.linux_native_landlock import ReadSnapshot
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'source.py').write_text('synthetic')
            with LinuxNativeFiles(root=root,project='your-fitness-coach') as files, \
                 patch('device_fabric.linux_native_landlock.resource.getrlimit',return_value=(1024,1024)):
                with self.assertRaises(NativeLinuxDenied):
                    ReadSnapshot(files)

    @unittest.skipUnless(getattr(os, 'geteuid', lambda: -1)() == 0, 'root-owned fixture required')
    def test_snapshot_rejects_nonroot_owned_project_before_scanning(self):
        from device_fabric.linux_native_files import LinuxNativeFiles,NativeLinuxDenied
        from device_fabric.linux_native_landlock import ReadSnapshot
        with tempfile.TemporaryDirectory(dir='/var/lib') as folder:
            root=Path(folder);(root/'source.py').write_text('synthetic');os.chown(root,65534,65534)
            with LinuxNativeFiles(root=root,project='your-fitness-coach') as files, \
                 patch('device_fabric.linux_native_landlock._trusted_source_fs',return_value=True), \
                 patch('device_fabric.linux_native_landlock.os.scandir') as scan:
                with self.assertRaises(NativeLinuxDenied):
                    ReadSnapshot(files)
                scan.assert_not_called()

    @unittest.skipUnless(getattr(os, 'geteuid', lambda: -1)() == 0, 'root-owned immutable fixture required')
    def test_snapshot_excludes_untrusted_writers_hardlinks_and_symlinks(self):
        from device_fabric.linux_native_files import LinuxNativeFiles
        from device_fabric.linux_native_landlock import ReadSnapshot
        with tempfile.TemporaryDirectory(dir='/var/lib') as folder:
            root=Path(folder);os.chmod(root,0o755)
            for name in ('safe.py','foreign.py','writable.py','hard.py'):
                (root/name).write_text('synthetic');os.chmod(root/name,0o644)
            os.chown(root/'foreign.py',65534,65534)
            os.chmod(root/'writable.py',0o664)
            os.link(root/'hard.py',root/'hard-alias.py')
            (root/'shortcut.py').symlink_to('safe.py')
            (root/'writable-dir').mkdir();os.chmod(root/'writable-dir',0o775)
            (root/'writable-dir'/'hidden.py').write_text('synthetic')
            with LinuxNativeFiles(root=root,project='your-fitness-coach') as files, \
                 patch('device_fabric.linux_native_landlock._trusted_source_fs',return_value=True):
                with ReadSnapshot(files) as snap:
                    self.assertEqual(set(snap.regular),{'safe.py'})
                    self.assertEqual(set(snap.directories),{''})

    @unittest.skipUnless(getattr(os, 'geteuid', lambda: -1)() == 0, 'root-owned immutable fixture required')
    def test_snapshot_refuses_added_modified_and_replaced_inodes(self):
        with tempfile.TemporaryDirectory(dir='/var/lib') as folder:
            root=Path(folder);os.chmod(root,0o755)
            for name in ('replace.md','modify.md'):
                (root/name).write_text('synthetic');os.chmod(root/name,0o644)
            (root/'sub').mkdir();(root/'sub'/'child.py').write_text('synthetic')
            script=textwrap.dedent('''
                import os,resource,sys
                from pathlib import Path
                from device_fabric.linux_native_files import LinuxNativeFiles,NativeLinuxDenied
                from device_fabric.linux_native_landlock import ReadSnapshot
                from device_fabric import linux_native_landlock as boundary
                boundary._trusted_source_fs=lambda _fd: True  # disposable container overlay fixture
                resource.setrlimit(resource.RLIMIT_NOFILE,(32768,resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
                files=LinuxNativeFiles(root=Path(sys.argv[1]),project='your-fitness-coach')
                with ReadSnapshot(files) as snap:
                    snap.seal();print('READY',flush=True);sys.stdin.read(1)
                    for name in ('replace.md','moved.md','modify.md','new.py','sub/child.py'):
                        try: files.read_file(name)
                        except NativeLinuxDenied: pass
                        else: raise AssertionError('changed path accepted')
                    try: os.open('replace.md',os.O_RDONLY,dir_fd=files._root_fd)
                    except PermissionError: pass
                    else: raise AssertionError('kernel accepted replacement')
                    print('PASS')
            ''')
            proc=subprocess.Popen(['runuser','-u','nobody','--',sys.executable,'-B','-c',script,folder],
                                  stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                ready,_,_=select.select([proc.stdout],[],[],10)
                self.assertTrue(ready,'sandbox did not start')
                self.assertEqual(proc.stdout.readline().strip(),'READY')
                (root/'replace.md').rename(root/'moved.md')
                (root/'replace.md').write_text('replacement')
                (root/'modify.md').write_text('changed synthetic')
                (root/'new.py').write_text('new synthetic')
                (root/'sub').rename(root/'moved_sub');(root/'sub').mkdir()
                (root/'sub'/'child.py').write_text('replacement')
                out,err=proc.communicate('x',timeout=10)
                self.assertEqual(proc.returncode,0,err)
                self.assertEqual(out.strip(),'PASS')
            finally:
                if proc.poll() is None:
                    proc.kill();proc.wait(timeout=5)
                for stream in (proc.stdin,proc.stdout,proc.stderr):
                    if stream is not None:
                        stream.close()


if __name__ == '__main__':
    unittest.main()
