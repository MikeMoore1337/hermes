"""One YFC owner pairing attempt; bearer goes only to the caller's pipe.

The operator terminal remains separate and uses the existing root-TTY CAS.
This source does not install a service or persist a device credential.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import time

SOURCE = Path('/opt/hermes-agent-owner/releases/main-5b62d5bba585c6bb6d1f7f6abe6a7def33ab4f7d')
EXISTING = Path('/root/h454_native_hermes_enrollment_912.py')
EXISTING_SHA = 'c9518d082da3d563906c42ff2bc4574a779361f9b2c15238ac447c4a8c05288d'
RUN = Path('/run/hermes-h454-yfc-enrollment')
SOCKET = RUN/'owner.sock'
MARKER = Path('/var/lib/hermes-h454-yfc-enrollment.pending')
TARGET = 'yfc-vps'
PUBLIC_KEY = Path('/root/h454-yfc-sender-preview/transport.pub')
PUBLIC_SHA = '27c6a57183cf0b4122c9b4eedf792881cc8951875a88f9c2369819fcaa6064d8'


class Hold(ValueError):
    pass


def demand(value):
    if not value:
        raise Hold('h454_yfc_enrollment_hold')


def _secret_pipe(stream):
    mode=os.fstat(stream.fileno()).st_mode
    demand(not stream.isatty() and (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)))


def encrypt(payload, *, path=PUBLIC_KEY, pin=PUBLIC_SHA, uid=0):
    """Encrypt to the exact YFC public key; plaintext is only OpenSSL stdin."""
    demand(type(payload) is bytes and 0<len(payload)<=446)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(fd); data=os.read(fd,4097); after=os.fstat(fd)
        demand(stat.S_ISREG(info.st_mode) and info.st_uid==uid and info.st_nlink==1 and
               stat.S_IMODE(info.st_mode)==0o600 and 0<len(data)<=4096 and len(data)==info.st_size and
               (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==
               (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and
               hashlib.sha256(data).hexdigest()==pin)
        os.lseek(fd,0,os.SEEK_SET)
        result=subprocess.run(['/usr/bin/openssl','pkeyutl','-encrypt','-pubin','-inkey','/proc/self/fd/'+str(fd),
                               '-pkeyopt','rsa_padding_mode:oaep','-pkeyopt','rsa_oaep_md:sha256',
                               '-pkeyopt','rsa_mgf1_md:sha256'],input=payload,stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL,pass_fds=(fd,),timeout=10,check=False)
        demand(result.returncode==0 and len(result.stdout)==512)
        return result.stdout
    finally: os.close(fd)


def _old():
    st=EXISTING.lstat()
    demand(os.geteuid()==0 and stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1
           and stat.S_IMODE(st.st_mode)==0o600 and 0<st.st_size<100000)
    fd=os.open(EXISTING,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        inside=os.fstat(fd); data=os.read(fd,100001)
        after=os.fstat(fd); current=EXISTING.lstat()
        fields=('st_dev','st_ino','st_mode','st_uid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        demand(all(getattr(st,f)==getattr(inside,f)==getattr(after,f)==getattr(current,f) for f in fields)
               and len(data)==st.st_size and hashlib.sha256(data).hexdigest()==EXISTING_SHA)
    finally:
        os.close(fd)
    old={'__name__':'h454_verified_enrollment','__file__':str(EXISTING)}
    exec(compile(data,str(EXISTING),'exec'),old)
    demand(Path(old['SOURCE'])==SOURCE and socket.gethostname().split('.')[0]=='vps1777112993')
    old['_source_gate'](); old['_runtime_gate'](); old['_compiled_gate']()
    return old


def _post(old, path, body):
    """Only the pinned relay's local pairing endpoints; request stays on stdin."""
    demand(path in ('/device/start','/device/poll') and type(body) is bytes and 0<len(body)<=2048)
    value=json.loads(body.decode('ascii'))
    expected=old['NAME'][TARGET]
    demand(type(value) is dict and (value=={'client_name':expected} if path=='/device/start' else
           set(value)=={'device_code','name','platform'} and value['name']==expected and value['platform']=='linux'
           and type(value['device_code']) is str and re.fullmatch(r'[A-Za-z0-9_-]{24,256}',value['device_code']) is not None))
    old['_runtime_gate']()
    script=("const p="+json.dumps(path)+";const data="+json.dumps(body.decode('ascii'))+";"
            "const c=new AbortController();const t=setTimeout(()=>c.abort(),5000);"
            "try{const r=await fetch('http://127.0.0.1:3000'+p,{method:'POST',"
            "headers:{'content-type':'application/json','accept':'application/json'},"
            "body:data,signal:c.signal,redirect:'manual'});const b=await r.text();"
            "if(b.length>2048)throw Error();process.stdout.write(JSON.stringify({status:r.status,body:b}));}"
            "catch{process.stdout.write(JSON.stringify({status:599,body:''}));}finally{clearTimeout(t);}")
    result=subprocess.run(['/usr/bin/docker','exec','--interactive','--user','65534:65534',
                           old['RELAY'],'node','--input-type=module','-'],input=script.encode('ascii'),
                          stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=12,check=False)
    demand(result.returncode==0 and 0<len(result.stdout)<=4096)
    response=json.loads(result.stdout.decode('ascii'))
    demand(type(response) is dict and set(response)=={'status','body'} and
           type(response['status']) is int and response['status'] in (200,400) and
           type(response['body']) is str and 0<len(response['body'])<=2048)
    old['_runtime_gate']()
    return response['status'],response['body'].encode('ascii')


def _line(stream, limit=512):
    data=bytearray()
    while len(data)<=limit:
        part=stream.recv(1)
        demand(bool(part))
        if part==b'\n':
            return bytes(data)
        data.extend(part)
    raise Hold('h454_yfc_enrollment_hold')


def _peer_root(stream, *, tty=False):
    pid,uid,_gid=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    demand(uid==0 and pid>1)
    if tty:
        descriptors=[]
        try:
            for index in (0,1):
                fd=os.open('/proc/'+str(pid)+'/fd/'+str(index),os.O_RDONLY|os.O_NOCTTY|os.O_CLOEXEC)
                descriptors.append(fd)
            demand(all(os.isatty(fd) for fd in descriptors) and
                   os.fstat(descriptors[0]).st_rdev==os.fstat(descriptors[1]).st_rdev)
        finally:
            for fd in descriptors: os.close(fd)


def _new_marker():
    parent=MARKER.parent.lstat()
    demand(stat.S_ISDIR(parent.st_mode) and parent.st_uid==0 and not parent.st_mode&0o022)
    fd=os.open(MARKER,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        raw=b'H454_YFC_ENROLLMENT_ATTEMPT\n'
        os.fchmod(fd,0o600); demand(os.write(fd,raw)==len(raw)); os.fsync(fd)
    finally: os.close(fd)
    fd=os.open(MARKER.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def _run_preflight():
    parent=RUN.parent.lstat()
    demand(stat.S_ISDIR(parent.st_mode) and parent.st_uid==0 and not parent.st_mode&0o022 and
           not RUN.exists() and not RUN.is_symlink())


def sender(old, *, send_stdout):
    """One process, one code, one real owner approval and no automatic retry."""
    demand(callable(send_stdout))
    encrypt(b'H454_YFC_ENCRYPTION_PREFLIGHT')
    _run_preflight()
    _new_marker()
    os.mkdir(RUN,0o700)
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        listener.bind(str(SOCKET)); os.chmod(SOCKET,0o600); listener.listen(1); listener.settimeout(900)
        stream,_=listener.accept()
        with stream:
            stream.settimeout(900); _peer_root(stream,tty=True)
            demand(_line(stream)==b'START_APPROVED')
            pending=old['native_start'](TARGET,post=lambda p,b:_post(old,p,b))
            started=time.monotonic()
            stream.sendall(pending.user_code.encode('ascii')+b'\n')
            demand(_line(stream)==b'OWNER_CAS_APPROVED' and time.monotonic()-started<pending.expires_in-20)
            paired=old['native_poll'](pending,post=lambda p,b:_post(old,p,b),expected_ws_url=old['ENROLLMENT_WS_URL'])
            demand(paired.target==TARGET and old['IDENTITY'][TARGET].fullmatch(paired.device_id) is not None
                   and old['TOKEN'].fullmatch(paired.token) is not None and paired.ws_url==old['ENROLLMENT_WS_URL'])
            payload=json.dumps({'device_id':paired.device_id,'token':paired.token},sort_keys=True,
                               separators=(',',':'),ensure_ascii=True).encode('ascii')
            demand(0<len(payload)<=2048)
            stream.sendall(b'OWNER_PAIRED_DELIVERY_PENDING\n')
            send_stdout(encrypt(payload))
    finally:
        listener.close()


def owner(old):
    """Two exact human TTY confirmations through the existing owner operator."""
    demand(sys.stdin.isatty() and sys.stdout.isatty())
    parent=RUN.lstat(); endpoint=SOCKET.lstat()
    demand(stat.S_ISDIR(parent.st_mode) and parent.st_uid==0 and stat.S_IMODE(parent.st_mode)==0o700 and
           stat.S_ISSOCK(endpoint.st_mode) and endpoint.st_uid==0 and stat.S_IMODE(endpoint.st_mode)==0o600)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:
        stream.settimeout(900); stream.connect(str(SOCKET)); _peer_root(stream)
        old['_tty_confirm']('H454 ENROLL READ ONLY YFC DEV',
                            'Enroll ONE pinned YFC dev-snapshot device; no native service is started.')
        stream.sendall(b'START_APPROVED\n')
        code=_line(stream).decode('ascii'); demand(re.fullmatch(r'[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}',code) is not None)
        with open('/dev/tty','w',encoding='ascii',buffering=1) as tty:
            tty.write('Fresh YFC code (enter it at the following prompt): '+code+'\n')
        from scripts import h454_native_owner_pair
        demand(h454_native_owner_pair.main(['--target',TARGET])==0)
        stream.sendall(b'OWNER_CAS_APPROVED\n')
        demand(_line(stream)==b'OWNER_PAIRED_DELIVERY_PENDING')
        print('H454_YFC_OWNER_PAIRED_DELIVERY_PENDING')


def main():
    try:
        demand(len(sys.argv)==2 and sys.argv[1] in ('sender','owner','selftest'))
        if sys.argv[1] in ('sender','selftest'): _secret_pipe(sys.stdout)
        old=_old()
        if sys.argv[1]=='sender':
            sender(old,send_stdout=lambda raw: (sys.stdout.buffer.write(raw),sys.stdout.buffer.flush()))
        elif sys.argv[1]=='owner':
            owner(old)
        else:
            sys.stdout.buffer.write(encrypt(b'H454_SYNTHETIC_ENVELOPE')); sys.stdout.buffer.flush()
        return 0
    except Exception:
        print('H454_YFC_ENROLLMENT_HOLD_NO_AUTO_RETRY',file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
