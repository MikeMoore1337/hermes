"""Receive one owner-paired YFC credential on stdin; never echo it."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys

from device_fabric.native_brc_enrollment import IDENTITY, TOKEN
from device_fabric.native_install_preview import parse_candidate
from device_fabric.native_private_tls import load_private_relay
from scripts.h454_native_audit_setup import yfc_host_lock
from scripts.h454_native_linux_runtime import SCHEMA, _parse_config
from scripts.h454_native_private_versioned_upgrade import checked_file, raw_show

STATE=Path('/var/lib/hermes-commander-native')
MANIFEST_SHA='0b1235c6d56d460c83ba45405c831bc08b4001d6207a3aeff04f80ff1a8ea8b4'
RELEASE='e26d0cb7ae4a7260f500f3fdebbb80bb378a22b5'
UNIT_SHA='487ce0184ad6d7b3cbf63c9cc9078320508ad2715d4bf94a3a8e35366f1d38db'
SNAPSHOT='/opt/hermes-commander-yfc-snapshots/dev-17c5f29921f379d1f5229eede40c88d5183ddcf9'
PENDING='.h454-yfc-enrollment.pending'
PUBLIC_KEY=Path('/root/h454-yfc-receiver-preview/transport.pub')
PRIVATE_KEY=Path('/root/h454-yfc-receiver-preview/transport.key')
PUBLIC_SHA='27c6a57183cf0b4122c9b4eedf792881cc8951875a88f9c2369819fcaa6064d8'


class Hold(ValueError):
    pass


def demand(value):
    if not value:
        raise Hold('h454_yfc_credential_hold')


def _secret_pipe(stream):
    mode=os.fstat(stream.fileno()).st_mode
    demand(not stream.isatty() and (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)))


def _key_fd(path, *, uid, limit):
    demand(isinstance(path,Path) and path.is_absolute())
    parent=path.parent.lstat()
    demand(stat.S_ISDIR(parent.st_mode) and parent.st_uid==uid and stat.S_IMODE(parent.st_mode)==0o700)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        demand(stat.S_ISREG(info.st_mode) and info.st_uid==uid and info.st_nlink==1 and
               stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=limit)
        return fd
    except BaseException:
        os.close(fd); raise


def _private_key(*, private=PRIVATE_KEY, public=PUBLIC_KEY, pin=PUBLIC_SHA, uid=0):
    pub_fd=_key_fd(public,uid=uid,limit=4096)
    try:
        pub=os.read(pub_fd,4097)
        demand(0<len(pub)<=4096 and hashlib.sha256(pub).hexdigest()==pin)
    finally: os.close(pub_fd)
    fd=_key_fd(private,uid=uid,limit=16384)
    try:
        result=subprocess.run(['/usr/bin/openssl','pkey','-in','/proc/self/fd/'+str(fd),'-pubout'],
                              stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                              pass_fds=(fd,),timeout=10,check=False)
        demand(result.returncode==0 and result.stdout==pub)
        os.lseek(fd,0,os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd); raise


def decrypt(cipher, *, private=PRIVATE_KEY, public=PUBLIC_KEY, pin=PUBLIC_SHA, uid=0):
    """Decrypt only the pinned YFC envelope; plaintext stays in memory."""
    demand(type(cipher) is bytes and len(cipher)==512)
    fd=_private_key(private=private,public=public,pin=pin,uid=uid)
    try:
        result=subprocess.run(['/usr/bin/openssl','pkeyutl','-decrypt','-inkey','/proc/self/fd/'+str(fd),
                               '-pkeyopt','rsa_padding_mode:oaep','-pkeyopt','rsa_oaep_md:sha256',
                               '-pkeyopt','rsa_mgf1_md:sha256'],input=cipher,stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL,pass_fds=(fd,),timeout=10,check=False)
        demand(result.returncode==0 and 0<len(result.stdout)<=446)
        return result.stdout
    finally: os.close(fd)


def discard_transport_key(fd, *, path=PRIVATE_KEY, uid=0):
    """Remove only the exact private key after the device file is durable."""
    before=os.fstat(fd)
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        current=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        fields=('st_dev','st_ino','st_mode','st_uid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        demand(stat.S_ISREG(before.st_mode) and before.st_uid==uid and before.st_nlink==1 and
               stat.S_IMODE(before.st_mode)==0o600 and all(getattr(before,f)==getattr(current,f) for f in fields))
        os.unlink(path.name,dir_fd=parent); os.fsync(parent)
    finally: os.close(parent)


def _unique(pairs):
    result={}
    for key,value in pairs:
        demand(key not in result); result[key]=value
    return result


def config_from_pipe(raw, candidate):
    """Bind incoming bearer to the exact local manifest, never caller paths."""
    demand(type(raw) is bytes and 0<len(raw)<=2048)
    value=json.loads(raw.decode('ascii'),object_pairs_hook=_unique)
    demand(type(value) is dict and set(value)=={'device_id','token'} and
           type(value['device_id']) is str and IDENTITY['yfc-vps'].fullmatch(value['device_id']) is not None and
           type(value['token']) is str and TOKEN.fullmatch(value['token']) is not None and
           json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')==raw)
    data={'schema':SCHEMA,'target':'yfc-vps','device_id':value['device_id'],'token':value['token'],
          'url':'wss://hermes.mikemoore.top/ws','release_sha':RELEASE,'manifest_sha256':MANIFEST_SHA,
          'roots':[{'project':project,'path':path} for project,path in candidate.roots]}
    payload=json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
    _parse_config(payload,candidate)
    return payload


def plan():
    """Read-only live host and state checks; no credentials are read."""
    demand(os.geteuid()==0)
    u=pwd.getpwnam('hermes-commander-native')
    demand((u.pw_uid,u.pw_gid,u.pw_dir,u.pw_shell)==(992,977,'/nonexistent','/usr/sbin/nologin'))
    directory=STATE.lstat()
    demand(stat.S_ISDIR(directory.st_mode) and (directory.st_uid,directory.st_gid)==(u.pw_uid,u.pw_gid)
           and stat.S_IMODE(directory.st_mode)==0o700)
    raw=checked_file(STATE/'manifest.json',8192,owner=u.pw_uid,private=True,modes={0o600})
    demand((STATE/'manifest.json').lstat().st_gid==u.pw_gid and hashlib.sha256(raw).hexdigest()==MANIFEST_SHA)
    candidate=parse_candidate(raw,expected_release=RELEASE,expected_target='yfc-vps')
    demand(len(candidate.roots)==1 and candidate.roots[0][1]==SNAPSHOT)
    demand(not (STATE/'device.json').exists() and not (STATE/'device.json').is_symlink()
           and not (STATE/PENDING).exists() and not (STATE/PENDING).is_symlink())
    unit=checked_file(Path('/etc/systemd/system/hermes-commander-native.service'),16384,modes={0o644})
    demand(hashlib.sha256(unit).hexdigest()==UNIT_SHA)
    state=raw_show('hermes-commander-native.service')
    demand(all(state.get(key)==value for key,value in {'ActiveState':'inactive','UnitFileState':'disabled',
           'LoadState':'loaded','DropInPaths':'','NeedDaemonReload':'no',
           'FragmentPath':'/etc/systemd/system/hermes-commander-native.service',
           'User':'hermes-commander-native','Group':'hermes-commander-native'}.items()))
    processes=subprocess.run(['/usr/bin/pgrep','-u',str(u.pw_uid)],stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8,check=False)
    demand(processes.returncode==1)
    for unit_name in ('hermes-commander-audit.socket','hermes-commander-tunnel.service'):
        result=subprocess.run(['/usr/bin/systemctl','is-active','--quiet',unit_name],
                              stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                              timeout=8,check=False)
        demand(result.returncode==0)
    load_private_relay('yfc-vps',RELEASE)
    demand(Path('/run/hermes-commander-tunnel/relay.sock').is_socket())
    fd=_private_key()
    os.close(fd)
    return u,candidate


def write_device(state, uid, gid, payload):
    """Exclusive inode-pinned publication; uncertain writes are never retried."""
    demand(isinstance(state,Path) and state.is_absolute() and type(uid) is int and type(gid) is int
           and type(payload) is bytes and 0<len(payload)<=8192)
    dfd=os.open(state,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        fcntl.flock(dfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        info=os.fstat(dfd); current=state.lstat()
        demand((info.st_dev,info.st_ino)==(current.st_dev,current.st_ino) and
               (info.st_uid,info.st_gid)==(uid,gid) and stat.S_IMODE(info.st_mode)==0o700)
        for name in ('device.json',PENDING):
            try: os.stat(name,dir_fd=dfd,follow_symlinks=False)
            except FileNotFoundError: pass
            else: raise Hold('h454_yfc_credential_hold')
        fd=os.open(PENDING,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=dfd)
        try:
            os.fchown(fd,uid,gid); os.fchmod(fd,0o600); view=memoryview(payload)
            while view:
                count=os.write(fd,view); demand(count>0); view=view[count:]
            os.fsync(fd)
        finally: os.close(fd)
        staged=os.stat(PENDING,dir_fd=dfd,follow_symlinks=False)
        demand(stat.S_ISREG(staged.st_mode) and (staged.st_uid,staged.st_gid)==(uid,gid)
               and staged.st_nlink==1 and stat.S_IMODE(staged.st_mode)==0o600 and staged.st_size==len(payload))
        fd=os.open(PENDING,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dfd)
        try:
            inside=os.fstat(fd); actual=os.read(fd,8193)
            demand((inside.st_dev,inside.st_ino)==(staged.st_dev,staged.st_ino) and actual==payload)
        finally: os.close(fd)
        os.link(PENDING,'device.json',src_dir_fd=dfd,dst_dir_fd=dfd,follow_symlinks=False); os.fsync(dfd)
        active=os.stat('device.json',dir_fd=dfd,follow_symlinks=False)
        demand((active.st_dev,active.st_ino)==(staged.st_dev,staged.st_ino) and active.st_nlink==2)
        os.unlink(PENDING,dir_fd=dfd); os.fsync(dfd)
        active=os.stat('device.json',dir_fd=dfd,follow_symlinks=False)
        demand(active.st_nlink==1 and (active.st_uid,active.st_gid)==(uid,gid)
               and stat.S_IMODE(active.st_mode)==0o600 and active.st_size==len(payload))
    finally: os.close(dfd)


def main():
    try:
        demand(len(sys.argv)==2 and sys.argv[1] in ('preflight','receive','selftest'))
        if sys.argv[1] in ('receive','selftest'): _secret_pipe(sys.stdin)
        with yfc_host_lock():
            user,candidate=plan()
            if sys.argv[1]=='preflight':
                print('H454_YFC_RECEIVER_PREFLIGHT_PASS_NO_MUTATION')
            elif sys.argv[1]=='selftest':
                cipher=sys.stdin.buffer.read(513); demand(len(cipher)==512)
                demand(decrypt(cipher)==b'H454_SYNTHETIC_ENVELOPE')
                print('H454_YFC_CRYPTO_SELFTEST_PASS')
            else:
                cipher=sys.stdin.buffer.read(513); demand(len(cipher)==512)
                key_fd=_private_key()
                try:
                    payload=config_from_pipe(decrypt(cipher),candidate)
                    user,again=plan(); demand(again==candidate)
                    write_device(STATE,user.pw_uid,user.pw_gid,payload)
                    discard_transport_key(key_fd)
                finally: os.close(key_fd)
                print('H454_YFC_OWNER_DEVICE_PAIRED_NATIVE_OFF')
        return 0
    except Exception:
        print('H454_YFC_CREDENTIAL_HOLD_NO_AUTO_RETRY',file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
