"""Prepare the fixed read-only audit socket for one pinned Hermes installation."""
from __future__ import annotations

import grp
import fcntl
import hashlib
import os
from pathlib import Path
import pwd
import socket
import stat
import subprocess
from contextlib import contextmanager

from scripts import h454_native_paired_apply as paired
from scripts.h454_native_linux_audit_unit import render_audit_units
from scripts.h454_native_private_versioned_upgrade import checked_file, create_file, owned_directory, raw_show
from device_fabric.native_private_tls import load_private_relay

ACCOUNT = 'hermes-commander-audit'
SOCKET_UNIT = 'hermes-commander-audit.socket'
AUDIT_UNIT = 'hermes-commander-audit@.service'
UNIT_DIR = Path('/etc/systemd/system')
UNIT_SEARCH_DIRS = (UNIT_DIR, Path('/run/systemd/system'), Path('/usr/lib/systemd/system'),
                    Path('/lib/systemd/system'))
SOCKET_DIR = Path('/run/hermes-commander-audit')
MANIFEST = Path('/var/lib/hermes-commander-native/manifest.json')
MANIFEST_SHA = '0b8dac8e166ab4a54c7b5a522803567326aa9c634344a84b990943e60b4298fd'
ACTIVE_SHA = '9ddf244fcc903377bf947f4fc7382b3e0f9ca63c00e35780ab517a84e4fee24d'
YFC_RELEASE = 'e26d0cb7ae4a7260f500f3fdebbb80bb378a22b5'
YFC_ACTIVE_SHA = '487ce0184ad6d7b3cbf63c9cc9078320508ad2715d4bf94a3a8e35366f1d38db'
YFC_RECEIPT = Path('/opt/hermes-commander-native/receipts/yfc-vps-' + YFC_RELEASE + '-active.json')
YFC_RECEIPT_SHA = '0f454a5678b734b447506bc90e757167c74007a41d57226701c5ebd83aac2ba1'
YFC_HOST_KEY = Path('/etc/ssh/ssh_host_ed25519_key.pub')
YFC_HOST_KEY_SHA = 'bd6d9675cc868f14e97c8ef24f58c560cf41930f6bc2dcb7eedc93e6262ff595'


class AuditSetupHold(ValueError):
    """Never report private host paths, credentials, or command output."""

    def __init__(self, reason: str = 'h454_audit_setup_denied'):
        self.phase = 'AUDIT_CLEANUP' if reason == 'h454_audit_cleanup_hold' else 'AUDIT_SETUP'
        super().__init__(reason)


def _run(args: list[str], *, timeout: int = 15) -> subprocess.CompletedProcess:
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode != 0:
        raise AuditSetupHold('h454_audit_setup_denied')
    return result


def _identity_absent() -> bool:
    try:
        pwd.getpwnam(ACCOUNT)
        return False
    except KeyError:
        pass
    try:
        grp.getgrnam(ACCOUNT)
        return False
    except KeyError:
        return True


def _state_directory_matches(identity) -> bool:
    info=MANIFEST.parent.lstat()
    return (stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o700 and
            (info.st_uid,info.st_gid)==(identity.pw_uid,identity.pw_gid))


def _service_group_exclusive(identity) -> bool:
    group=grp.getgrgid(identity.pw_gid)
    return (not any(name != identity.pw_name for name in group.gr_mem) and
            not any(item.pw_gid==identity.pw_gid and item.pw_name!=identity.pw_name
                    for item in pwd.getpwall()))


def _audit_socket_protected(identity) -> bool:
    directory=SOCKET_DIR.lstat();endpoint=(SOCKET_DIR/'properties.sock').lstat()
    return (stat.S_ISDIR(directory.st_mode) and directory.st_uid==0 and
            stat.S_IMODE(directory.st_mode)==0o755 and stat.S_ISSOCK(endpoint.st_mode) and
            endpoint.st_uid==0 and endpoint.st_gid==identity.pw_gid and
            stat.S_IMODE(endpoint.st_mode)==0o660)


def plan() -> dict[str, object]:
    """Read-only admission; no account, unit, service, or credential mutation."""
    try:
        if os.geteuid() != 0 or socket.gethostname() != 'vps1777112993':
            raise AuditSetupHold()
        owned_directory(UNIT_DIR)
        identity = pwd.getpwnam('hermes-commander-native')
        if (identity.pw_uid<=0 or identity.pw_gid<=0 or
            identity.pw_shell not in ('/usr/sbin/nologin','/sbin/nologin') or
            not _state_directory_matches(identity)):
            raise AuditSetupHold()
        if not _service_group_exclusive(identity):
            raise AuditSetupHold()
        manifest = checked_file(MANIFEST, 8192, owner=identity.pw_uid, private=True, modes={0o600})
        if MANIFEST.lstat().st_gid != identity.pw_gid:
            raise AuditSetupHold()
        active = checked_file(UNIT_DIR / 'hermes-commander-native.service', 16384, modes={0o644})
        if (hashlib.sha256(manifest).hexdigest() != MANIFEST_SHA or
            hashlib.sha256(active).hexdigest() != ACTIVE_SHA or
            not _identity_absent() or SOCKET_DIR.exists() or SOCKET_DIR.is_symlink() or
            any((directory / name).exists() or (directory / name).is_symlink()
                for directory in UNIT_SEARCH_DIRS for name in (SOCKET_UNIT, AUDIT_UNIT))):
            raise AuditSetupHold()
        state = raw_show('hermes-commander-native.service')
        required = {'ActiveState':'active', 'UnitFileState':'disabled', 'LoadState':'loaded',
                    'FragmentPath':str(UNIT_DIR / 'hermes-commander-native.service'),
                    'User':'hermes-commander-native', 'Group':'hermes-commander-native',
                    'DropInPaths':'', 'NeedDaemonReload':'no'}
        if any(state.get(key) != value for key, value in required.items()):
            raise AuditSetupHold()
        return {'status':'H454_AUDIT_SETUP_PLAN_PASS','mutations':False}
    except Exception:
        raise AuditSetupHold('h454_audit_setup_denied') from None


def plan_yfc() -> dict[str, object]:
    """Read-only admission for the installed, unpaired and inactive YFC unit."""
    try:
        if os.geteuid() != 0:
            raise AuditSetupHold()
        owned_directory(UNIT_DIR)
        owned_directory(YFC_RECEIPT.parent)
        identity = pwd.getpwnam('hermes-commander-native')
        if (identity.pw_uid <= 0 or identity.pw_gid <= 0 or identity.pw_dir != '/nonexistent' or
            identity.pw_shell not in ('/usr/sbin/nologin','/sbin/nologin') or
            any(item.pw_uid==identity.pw_uid and item.pw_name!=identity.pw_name for item in pwd.getpwall()) or
            not _service_group_exclusive(identity) or MANIFEST.parent.exists() or
            MANIFEST.parent.is_symlink()):
            raise AuditSetupHold()
        password=_run(['/usr/bin/passwd','-S','hermes-commander-native']).stdout.decode('ascii').split()
        if len(password)<2 or password[0]!='hermes-commander-native' or password[1] not in ('L','LK'):
            raise AuditSetupHold()
        receipt = checked_file(YFC_RECEIPT,8192,private=True,modes={0o600})
        active = checked_file(UNIT_DIR/'hermes-commander-native.service',16384,modes={0o644})
        host_key = checked_file(YFC_HOST_KEY,1024,modes={0o644})
        if (hashlib.sha256(receipt).hexdigest()!=YFC_RECEIPT_SHA or
            hashlib.sha256(active).hexdigest()!=YFC_ACTIVE_SHA or
            hashlib.sha256(host_key).hexdigest()!=YFC_HOST_KEY_SHA or
            not _identity_absent() or SOCKET_DIR.exists() or SOCKET_DIR.is_symlink() or
            any((directory/name).exists() or (directory/name).is_symlink()
                for directory in UNIT_SEARCH_DIRS for name in (SOCKET_UNIT,AUDIT_UNIT))):
            raise AuditSetupHold()
        load_private_relay('yfc-vps',YFC_RELEASE)
        state=raw_show('hermes-commander-native.service')
        required={'ActiveState':'inactive','UnitFileState':'disabled','LoadState':'loaded',
                  'FragmentPath':str(UNIT_DIR/'hermes-commander-native.service'),
                  'User':'hermes-commander-native','Group':'hermes-commander-native',
                  'DropInPaths':'','NeedDaemonReload':'no'}
        if any(state.get(key)!=value for key,value in required.items()):
            raise AuditSetupHold()
        return {'status':'H454_YFC_AUDIT_SETUP_PLAN_PASS','mutations':False}
    except Exception:
        raise AuditSetupHold('h454_audit_setup_denied') from None


def ensure_lock() -> None:
    """Create the existing shared lifecycle lock only when it is absent."""
    parent=paired.LOCK.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) != 0o1777:
        raise AuditSetupHold('h454_audit_setup_denied')
    try:
        fd=os.open(paired.LOCK,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    except FileExistsError:
        return
    try:
        os.fchmod(fd,0o600);os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def yfc_host_lock():
    """Use the shared lock before YFC has a native state directory."""
    fd = None
    try:
        if os.geteuid()!=0:
            raise AuditSetupHold()
        owned_directory(paired.LOCK.parent.parent)
        owned_directory(MANIFEST.parent.parent)
        parent=paired.LOCK.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=0 or
            stat.S_IMODE(parent.st_mode)!=0o1777 or
            hashlib.sha256(checked_file(YFC_HOST_KEY,1024,modes={0o644})).hexdigest()!=YFC_HOST_KEY_SHA):
            raise AuditSetupHold()
        fd=os.open(paired.LOCK,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or
            stat.S_IMODE(info.st_mode)!=0o600 or info.st_size!=0):
            raise AuditSetupHold()
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        current=paired.LOCK.lstat()
        if (current.st_dev,current.st_ino)!=(info.st_dev,info.st_ino):
            raise AuditSetupHold()
        yield
    except AuditSetupHold:
        raise
    except Exception:
        raise AuditSetupHold('h454_audit_setup_denied') from None
    finally:
        if fd is not None:
            os.close(fd)


def _socket_probe() -> None:
    code="""import socket,struct
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(5)
s.connect('/run/hermes-commander-audit/properties.sock')
assert struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))==(1,0,0)
data=bytearray()
while len(data)<=16384:
 part=s.recv(16385-len(data))
 if not part:break
 data.extend(part)
assert 0<len(data)<=16384
lines=data.decode('ascii').splitlines()
assert 'User=hermes-commander-native' in lines and 'NoNewPrivileges=yes' in lines
print('AUDIT_SOCKET_PROBE=PASS')"""
    result=_run(['/usr/sbin/runuser','-u','hermes-commander-native','--',
                 '/usr/bin/python3','-B','-c',code],timeout=12)
    if result.stdout.strip()!=b'AUDIT_SOCKET_PROBE=PASS':
        raise AuditSetupHold('h454_audit_setup_denied')


def _sync_unit_directory() -> None:
    fd=os.open(UNIT_DIR,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _rollback(created: list[tuple[Path, int, int, str]], *,
              account_uid: int | None, account_gid: int | None,
              start_attempted: bool) -> None:
    """Remove only objects created by this invocation; hold on any ambiguity."""
    if start_attempted:
        _run(['/usr/bin/systemctl','stop',SOCKET_UNIT])
    for path,dev,ino,digest in created:
        node=path.lstat()
        if ((node.st_dev,node.st_ino)!=(dev,ino) or node.st_uid!=0 or
            hashlib.sha256(checked_file(path,16384,modes={0o644})).hexdigest()!=digest):
            raise AuditSetupHold('h454_audit_cleanup_hold')
    for path,_dev,_ino,_digest in created:
        path.unlink()
    if created:
        _sync_unit_directory()
        _run(['/usr/bin/systemctl','daemon-reload'])
    if start_attempted and (SOCKET_DIR.exists() or SOCKET_DIR.is_symlink()):
        node=SOCKET_DIR.lstat()
        if (not stat.S_ISDIR(node.st_mode) or node.st_uid!=0 or
            stat.S_IMODE(node.st_mode)!=0o755):
            raise AuditSetupHold('h454_audit_cleanup_hold')
        SOCKET_DIR.rmdir()
    if account_uid is not None and account_gid is not None:
        current=pwd.getpwnam(ACCOUNT);group=grp.getgrnam(ACCOUNT)
        processes=subprocess.run(['/usr/bin/pgrep','-u',str(account_uid)],capture_output=True,timeout=5,check=False)
        if (current.pw_uid!=account_uid or current.pw_gid!=account_gid or group.gr_gid!=account_gid or
            group.gr_mem or any(item.pw_gid==account_gid and item.pw_name!=ACCOUNT for item in pwd.getpwall()) or
            processes.returncode!=1):
            raise AuditSetupHold('h454_audit_cleanup_hold')
        _run(['/usr/sbin/userdel',ACCOUNT])
        try:
            pwd.getpwnam(ACCOUNT)
        except KeyError:
            pass
        else:
            raise AuditSetupHold('h454_audit_cleanup_hold')
        try:
            group=grp.getgrnam(ACCOUNT)
        except KeyError:
            return
        if group.gr_gid!=account_gid or group.gr_mem or any(item.pw_gid==account_gid for item in pwd.getpwall()):
            raise AuditSetupHold('h454_audit_cleanup_hold')
        _run(['/usr/sbin/groupdel',ACCOUNT])
        try:
            grp.getgrnam(ACCOUNT)
        except KeyError:
            return
        raise AuditSetupHold('h454_audit_cleanup_hold')


def _install(plan_function, *, active_sha: str, expected_state: str, lock_factory) -> dict[str, object]:
    """Install a fixed, unprivileged local query socket without touching the worker."""
    ensure_lock()
    with lock_factory():
        plan_function()
        created=[]
        account_uid=None
        account_gid=None
        start_attempted=False
        try:
            _run(['/usr/sbin/useradd','--system','--user-group','--no-create-home',
                  '--home-dir','/nonexistent','--shell','/usr/sbin/nologin',ACCOUNT])
            identity=pwd.getpwnam(ACCOUNT);group=grp.getgrnam(ACCOUNT)
            account_uid,account_gid=identity.pw_uid,identity.pw_gid
            if (identity.pw_uid<=0 or identity.pw_gid<=0 or identity.pw_gid!=group.gr_gid or
                identity.pw_shell!='/usr/sbin/nologin' or identity.pw_dir!='/nonexistent' or group.gr_mem or
                any((item.pw_uid==identity.pw_uid or item.pw_gid==identity.pw_gid) and item.pw_name!=ACCOUNT
                    for item in pwd.getpwall())):
                raise AuditSetupHold()
            password=_run(['/usr/bin/passwd','-S',ACCOUNT]).stdout.decode('ascii').split()
            if len(password)<2 or password[0]!=ACCOUNT or password[1] not in ('L','LK'):
                raise AuditSetupHold()
            socket_unit,worker_unit=render_audit_units()
            for name,body in ((SOCKET_UNIT,socket_unit),(AUDIT_UNIT,worker_unit)):
                path=UNIT_DIR/name
                create_file(path,body.encode('ascii'),0o644)
                info=path.lstat();created.append((path,info.st_dev,info.st_ino,hashlib.sha256(body.encode('ascii')).hexdigest()))
            _sync_unit_directory()
            _run(['/usr/bin/systemctl','daemon-reload'])
            start_attempted=True
            _run(['/usr/bin/systemctl','start',SOCKET_UNIT])
            native=pwd.getpwnam('hermes-commander-native')
            if not _service_group_exclusive(native) or not _audit_socket_protected(native):
                raise AuditSetupHold()
            _socket_probe()
            active=checked_file(UNIT_DIR/'hermes-commander-native.service',16384,modes={0o644})
            if (hashlib.sha256(active).hexdigest()!=active_sha or
                raw_show('hermes-commander-native.service').get('ActiveState')!=expected_state):
                raise AuditSetupHold()
            return {'status':'H454_AUDIT_SOCKET_READY','worker_restarted':False}
        except Exception:
            try:
                _rollback(created,account_uid=account_uid,account_gid=account_gid,start_attempted=start_attempted)
                if account_uid is None and not _identity_absent():
                    raise AuditSetupHold('h454_audit_cleanup_hold')
            except Exception:
                raise AuditSetupHold('h454_audit_cleanup_hold') from None
            raise AuditSetupHold('h454_audit_setup_denied') from None


def install() -> dict[str, object]:
    return _install(plan,active_sha=ACTIVE_SHA,expected_state='active',lock_factory=paired.host_lock)


def install_yfc() -> dict[str, object]:
    return _install(plan_yfc,active_sha=YFC_ACTIVE_SHA,expected_state='inactive',lock_factory=yfc_host_lock)
