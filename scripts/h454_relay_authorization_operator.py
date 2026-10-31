"""Owner-side preparation, installation and inode-pinned revocation of the WSS SSH key."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys

try:
    import fcntl
    import pwd
except ImportError:  # Windows may import the tests, but cannot run this operator.
    fcntl = None
    pwd = None

from scripts.h454_relay_authorized_keys import ForwardAuthorizationError, restricted_second_key
from scripts import h454_relay_second_authorized_key as key_slot

REGISTRY_PARENT = Path('/var/lib')
REGISTRY_NAME = 'hermes-h454-wss-key'
RELAY_NAME = 'hermes-brc-relay'
NETWORK_NAME = 'hermes-brc-internal'
HEX = re.compile(r'[a-f0-9]{64}\Z')


class Hold(ValueError):
    pass


class Unsettled(Hold):
    pass


def demand(condition, code):
    if not condition:
        raise Hold(code)


def _directory(path, *, owner, mode=None):
    demand(path.is_absolute() and os.path.realpath(path) == str(path), 'DIRECTORY_PATH')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        demand(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and
               (stat.S_IMODE(info.st_mode) == mode if mode is not None else not info.st_mode & 0o022),
               'DIRECTORY_PERMISSIONS')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _ssh_directory(account, expected=None):
    demand(isinstance(account, str) and re.fullmatch(r'[a-z_][a-z0-9_-]{0,63}', account) is not None, 'ACCOUNT')
    user = pwd.getpwnam(account)
    demand(user.pw_uid > 0, 'ACCOUNT')
    if expected is not None:
        demand((user.pw_uid, user.pw_gid, user.pw_dir) ==
               (expected['uid'], expected['gid'], expected['home']), 'ACCOUNT_DRIFT')
    home = _directory(Path(user.pw_dir), owner=user.pw_uid)
    try:
        fd = os.open('.ssh', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home)
    finally:
        os.close(home)
    try:
        info = os.fstat(fd)
        demand(stat.S_ISDIR(info.st_mode) and info.st_uid == user.pw_uid and
               stat.S_IMODE(info.st_mode) == 0o700, 'SSH_DIRECTORY')
        return user, fd
    except BaseException:
        os.close(fd)
        raise


def _original_hash(ssh_fd, uid, public_key, relay_ip):
    fd = os.open('authorized_keys', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=ssh_fd)
    try:
        info = os.fstat(fd)
        demand(info.st_uid in (0, uid) and info.st_nlink == 1 and not info.st_mode & 0o022, 'ORIGINAL_KEYS')
        digest = hashlib.sha256(key_slot._read(fd, 1_048_576)).hexdigest()
    finally:
        os.close(fd)
    entry = restricted_second_key(public_key, relay_ip)
    key_slot._original(ssh_fd, uid, digest, entry.split()[-1])
    return digest


def _run(arguments, limit):
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=True,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    demand(len(result.stdout) <= limit, 'COMMAND_OUTPUT')
    return result.stdout


def snapshot(account, public_key):
    demand(fcntl is not None and pwd is not None and os.geteuid() == 0, 'ROOT')
    user, ssh_fd = _ssh_directory(account)
    try:
        inspected = json.loads(_run(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock',
                                     'inspect', RELAY_NAME], 1_048_576))
        demand(isinstance(inspected, list) and len(inspected) == 1, 'RELAY')
        relay = inspected[0]
        demand(relay['Name'] == '/' + RELAY_NAME and relay['State']['Running'] is True and
               HEX.fullmatch(relay['Id']) is not None and
               re.fullmatch(r'sha256:[a-f0-9]{64}', relay['Image']) is not None, 'RELAY')
        network = relay['NetworkSettings']['Networks'][NETWORK_NAME]
        address = ipaddress.IPv4Address(network['IPAddress'])
        demand(str(address) == network['IPAddress'] and HEX.fullmatch(network['NetworkID']) is not None and
               any(address in ipaddress.IPv4Network(cidr) for cidr in
                   ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')), 'RELAY_NETWORK')
        entry = restricted_second_key(public_key, str(address))
        canonical_key = b' '.join(entry.split()[-2:]).decode('ascii')
        original = _original_hash(ssh_fd, user.pw_uid, canonical_key, str(address))
        connection = os.environ.get('SSH_CONNECTION', '').split()
        demand(len(connection) == 4, 'SSH_CONNECTION')
        source = str(ipaddress.ip_address(connection[0]))
        settings = _run(['/usr/sbin/sshd', '-T', '-C',
                         'user=' + account + ',addr=' + source + ',host=' + source], 131_072)
        options = {}
        for line in settings.decode('utf8').splitlines():
            name, _, value = line.partition(' ')
            options.setdefault(name, []).append(value)
        permit = options.get('permitopen', [])
        demand(options.get('authorizedkeysfile') == ['.ssh/authorized_keys .ssh/authorized_keys2'] and
               options.get('authorizedkeyscommand') == ['none'] and options.get('usedns') == ['no'] and
               options.get('strictmodes') == ['yes'] and options.get('allowtcpforwarding') in (['yes'], ['local']) and
               len(permit) == 1 and (permit[0] == 'any' or str(address) + ':3001' in permit[0].split()), 'SSHD_POLICY')
        return {'version': 1, 'account': account, 'uid': user.pw_uid, 'gid': user.pw_gid,
                'home': user.pw_dir, 'public_key': canonical_key, 'original_sha256': original,
                'relay_id': relay['Id'], 'relay_image': relay['Image'], 'network_id': network['NetworkID'],
                'relay_ip': str(address), 'sshd_sha256': hashlib.sha256(settings).hexdigest()}
    finally:
        os.close(ssh_fd)


def _registry(create):
    parent = _directory(REGISTRY_PARENT, owner=0)
    try:
        if create:
            try:
                os.mkdir(REGISTRY_NAME, 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
        fd = os.open(REGISTRY_NAME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        info = os.fstat(fd)
        demand(info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'REGISTRY')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _locked(registry):
    demand(fcntl is not None, 'ROOT')
    fd = os.open('operator.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=registry)
    try:
        info = os.fstat(fd)
        demand(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
               info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, 'LOCK')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_record(registry, name, optional=False):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=registry)
    except FileNotFoundError:
        if optional:
            return None
        raise
    try:
        info = os.fstat(fd)
        demand(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
               stat.S_IMODE(info.st_mode) == 0o600, 'RECORD')
        if info.st_nlink > 1:
            aliases = []
            for entry in os.listdir(registry):
                if re.fullmatch(r'\.h454-[a-f0-9]{32}', entry) is None:
                    continue
                candidate = os.stat(entry, dir_fd=registry, follow_symlinks=False)
                if (candidate.st_dev, candidate.st_ino) == (info.st_dev, info.st_ino):
                    aliases.append(entry)
            demand(len(aliases) == info.st_nlink - 1, 'RECORD_LINKS')
            for entry in aliases:
                os.unlink(entry, dir_fd=registry)
            os.fsync(registry)
        demand(os.fstat(fd).st_nlink == 1, 'RECORD_LINKS')
        return key_slot._read(fd, 16_384)
    finally:
        os.close(fd)


def _write_once(registry, name, data):
    existing = _read_record(registry, name, optional=True)
    if existing is not None:
        demand(existing == data, 'RECORD_DRIFT')
        return
    temp = '.h454-' + secrets.token_hex(16)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=registry)
    try:
        offset = 0
        while offset < len(data):
            count = os.write(fd, data[offset:])
            demand(count > 0, 'RECORD_WRITE')
            offset += count
        os.fsync(fd)
        try:
            os.link(temp, name, src_dir_fd=registry, dst_dir_fd=registry, follow_symlinks=False)
        except FileExistsError:
            demand(_read_record(registry, name) == data, 'RECORD_DRIFT')
        os.fsync(registry)
    finally:
        os.close(fd)
        os.unlink(temp, dir_fd=registry)
    demand(_read_record(registry, name) == data, 'RECORD_DRIFT')


def _bytes(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')


def _request(registry, pin):
    demand(isinstance(pin, str) and HEX.fullmatch(pin) is not None, 'REQUEST_PIN')
    raw = _read_record(registry, 'request.json')
    demand(hashlib.sha256(raw).hexdigest() == pin, 'REQUEST_DRIFT')
    value = json.loads(raw)
    fields = {'version', 'account', 'uid', 'gid', 'home', 'public_key', 'original_sha256',
              'relay_id', 'relay_image', 'network_id', 'relay_ip', 'sshd_sha256'}
    demand(isinstance(value, dict) and set(value) == fields and _bytes(value) == raw and
           type(value['version']) is int and value['version'] == 1 and
           type(value['uid']) is int and value['uid'] > 0 and type(value['gid']) is int and value['gid'] >= 0 and
           all(isinstance(value[name], str) for name in fields - {'version', 'uid', 'gid'}) and
           all(HEX.fullmatch(value[name]) is not None for name in ('original_sha256', 'relay_id', 'network_id', 'sshd_sha256')) and
           re.fullmatch(r'sha256:[a-f0-9]{64}', value['relay_image']) is not None, 'REQUEST')
    return value


def prepare(account, public_key):
    request = snapshot(account, public_key)
    registry = _registry(True)
    lock = None
    try:
        lock = _locked(registry)
        previous = _read_record(registry, 'request.json', optional=True)
        if previous is None:
            user, ssh_fd = _ssh_directory(account)
            try:
                try:
                    os.stat(key_slot.TARGET, dir_fd=ssh_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise Hold('SECOND_FILE_OCCUPIED')
                demand(os.fstat(registry).st_dev == os.fstat(ssh_fd).st_dev, 'FILESYSTEM')
            finally:
                os.close(ssh_fd)
        raw = _bytes(request)
        _write_once(registry, 'request.json', raw)
        return hashlib.sha256(raw).hexdigest()
    finally:
        if lock is not None:
            os.close(lock)
        os.close(registry)


def install(pin):
    registry = _registry(False)
    lock = None
    try:
        lock = _locked(registry)
        request = _request(registry, pin)
        demand(snapshot(request['account'], request['public_key']) == request, 'SNAPSHOT_DRIFT')
        user, ssh_fd = _ssh_directory(request['account'], request)
        try:
            previous = _read_record(registry, 'receipt.json', optional=True)
            if previous is not None:
                slot = os.open(key_slot.SLOT, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=registry)
                try:
                    info = os.fstat(slot)
                    data = key_slot._read(slot, 4096)
                finally:
                    os.close(slot)
                expected = hashlib.sha256(restricted_second_key(request['public_key'], request['relay_ip'])).hexdigest()
                demand(hashlib.sha256(data).hexdigest() == expected and
                       previous == _bytes({'version': 1, 'request_sha256': pin, 'device': info.st_dev,
                                           'inode': info.st_ino, 'sha256': expected}), 'RECEIPT_DRIFT')
            try:
                receipt = key_slot.install(registry, ssh_fd, uid=user.pw_uid,
                    original_sha256=request['original_sha256'], public_key=request['public_key'], relay_ip=request['relay_ip'])
            except key_slot.SecondKeyHold as exc:
                if str(exc) == 'KEY_INSTALL_UNSETTLED':
                    raise Unsettled('INSTALL_UNSETTLED') from exc
                raise
            try:
                demand(snapshot(request['account'], request['public_key']) == request, 'SNAPSHOT_DRIFT')
                _write_once(registry, 'receipt.json', _bytes({'version': 1, 'request_sha256': pin, **receipt}))
            except Exception as exc:
                try:
                    key_slot.revoke(registry, ssh_fd, uid=user.pw_uid, **receipt)
                except Exception as revoke_error:
                    raise Unsettled('INSTALL_UNSETTLED') from revoke_error
                raise Hold('INSTALL_REVOKED') from exc
        finally:
            os.close(ssh_fd)
    finally:
        if lock is not None:
            os.close(lock)
        os.close(registry)


def revoke(pin):
    registry = _registry(False)
    lock = None
    try:
        lock = _locked(registry)
        request = _request(registry, pin)
        user, ssh_fd = _ssh_directory(request['account'], request)
        try:
            try:
                slot = os.open(key_slot.SLOT, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=registry)
            except FileNotFoundError:
                try:
                    os.stat(key_slot.TARGET, dir_fd=ssh_fd, follow_symlinks=False)
                except FileNotFoundError:
                    return 'ABSENT'
                raise Hold('SLOT_MISSING')
            try:
                info = os.fstat(slot)
                data = key_slot._read(slot, 4096)
            finally:
                os.close(slot)
            expected = hashlib.sha256(restricted_second_key(request['public_key'], request['relay_ip'])).hexdigest()
            demand(not data or hashlib.sha256(data).hexdigest() == expected, 'SLOT_DRIFT')
            receipt = _read_record(registry, 'receipt.json', optional=True)
            if receipt is not None:
                demand(receipt == _bytes({'version': 1, 'request_sha256': pin, 'device': info.st_dev,
                                         'inode': info.st_ino, 'sha256': expected}), 'RECEIPT_DRIFT')
            key_slot.revoke(registry, ssh_fd, uid=user.pw_uid, device=info.st_dev, inode=info.st_ino, sha256=expected)
            return 'EMPTY'
        finally:
            os.close(ssh_fd)
    finally:
        if lock is not None:
            os.close(lock)
        os.close(registry)


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        demand(name not in result, 'DUPLICATE_INPUT')
        result[name] = value
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('prepare', 'install', 'revoke'))
    parser.add_argument('--request-sha256')
    parser.add_argument('--owner-approved', action='store_true')
    args = parser.parse_args()
    try:
        if args.mode == 'prepare':
            demand(args.request_sha256 is None and not args.owner_approved, 'ARGUMENTS')
            raw = sys.stdin.buffer.read(4097)
            demand(len(raw) <= 4096, 'INPUT')
            value = json.loads(raw, object_pairs_hook=_unique_object)
            demand(isinstance(value, dict) and set(value) == {'account', 'public_key'}, 'INPUT')
            print('H454_RELAY_REQUEST_SHA256=' + prepare(value['account'], value['public_key']))
        else:
            demand(args.owner_approved and args.request_sha256 is not None, 'APPROVAL')
            if args.mode == 'install':
                install(args.request_sha256)
                print('H454_RELAY_KEY=INSTALLED_PENDING_CONNECTION_TEST')
            else:
                status = revoke(args.request_sha256)
                print('H454_RELAY_KEY_SLOT=' + status)
                print('H454_EXISTING_SESSIONS=NOT_TERMINATED')
                print('H454_OTHER_KEY_PATHS=NOT_VERIFIED')
    except Unsettled:
        print('H454_RELAY_AUTHORIZATION=HOLD_UNSETTLED')
        return 2
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, ForwardAuthorizationError):
        print('H454_RELAY_AUTHORIZATION=HOLD')
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
