"""Prepare an owner-local CA and relay certificate without opening a listener."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess

from scripts.h454_relay_authorization_operator import Hold, _bytes, _directory, _names, demand
from scripts.h454_relay_second_authorized_key import _read

PARENT = Path('/var/lib')
NAME = 'hermes-h454-wss-tls'
OPENSSL = '/usr/bin/openssl'
FILES = {'ca.key', 'ca.crt', 'relay.key', 'relay.crt', 'manifest.json'}
TEMP_FILES = FILES | {'relay.csr', 'relay.ext'}


def _openssl(directory, args, *, input_bytes=None, timeout=45):
    result = subprocess.run([OPENSSL, *args], cwd=directory, input=input_bytes,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=True,
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null'})
    demand(len(result.stdout) <= 65_536, 'OPENSSL_OUTPUT')
    return result.stdout


def _file(directory, name, *, mode, gid=0, maximum=65_536, read=True):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        info = os.fstat(fd)
        demand(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == gid and
               info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode and 0 < info.st_size <= maximum,
               'TLS_FILE')
        return _read(fd, maximum) if read else None
    finally:
        os.close(fd)


def _public_key(directory, certificate, key):
    detail = _openssl(directory, ['pkey', '-in', key, '-pubout', '-text', '-noout']).decode('ascii')
    demand('Public-Key: (3072 bit)' in detail, 'TLS_KEY_SIZE')
    private_public = _openssl(directory, ['pkey', '-in', key, '-pubout', '-outform', 'DER'])
    pem = _openssl(directory, ['x509', '-in', certificate, '-pubkey', '-noout'])
    certificate_public = _openssl(directory, ['pkey', '-pubin', '-inform', 'PEM', '-outform', 'DER'],
                                  input_bytes=pem)
    demand(private_public == certificate_public and len(private_public) > 0, 'TLS_KEY_MISMATCH')
    return hashlib.sha256(private_public).hexdigest()


def _expiry(directory, certificate):
    value = _openssl(directory, ['x509', '-in', certificate, '-noout', '-enddate']).decode('ascii').strip()
    demand(value.startswith('notAfter=') and len(value) <= 64, 'TLS_EXPIRY')
    return value[9:]


def verify(directory):
    demand(os.name == 'posix' and os.geteuid() == 0, 'ROOT')
    fd = _directory(directory, owner=0, mode=0o700)
    try:
        demand(_names(fd) == FILES, 'TLS_CONTENTS')
        _file(fd, 'ca.key', mode=0o600, maximum=16_384, read=False)
        _file(fd, 'relay.key', mode=0o440, gid=65534, maximum=16_384, read=False)
        ca = _file(fd, 'ca.crt', mode=0o444)
        cert = _file(fd, 'relay.crt', mode=0o444)
        manifest_bytes = _file(fd, 'manifest.json', mode=0o600)
        manifest = json.loads(manifest_bytes)
        demand(isinstance(manifest, dict) and type(manifest.get('version')) is int and
               _bytes(manifest) == manifest_bytes, 'TLS_MANIFEST')
        _openssl(directory, ['verify', '-CAfile', 'ca.crt', '-purpose', 'sslserver',
                             '-verify_hostname', 'brc-agent.internal', 'relay.crt'])
        _openssl(directory, ['x509', '-in', 'relay.crt', '-noout', '-checkend', '2592000'])
        _openssl(directory, ['x509', '-in', 'ca.crt', '-noout', '-checkend', '15552000'])
        san = _openssl(directory, ['x509', '-in', 'relay.crt', '-noout', '-ext', 'subjectAltName']).decode('ascii')
        demand([line.strip() for line in san.splitlines() if line.strip().startswith('DNS:')] ==
               ['DNS:brc-agent.internal'], 'TLS_SAN')
        ca_constraints = _openssl(directory, ['x509', '-in', 'ca.crt', '-noout', '-ext', 'basicConstraints']).decode('ascii')
        relay_constraints = _openssl(directory, ['x509', '-in', 'relay.crt', '-noout', '-ext', 'basicConstraints']).decode('ascii')
        demand('CA:TRUE' in ca_constraints and 'pathlen:0' in ca_constraints and
               'CA:FALSE' in relay_constraints, 'TLS_CONSTRAINTS')
        ca_public = _public_key(directory, 'ca.crt', 'ca.key')
        relay_public = _public_key(directory, 'relay.crt', 'relay.key')
        expected = {'version': 1, 'ca_sha256': hashlib.sha256(ca).hexdigest(),
                    'certificate_sha256': hashlib.sha256(cert).hexdigest(),
                    'ca_public_sha256': ca_public, 'relay_public_sha256': relay_public,
                    'ca_expiry': _expiry(directory, 'ca.crt'), 'certificate_expiry': _expiry(directory, 'relay.crt')}
        demand(manifest == expected and ca_public != relay_public, 'TLS_MANIFEST')
        return expected
    finally:
        os.close(fd)


def _rename_no_replace(parent, source, destination):
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        rename = libc.renameat2
    except AttributeError as error:
        raise Hold('TLS_ATOMIC_RENAME_UNAVAILABLE') from error
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent, os.fsencode(source), parent, os.fsencode(destination), 1) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))


def _remove_owned_staging(parent, name, expected):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    except FileNotFoundError:
        return
    try:
        info = os.fstat(fd)
        demand((info.st_dev, info.st_ino) == expected and info.st_uid == 0 and
               stat.S_IMODE(info.st_mode) == 0o700, 'TLS_STAGING_DRIFT')
        names = _names(fd)
        demand(names <= TEMP_FILES, 'TLS_STAGING_DRIFT')
        for item in names:
            current = os.stat(item, dir_fd=fd, follow_symlinks=False)
            demand(stat.S_ISREG(current.st_mode) and current.st_uid == 0 and current.st_nlink == 1,
                   'TLS_STAGING_DRIFT')
        for item in names:
            os.unlink(item, dir_fd=fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent)
    os.fsync(parent)


def _assert_no_staging(parent):
    count = 0
    with os.scandir(parent) as entries:
        for entry in entries:
            count += 1
            demand(count <= 8192, 'TLS_PARENT_SIZE')
            demand(re.fullmatch(r'\.h454-tls-[a-f0-9]{32}', entry.name) is None, 'TLS_STAGING_PENDING')


def prepare():
    demand(os.name == 'posix' and os.geteuid() == 0, 'ROOT')
    parent = _directory(PARENT, owner=0)
    temp = '.h454-tls-' + secrets.token_hex(16)
    temp_identity = None
    old_umask = os.umask(0o077)
    try:
        try:
            os.stat(NAME, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Hold('TLS_TARGET_OCCUPIED')
        _assert_no_staging(parent)
        os.mkdir(temp, 0o700, dir_fd=parent)
        info = os.stat(temp, dir_fd=parent, follow_symlinks=False)
        temp_identity = (info.st_dev, info.st_ino)
        directory = PARENT / temp
        _openssl(directory, ['req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-keyout', 'ca.key',
                             '-out', 'ca.crt', '-sha256', '-days', '730', '-subj', '/CN=Hermes H454 WSS CA',
                             '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                             '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
        _openssl(directory, ['req', '-new', '-newkey', 'rsa:3072', '-nodes', '-keyout', 'relay.key',
                             '-out', 'relay.csr', '-subj', '/CN=brc-agent.internal'])
        ext = directory / 'relay.ext'
        with ext.open('x', encoding='ascii') as file:
            file.write('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                       'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:brc-agent.internal\n')
            file.flush()
            os.fsync(file.fileno())
        _openssl(directory, ['x509', '-req', '-in', 'relay.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
                             '-set_serial', '0x' + secrets.token_hex(16), '-out', 'relay.crt', '-days', '180',
                             '-sha256', '-extfile', 'relay.ext'])
        os.chown(directory / 'relay.key', 0, 65534, follow_symlinks=False)
        os.chmod(directory / 'relay.key', 0o440, follow_symlinks=False)
        os.chmod(directory / 'ca.crt', 0o444, follow_symlinks=False)
        os.chmod(directory / 'relay.crt', 0o444, follow_symlinks=False)
        ca = (directory / 'ca.crt').read_bytes()
        cert = (directory / 'relay.crt').read_bytes()
        manifest = {'version': 1, 'ca_sha256': hashlib.sha256(ca).hexdigest(),
                    'certificate_sha256': hashlib.sha256(cert).hexdigest(),
                    'ca_public_sha256': _public_key(directory, 'ca.crt', 'ca.key'),
                    'relay_public_sha256': _public_key(directory, 'relay.crt', 'relay.key'),
                    'ca_expiry': _expiry(directory, 'ca.crt'), 'certificate_expiry': _expiry(directory, 'relay.crt')}
        with (directory / 'manifest.json').open('xb') as file:
            file.write(_bytes(manifest))
            file.flush()
            os.fsync(file.fileno())
        (directory / 'relay.csr').unlink()
        ext.unlink()
        demand(verify(directory) == manifest, 'TLS_VERIFY')
        for name in FILES:
            fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        _rename_no_replace(parent, temp, NAME)
        os.fsync(parent)
        demand(verify(PARENT / NAME) == manifest, 'TLS_VERIFY')
        return manifest
    finally:
        os.umask(old_umask)
        try:
            if temp_identity is not None:
                _remove_owned_staging(parent, temp, temp_identity)
        finally:
            os.close(parent)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('prepare', 'verify'))
    parser.add_argument('--owner-approved', action='store_true')
    args = parser.parse_args()
    try:
        demand((args.mode == 'prepare') == args.owner_approved, 'APPROVAL')
        result = prepare() if args.mode == 'prepare' else verify(PARENT / NAME)
        print('H454_RELAY_TLS_IDENTITY=PREPARED')
        print('H454_RELAY_CA_SHA256=' + result['ca_sha256'].upper())
        print('H454_RELAY_TLS_LISTENER=NOT_STARTED')
    except Hold as error:
        print('H454_RELAY_TLS_IDENTITY=HOLD')
        if re.fullmatch(r'[A-Z0-9_]{1,80}', str(error)) is not None:
            print('H454_REASON=' + str(error))
        print('H454_TLS_STATE=INSPECT_BEFORE_RETRY')
        return 2
    except Exception:
        print('H454_RELAY_TLS_IDENTITY=HOLD')
        print('H454_TLS_STATE=INSPECT_BEFORE_RETRY')
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
