"""Restart one pinned WSS sidecar after its pinned relay returns."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import time

try:
    import fcntl
except ImportError:
    fcntl = None


HEX = re.compile(r'[a-f0-9]{64}\Z')
IMAGE = re.compile(r'sha256:[a-f0-9]{64}\Z')
NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z')
FIELDS = {'version', 'relay_id', 'relay_name', 'relay_image', 'network_id', 'network_name',
          'relay_ipv4', 'gateway_ipv4', 'sidecar_id', 'sidecar_name', 'sidecar_image',
          'profile_sha256', 'proxy_sha256', 'ca_sha256', 'certificate_sha256', 'key_sha256',
          'tls_directory'}
DOCKER = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']
MARKER = 'reconcile.pending'


class Hold(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Hold(reason)


def _directory(path):
    require(path.is_absolute() and os.path.realpath(path) == str(path), 'DIRECTORY')
    for parent in path.parents:
        info = os.lstat(parent)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
                (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX), 'DIRECTORY')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if not (stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
            stat.S_IMODE(info.st_mode) == 0o700):
        os.close(fd)
        raise Hold('DIRECTORY')
    return fd


def _read_fd(fd, mode, gid=0, maximum=65536):
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == gid and
            info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode and
            0 < info.st_size <= maximum, 'FILE')
    data = b''
    while len(data) <= maximum:
        part = os.read(fd, min(8192, maximum + 1 - len(data)))
        if not part:
            break
        data += part
    after = os.fstat(fd)
    require(len(data) == info.st_size and
            (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'FILE_DRIFT')
    return data


def _read_file(directory, name, mode, gid=0, maximum=65536):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        return _read_fd(fd, mode, gid, maximum)
    finally:
        os.close(fd)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'PINS')
        result[key] = value
    return result


def _pins(raw):
    pins = json.loads(raw, object_pairs_hook=_unique)
    require(isinstance(pins, dict) and set(pins) == FIELDS and type(pins['version']) is int and
            pins['version'] == 1, 'PINS')
    for name in ('relay_id', 'network_id', 'sidecar_id', 'profile_sha256', 'proxy_sha256',
                 'ca_sha256', 'certificate_sha256', 'key_sha256'):
        require(isinstance(pins[name], str) and HEX.fullmatch(pins[name]) is not None, 'PINS')
    for name in ('relay_image', 'sidecar_image'):
        require(isinstance(pins[name], str) and IMAGE.fullmatch(pins[name]) is not None, 'PINS')
    for name in ('relay_name', 'network_name', 'sidecar_name'):
        require(isinstance(pins[name], str) and NAME.fullmatch(pins[name]) is not None, 'PINS')
    for name in ('relay_ipv4', 'gateway_ipv4'):
        address = ipaddress.IPv4Address(pins[name])
        require(str(address) == pins[name] and any(address in ipaddress.IPv4Network(cidr) for cidr in
                ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')), 'PINS')
    require(pins['relay_ipv4'] != pins['gateway_ipv4'] and pins['relay_id'] != pins['sidecar_id'] and
            isinstance(pins['tls_directory'], str), 'PINS')
    return pins


def _docker(*arguments):
    result = subprocess.run(DOCKER + list(arguments), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=15, check=True,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(len(result.stdout) <= 1_048_576, 'DOCKER_OUTPUT')
    return result.stdout


def _inspect(kind, identity):
    value = json.loads(_docker(kind, 'inspect', identity), object_pairs_hook=_unique)
    require(isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict), 'INSPECT')
    return value[0]


def profile_sha256(sidecar):
    mounts = sidecar['Mounts']
    require(isinstance(mounts, list) and all(isinstance(mount, dict) and
            isinstance(mount.get('Destination'), str) for mount in mounts) and
            len({mount['Destination'] for mount in mounts}) == len(mounts), 'SIDECAR_PROFILE')
    config = dict(sidecar['Config'])
    host = dict(sidecar['HostConfig'])
    require('Hostname' in config and 'OomKillDisable' in host, 'SIDECAR_PROFILE')
    mode = host.get('NetworkMode')
    relay_id = mode[10:] if isinstance(mode, str) and mode.startswith('container:') else ''
    own_id = sidecar.get('Id')
    require(isinstance(own_id, str) and HEX.fullmatch(own_id) and HEX.fullmatch(relay_id) and
            config.get('Hostname') in (own_id[:12], relay_id[:12]), 'SIDECAR_PROFILE')
    config['Hostname'] = '<docker-container-network>'
    if host.get('OomKillDisable') is None or host.get('OomKillDisable') is False:
        host['OomKillDisable'] = False
    profile = {'Config': config, 'HostConfig': host,
               'Mounts': sorted(mounts, key=lambda mount: mount['Destination'])}
    raw = json.dumps(profile, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return hashlib.sha256(raw).hexdigest()


def _snapshot(pins, directory, tls_directory):
    relay = _inspect('container', pins['relay_id'])
    sidecar = _inspect('container', pins['sidecar_id'])
    network = _inspect('network', pins['network_id'])
    require(relay['Id'] == pins['relay_id'] and relay['Name'] == '/' + pins['relay_name'] and
            relay['Image'] == pins['relay_image'] and relay['State']['Running'] is True and
            not relay['State']['Paused'] and not relay['State']['Restarting'] and
            set(relay['NetworkSettings']['Networks']) == {pins['network_name']}, 'RELAY')
    endpoint = relay['NetworkSettings']['Networks'][pins['network_name']]
    require(endpoint['NetworkID'] == pins['network_id'] and endpoint['IPAddress'] == pins['relay_ipv4'] and
            (endpoint.get('IPAMConfig') or {}).get('IPv4Address') == pins['relay_ipv4'] and
            not endpoint.get('GlobalIPv6Address'), 'RELAY_NETWORK')
    config = network['IPAM']['Config']
    require(network['Id'] == pins['network_id'] and network['Name'] == pins['network_name'] and
            network['Driver'] == 'bridge' and network['Internal'] is True and network['EnableIPv6'] is False and
            len(config) == 1 and config[0]['Gateway'] == pins['gateway_ipv4'] and
            ipaddress.IPv4Address(pins['relay_ipv4']) in ipaddress.IPv4Network(config[0]['Subnet']) and
            ipaddress.IPv4Address(pins['gateway_ipv4']) in ipaddress.IPv4Network(config[0]['Subnet']) and
            pins['relay_id'] in network['Containers'], 'NETWORK')
    host = sidecar['HostConfig']
    env = sidecar['Config']['Env'] or []
    mounts = sidecar['Mounts']
    expected_mounts = {
        '/run/h454-wss/proxy.mjs': str(directory / 'proxy.mjs'),
        '/run/h454-wss/relay.key': str(tls_directory / 'relay.key'),
        '/run/h454-wss/relay.crt': str(tls_directory / 'relay.crt'),
    }
    require(sidecar['Id'] == pins['sidecar_id'] and sidecar['Name'] == '/' + pins['sidecar_name'] and
            sidecar['Image'] == pins['sidecar_image'], 'SIDECAR_IDENTITY')
    require(profile_sha256(sidecar) == pins['profile_sha256'], 'SIDECAR_PROFILE')
    require(sidecar['Config']['User'] == '65534:65534' and sidecar['Config']['Entrypoint'] == ['node'] and
            sidecar['Config']['Cmd'] == ['/run/h454-wss/proxy.mjs'], 'SIDECAR_CONFIG')
    require(
            [x for x in env if x.startswith('H454_SSH_SOURCE_IPV4=')] ==
                ['H454_SSH_SOURCE_IPV4=' + pins['gateway_ipv4']] and
            not any(x.startswith(('NODE_OPTIONS=', 'NODE_PATH=', 'NODE_EXTRA_CA_CERTS=',
                                  'NODE_TLS_REJECT_UNAUTHORIZED=', 'LD_PRELOAD=', 'LD_LIBRARY_PATH=')) for x in env),
            'SIDECAR_ENVIRONMENT')
    require(host['NetworkMode'] == 'container:' + pins['relay_id'] and host['ReadonlyRootfs'] is True and
            host['Privileged'] is False and 'ALL' in (host.get('CapDrop') or []) and
            (host.get('OomKillDisable') is None or host.get('OomKillDisable') is False) and
            not host.get('CapAdd') and not host.get('Devices') and not host.get('DeviceRequests') and
            host.get('PidMode') != 'host' and host.get('IpcMode') != 'host' and
            0 < host['PidsLimit'] <= 64 and 0 < host['Memory'] <= 268_435_456 and
            set(host.get('SecurityOpt') or []) == {'no-new-privileges'} and
            host['RestartPolicy']['Name'] == 'unless-stopped' and not host['PortBindings'] and
            not host['PublishAllPorts'], 'SIDECAR_RUNTIME')
    require(len(mounts) == len(expected_mounts) and
            all(mount['Type'] == 'bind' and mount['RW'] is False and
                expected_mounts.get(mount['Destination']) == mount['Source'] for mount in mounts) and
            {mount['Destination'] for mount in mounts} == set(expected_mounts), 'SIDECAR_MOUNTS')
    return relay, sidecar


def _tls(pins, ca):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=ca.decode('ascii'))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((pins['relay_ipv4'], 3001), timeout=3) as connection:
        with context.wrap_socket(connection, server_hostname='brc-agent.internal') as secure:
            secure.settimeout(3)
            secure.sendall(b'GET / HTTP/1.1\r\nHost: brc-agent.internal\r\nConnection: close\r\n\r\n')
            response = b''
            while b'\r\n' not in response and len(response) < 8192:
                part = secure.recv(1024)
                if not part:
                    break
                response += part
            require(response.split(b'\r\n', 1)[0] == b'HTTP/1.1 404 Not Found', 'TLS_PROBE')


def _namespace(relay, sidecar):
    require(relay['State']['Running'] is True and sidecar['State']['Running'] is True, 'NOT_RUNNING')
    first, second = relay['State']['Pid'], sidecar['State']['Pid']
    require(type(first) is int and first > 0 and type(second) is int and second > 0 and
            os.stat('/proc/' + str(first) + '/ns/net').st_ino ==
            os.stat('/proc/' + str(second) + '/ns/net').st_ino, 'NAMESPACE')


def reconcile(config_path):
    require(fcntl is not None and os.name == 'posix' and os.geteuid() == 0, 'ROOT')
    config_path = Path(config_path)
    require(config_path.name == 'pins.json', 'PINS')
    directory = config_path.parent
    dir_fd = _directory(directory)
    config_fd = None
    tls_fd = None
    try:
        config_fd = os.open('pins.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
        fcntl.flock(config_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = os.fstat(config_fd)
        raw = _read_fd(config_fd, 0o600, maximum=16384)
        named = os.stat('pins.json', dir_fd=dir_fd, follow_symlinks=False)
        require((locked.st_dev, locked.st_ino) == (named.st_dev, named.st_ino), 'PINS_DRIFT')
        pins = _pins(raw)
        for marker_name in ('prepare.pending', MARKER):
            try:
                os.stat(marker_name, dir_fd=dir_fd, follow_symlinks=False)
                raise Hold('PENDING')
            except FileNotFoundError:
                pass
        tls_directory = Path(pins['tls_directory'])
        tls_fd = _directory(tls_directory)
        for name, descriptor, mode, gid, digest in (
                ('proxy.mjs', dir_fd, 0o444, 0, pins['proxy_sha256']),
                ('ca.crt', tls_fd, 0o444, 0, pins['ca_sha256']),
                ('relay.crt', tls_fd, 0o444, 0, pins['certificate_sha256']),
                ('relay.key', tls_fd, 0o440, 65534, pins['key_sha256'])):
            data = _read_file(descriptor, name, mode, gid)
            require(hashlib.sha256(data).hexdigest() == digest, 'FILE_DRIFT')
            if name == 'ca.crt':
                ca = data
        relay, sidecar = _snapshot(pins, directory, tls_directory)
        if sidecar['State']['Running'] is True:
            _namespace(relay, sidecar)
            _tls(pins, ca)
            return 'READY'
        require(sidecar['State']['Status'] in ('created', 'exited') and not sidecar['State']['Paused'] and
                not sidecar['State']['Restarting'] and not sidecar['State']['Dead'], 'SIDECAR_STATE')
        marker = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
        try:
            os.fchmod(marker, 0o600)
            marker_data = hashlib.sha256(raw).hexdigest().encode('ascii') + b'\n'
            require(os.write(marker, marker_data) == len(marker_data), 'PENDING_WRITE')
            os.fsync(marker)
            marker_info = os.fstat(marker)
        finally:
            os.close(marker)
        os.fsync(dir_fd)
        require(_docker('start', pins['sidecar_id']).decode('ascii').strip() == pins['sidecar_id'], 'START')
        deadline = time.monotonic() + 20
        while True:
            try:
                relay, sidecar = _snapshot(pins, directory, tls_directory)
                _namespace(relay, sidecar)
                _tls(pins, ca)
                break
            except (Hold, OSError, ssl.SSLError):
                if time.monotonic() >= deadline:
                    raise Hold('START_UNVERIFIED')
                time.sleep(0.5)
        named = os.stat(MARKER, dir_fd=dir_fd, follow_symlinks=False)
        require((named.st_dev, named.st_ino) == (marker_info.st_dev, marker_info.st_ino) and
                _read_file(dir_fd, MARKER, 0o600, maximum=128) ==
                hashlib.sha256(raw).hexdigest().encode('ascii') + b'\n', 'PENDING_DRIFT')
        os.unlink(MARKER, dir_fd=dir_fd)
        os.fsync(dir_fd)
        return 'RESTARTED'
    finally:
        if tls_fd is not None:
            os.close(tls_fd)
        if config_fd is not None:
            os.close(config_fd)
        os.close(dir_fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    try:
        print('H454_WSS_RECONCILE=' + reconcile(args.config))
        return 0
    except Hold as error:
        print('H454_WSS_RECONCILE=HOLD')
        reason = str(error)
        print('H454_WSS_RECONCILE_REASON=' + (reason if re.fullmatch(r'[A-Z_]{1,60}', reason) else 'INTERNAL'))
        return 2
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('H454_WSS_RECONCILE=HOLD')
        print('H454_WSS_RECONCILE_REASON=INTERNAL')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
