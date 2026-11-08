"""Prepare one pinned WSS sidecar without starting it or authorizing an SSH key."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import stat
import subprocess

from scripts import h454_relay_authorization_operator as authorization
from scripts import h454_relay_tls_identity as identity
from scripts import h454_wss_relay_reconcile as reconcile


PARENT = Path('/var/lib')
NAME = 'hermes-h454-wss-sidecar'
CONTAINER = 'hermes-h454-wss-proxy'


def _source(path, expected):
    reconcile.require(isinstance(expected, str) and reconcile.HEX.fullmatch(expected), 'SOURCE_PIN')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        reconcile.require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 100_000, 'SOURCE')
        data = b''
        while len(data) <= 100_000:
            part = os.read(fd, min(8192, 100_001 - len(data)))
            if not part:
                break
            data += part
        after = os.fstat(fd)
        reconcile.require(len(data) == before.st_size and
                          (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                          (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                          hashlib.sha256(data).hexdigest() == expected, 'SOURCE_DRIFT')
        return data
    finally:
        os.close(fd)


def _write_new(directory, name, data, mode):
    reconcile.require(isinstance(data, bytes) and 0 < len(data) <= 100_000, 'WRITE')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=directory)
    try:
        os.fchmod(fd, mode)
        offset = 0
        while offset < len(data):
            count = os.write(fd, data[offset:])
            reconcile.require(count > 0, 'WRITE')
            offset += count
        os.fsync(fd)
        info = os.fstat(fd)
        reconcile.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and
                          info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode, 'WRITE')
    finally:
        os.close(fd)
    os.fsync(directory)


def _relay(request):
    reconcile.require(authorization.snapshot(request['account'], request['public_key']) == request, 'REQUEST_DRIFT')
    relay = reconcile._inspect('container', request['relay_id'])
    network = reconcile._inspect('network', request['network_id'])
    endpoint = relay['NetworkSettings']['Networks'][authorization.NETWORK_NAME]
    config = network['IPAM']['Config']
    reconcile.require(relay['Id'] == request['relay_id'] and relay['Image'] == request['relay_image'] and
                      relay['Name'] == '/' + authorization.RELAY_NAME and relay['State']['Running'] is True and
                      not relay['State']['Paused'] and not relay['State']['Restarting'] and
                      set(relay['NetworkSettings']['Networks']) == {authorization.NETWORK_NAME} and
                      endpoint['NetworkID'] == request['network_id'] and endpoint['IPAddress'] == request['relay_ip'] and
                      (endpoint.get('IPAMConfig') or {}).get('IPv4Address') == request['relay_ip'] and
                      not endpoint.get('GlobalIPv6Address'), 'RELAY')
    reconcile.require(network['Id'] == request['network_id'] and network['Name'] == authorization.NETWORK_NAME and
                      network['Driver'] == 'bridge' and network['Internal'] is True and network['EnableIPv6'] is False and
                      len(config) == 1 and request['relay_id'] in network['Containers'], 'NETWORK')
    subnet = ipaddress.IPv4Network(config[0]['Subnet'])
    gateway = ipaddress.IPv4Address(config[0]['Gateway'])
    address = ipaddress.IPv4Address(request['relay_ip'])
    reconcile.require(address in subnet and gateway in subnet and address != gateway and
                      any(gateway in ipaddress.IPv4Network(cidr) for cidr in
                          ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')), 'NETWORK')
    image = reconcile._inspect('image', request['relay_image'])
    reconcile.require(image['Id'] == request['relay_image'] and not image['Config'].get('Volumes'), 'IMAGE')
    return relay, str(gateway)


def _port_free(pid):
    reconcile.require(type(pid) is int and pid > 0, 'RELAY')
    output = authorization._run(['/usr/bin/nsenter', '-t', str(pid), '-n', '/usr/bin/ss', '-H', '-ltn'], 131_072)
    reconcile.require(not any(re.search(rb':3001(?:\s|$)', line) for line in output.splitlines()), 'PORT_OCCUPIED')


def prepare(request_sha256, ca_sha256, proxy_sha256, reconciler_sha256, proxy, reconciler):
    reconcile.require(os.name == 'posix' and os.geteuid() == 0, 'ROOT')
    for digest in (request_sha256, ca_sha256, proxy_sha256, reconciler_sha256):
        reconcile.require(isinstance(digest, str) and reconcile.HEX.fullmatch(digest), 'PIN')
    reconcile.require(isinstance(proxy, bytes) and 0 < len(proxy) <= 100_000 and
                      isinstance(reconciler, bytes) and 0 < len(reconciler) <= 100_000 and
                      hashlib.sha256(proxy).hexdigest() == proxy_sha256 and
                      hashlib.sha256(reconciler).hexdigest() == reconciler_sha256, 'SOURCE_DRIFT')
    registry = authorization._registry(False)
    lock = None
    parent = None
    directory = None
    try:
        lock = authorization._locked(registry)
        request = authorization._request(registry, request_sha256)
        relay, gateway = _relay(request)
        tls_directory = identity.PARENT / identity.NAME
        manifest = identity.verify(tls_directory)
        reconcile.require(manifest['ca_sha256'] == ca_sha256, 'TLS_PIN')
        tls_fd = reconcile._directory(tls_directory)
        try:
            key_hash = hashlib.sha256(reconcile._read_file(tls_fd, 'relay.key', 0o440, 65534)).hexdigest()
        finally:
            os.close(tls_fd)
        _port_free(relay['State']['Pid'])
        names = reconcile._docker('container', 'ls', '--all', '--format', '{{.Names}}').decode('ascii').splitlines()
        reconcile.require(CONTAINER not in names, 'CONTAINER_OCCUPIED')
        parent = authorization._directory(PARENT, owner=0)
        try:
            os.mkdir(NAME, 0o700, dir_fd=parent)
        except FileExistsError as error:
            raise reconcile.Hold('REGISTRY_OCCUPIED') from error
        os.fsync(parent)
        directory = os.open(NAME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        info = os.fstat(directory)
        reconcile.require(info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'REGISTRY')
        marker = authorization._bytes({'version': 1, 'request_sha256': request_sha256, 'ca_sha256': ca_sha256,
                                       'proxy_sha256': proxy_sha256, 'reconciler_sha256': reconciler_sha256})
        _write_new(directory, 'prepare.pending', marker, 0o600)
        marker_info = os.stat('prepare.pending', dir_fd=directory, follow_symlinks=False)
        _write_new(directory, 'proxy.mjs', proxy, 0o444)
        _write_new(directory, 'reconcile.py', reconciler, 0o444)
        directory_path = PARENT / NAME
        output = reconcile._docker('create', '--pull=never', '--name', CONTAINER,
            '--label', 'com.hermes.h454.role=wss-proxy', '--label', 'com.hermes.h454.request=' + request_sha256,
            '--network', 'container:' + request['relay_id'], '--restart', 'unless-stopped', '--read-only',
            '--user', '65534:65534', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--pids-limit', '32', '--memory', '128m', '-e', 'H454_SSH_SOURCE_IPV4=' + gateway,
            '--mount', 'type=bind,src=' + str(directory_path / 'proxy.mjs') + ',dst=/run/h454-wss/proxy.mjs,readonly',
            '--mount', 'type=bind,src=' + str(tls_directory / 'relay.key') + ',dst=/run/h454-wss/relay.key,readonly',
            '--mount', 'type=bind,src=' + str(tls_directory / 'relay.crt') + ',dst=/run/h454-wss/relay.crt,readonly',
            '--entrypoint', 'node', request['relay_image'], '/run/h454-wss/proxy.mjs').decode('ascii').strip()
        reconcile.require(reconcile.HEX.fullmatch(output), 'CONTAINER_ID')
        sidecar = reconcile._inspect('container', output)
        reconcile.require(sidecar['State']['Status'] == 'created' and sidecar['State']['Running'] is False, 'CONTAINER_STATE')
        pins = {'version': 1, 'relay_id': request['relay_id'], 'relay_name': authorization.RELAY_NAME,
                'relay_image': request['relay_image'], 'network_id': request['network_id'],
                'network_name': authorization.NETWORK_NAME, 'relay_ipv4': request['relay_ip'],
                'gateway_ipv4': gateway, 'sidecar_id': output, 'sidecar_name': CONTAINER,
                'sidecar_image': request['relay_image'], 'profile_sha256': reconcile.profile_sha256(sidecar),
                'proxy_sha256': proxy_sha256, 'ca_sha256': ca_sha256,
                'certificate_sha256': manifest['certificate_sha256'], 'key_sha256': key_hash,
                'tls_directory': str(tls_directory)}
        reconcile._snapshot(pins, directory_path, tls_directory)
        current_relay, current_gateway = _relay(request)
        reconcile.require(current_gateway == gateway and identity.verify(tls_directory) == manifest, 'FINAL_DRIFT')
        _port_free(current_relay['State']['Pid'])
        _write_new(directory, 'pins.json', authorization._bytes(pins), 0o600)
        current_marker = os.stat('prepare.pending', dir_fd=directory, follow_symlinks=False)
        reconcile.require((current_marker.st_dev, current_marker.st_ino) == (marker_info.st_dev, marker_info.st_ino) and
                          reconcile._read_file(directory, 'prepare.pending', 0o600) == marker, 'MARKER_DRIFT')
        os.unlink('prepare.pending', dir_fd=directory)
        os.fsync(directory)
        return hashlib.sha256(authorization._bytes(pins)).hexdigest()
    finally:
        for fd in (directory, parent, lock, registry):
            if fd is not None:
                os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--request-sha256', required=True)
    parser.add_argument('--ca-sha256', required=True)
    parser.add_argument('--proxy-sha256', required=True)
    parser.add_argument('--reconciler-sha256', required=True)
    parser.add_argument('--owner-approved', action='store_true')
    args = parser.parse_args()
    try:
        reconcile.require(args.owner_approved, 'APPROVAL')
        directory = Path(__file__).resolve().parent
        proxy = _source(directory / 'h454_wss_relay_proxy.mjs', args.proxy_sha256)
        reconciler = _source(directory / 'h454_wss_relay_reconcile.py', args.reconciler_sha256)
        receipt = prepare(args.request_sha256, args.ca_sha256, args.proxy_sha256,
                          args.reconciler_sha256, proxy, reconciler)
        print('H454_SIDECAR_PREPARE=CREATED_NOT_STARTED')
        print('H454_SIDECAR_PINS_SHA256=' + receipt.upper())
        return 0
    except (reconcile.Hold, authorization.Hold) as error:
        reason = str(error)
        print('H454_SIDECAR_PREPARE=HOLD')
        print('H454_SIDECAR_PREPARE_REASON=' + (reason if re.fullmatch(r'[A-Z_]{1,60}', reason) else 'INTERNAL'))
        return 2
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('H454_SIDECAR_PREPARE=HOLD')
        print('H454_SIDECAR_PREPARE_REASON=INSPECT_BEFORE_RETRY')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
