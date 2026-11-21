"""H454 private read-only BRC transport, pinned to the existing TLS sidecar.

No enrollment, service activation, public fallback, listener, or files written.
An independent owner-root host operator must install the immutable trust and
approved systemd IPAddressAllow singleton before using this transport.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
from typing import Callable

from device_fabric.native_brc_status import PUBLIC, TOKEN, IDENTITY, parse_status
from device_fabric.linux_native_outbound import ENDPOINT

TRUST = Path('/opt/hermes-commander-native/trust')
CONFIG = 'private-relay.json'
CA = 'ca.crt'
HOST = 'brc-agent.internal'
PORT = 3001
WS_URI = 'wss://brc-agent.internal:3001/ws'
UNIX_DIRECTORY = '/run/hermes-commander-tunnel'
UNIX_SOCKET = UNIX_DIRECTORY + '/relay.sock'
UNIX_ENDPOINT = 'unix:' + UNIX_SOCKET
CA_MAX_BYTES = 8192
SHA40 = re.compile(r'[0-9a-f]{40}\Z')
SHA64 = re.compile(r'[0-9a-f]{64}\Z')


class PrivateTLSDenied(ValueError):
    """No file paths, tokens or network details in denials."""


def _deny():
    raise PrivateTLSDenied('h454_private_tls_denied')


def _private_ip(text: str) -> bool:
    try:
        if type(text) is not str or text.strip() != text:
            return False
        ip = ipaddress.IPv4Address(text)
        # Only the existing owner-approved private Docker bridge, no
        # loopback, public, link-local, multicast or unspecified addresses.
        return str(ip) == text and any(ip in net for net in (
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
        )) and not ip.is_loopback and not ip.is_link_local
    except (ValueError, TypeError, ipaddress.AddressValueError):
        return False


def _guard_dir(root: Path) -> None:
    if not root.is_absolute():
        _deny()
    for path in (root, *root.parents):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            _deny()
    if stat.S_IMODE(root.lstat().st_mode) != 0o755:
        _deny()


def _read(root: Path, name: str, maximum: int) -> bytes:
    path = root / name
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or
        before.st_nlink != 1 or stat.S_IMODE(before.st_mode) not in (0o444, 0o644) or
        not 0 < before.st_size <= maximum):
        _deny()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        current = os.fstat(fd)
        data = os.read(fd, maximum + 1)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    attrs = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size',
             'st_ctime_ns', 'st_mtime_ns')
    if (len(data) != before.st_size or any(
            getattr(before, a) != getattr(current, a) or
            getattr(before, a) != getattr(after, a) for a in attrs)):
        _deny()
    return data


@dataclass(frozen=True, repr=False, slots=True)
class PrivateRelay:
    target: str
    release_sha: str
    relay_ipv4: str
    ca: bytes

    def __repr__(self) -> str:
        return 'PrivateRelay([PINNED])'


def load_private_relay(target: str, release_sha: str, *, root: Path = TRUST) -> PrivateRelay:
    """Owner-reviewed public CA and exact private relay IP, no ambient DNS."""
    try:
        if (target not in ('hermes-vps', 'yfc-vps') or
            type(release_sha) is not str or SHA40.fullmatch(release_sha) is None or
            not isinstance(root, Path)):
            _deny()
        _guard_dir(root)
        raw = _read(root, CONFIG, 2048)
        def unique(pairs):
            out = {}
            for key, val in pairs:
                if key in out:
                    _deny()
                out[key] = val
            return out
        info = json.loads(raw.decode('ascii'), object_pairs_hook=unique,
                          parse_constant=lambda _: _deny())
        if type(info) is not dict:
            _deny()
        common = {'schema', 'target', 'release_sha', 'ca_sha256', 'server_name', 'port'}
        if (info.get('schema') == 'h454-private-relay-v1' and
                set(info) == common | {'relay_ipv4'} and _private_ip(info['relay_ipv4'])):
            address = info['relay_ipv4']
        elif (target == 'yfc-vps' and info.get('schema') == 'h454-private-relay-unix-v1' and
              set(info) == common | {'relay_socket'} and info['relay_socket'] == UNIX_SOCKET):
            address = UNIX_ENDPOINT
        else:
            _deny()
        if (
            info['target'] != target or info['release_sha'] != release_sha or
            info['server_name'] != HOST or type(info['port']) is not int or
            info['port'] != PORT or
            type(info['ca_sha256']) is not str or
            SHA64.fullmatch(info['ca_sha256']) is None or
            json.dumps(info, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True).encode('ascii') != raw):
            _deny()
        ca = _read(root, CA, CA_MAX_BYTES)
        if hashlib.sha256(ca).hexdigest() != info['ca_sha256'] or not (
                ca.startswith(b'-----BEGIN CERTIFICATE-----') and
                ca.rstrip().endswith(b'-----END CERTIFICATE-----') and
                ca.count(b'-----BEGIN CERTIFICATE-----') == 1):
            _deny()
        # Verify trust can be loaded before the first credential is used.
        _context(ca)
        return PrivateRelay(target, release_sha, address, ca)
    except Exception:
        raise PrivateTLSDenied('h454_private_tls_denied') from None


def _context(ca: bytes) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations(cadata=ca.decode('ascii'))
    ctx.options |= ssl.OP_NO_COMPRESSION
    return ctx


def _raw_socket(config: PrivateRelay, timeout: float):
    if config.relay_ipv4 == UNIX_ENDPOINT:
        if config.target != 'yfc-vps':
            _deny()
        raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            raw.settimeout(timeout)
            raw.connect(UNIX_SOCKET)
            return raw
        except Exception:
            raw.close()
            raise
    return socket.create_connection((config.relay_ipv4, PORT), timeout=timeout)


def _connection(config: PrivateRelay, timeout: float):
    raw = _raw_socket(config, timeout)
    try:
        return _context(config.ca).wrap_socket(raw, server_hostname=HOST)
    except Exception:
        raw.close()
        raise


def current_bearer(config: PrivateRelay, *, target: str, device_id: str,
                   bearer: str, timeout: float = 8.0) -> bool:
    """Check authoritative status on the private TLS sidecar per READ call."""
    if (type(config) is not PrivateRelay or target != config.target or
        type(device_id) is not str or IDENTITY[target].fullmatch(device_id) is None or
        type(bearer) is not str or TOKEN.fullmatch(bearer) is None or
        type(timeout) not in (float, int) or not 1 <= timeout <= 12):
        return False
    try:
        with _connection(config, timeout) as secure:
            secure.settimeout(timeout)
            headers = (
                'GET /device/native-status HTTP/1.1\r\n'
                f'Host: {HOST}:{PORT}\r\n'
                f'Authorization: Bearer {bearer}\r\n'
                'Accept: application/json\r\n'
                'Cache-Control: no-store\r\n'
                'Connection: close\r\n\r\n'
            ).encode('ascii')
            secure.sendall(headers)
            resp = http.client.HTTPResponse(secure)
            resp.begin()
            if (resp.status != 200 or resp.getheader('Content-Type') != 'application/json'):
                return False
            if resp.getheader('Content-Length') is not None:
                size = int(resp.getheader('Content-Length'))
                if not 0 < size <= 512:
                    return False
            data = resp.read(513)
            if len(data) > 512:
                return False
        return parse_status(data, target=target, device_id=device_id)
    except Exception:
        return False


def private_revoked_provider(config: PrivateRelay, *, target: str,
                             device_id: str, bearer: str, base_url: str) -> Callable[[], bool]:
    if (type(config) is not PrivateRelay or target != config.target or
        base_url != PUBLIC or type(bearer) is not str or
        TOKEN.fullmatch(bearer) is None or
        type(device_id) is not str or IDENTITY[target].fullmatch(device_id) is None):
        _deny()
    return lambda: not current_bearer(config, target=target,
                                      device_id=device_id, bearer=bearer)


def private_websocket_connector(config: PrivateRelay, underlying: Callable) -> Callable:
    """Keep BRC public logical device URL, but connect only to the private TLS peer."""
    if type(config) is not PrivateRelay or not callable(underlying):
        _deny()

    def connect(url: str, **kwargs):
        allowed = {'additional_headers', 'open_timeout', 'close_timeout',
                   'compression', 'proxy', 'max_size', 'ping_interval', 'ping_timeout'}
        headers = kwargs.get('additional_headers')
        if (url != ENDPOINT or set(kwargs) != allowed or kwargs.get('proxy') is not None
            or kwargs.get('compression') is not None or type(headers) is not dict
            or set(headers) != {'Authorization', 'X-BRC-Protocol'} or
            headers.get('X-BRC-Protocol') != '1' or
            type(headers.get('Authorization')) is not str or
            not headers['Authorization'].startswith('Bearer brc_dev_') or
            TOKEN.fullmatch(headers['Authorization'][7:]) is None):
            _deny()
        raw = _raw_socket(config, 8)
        try:
            return underlying(
                WS_URI, sock=raw, ssl=_context(config.ca),
                server_hostname=HOST, **kwargs,
            )
        except TimeoutError:
            raw.close()
            raise TimeoutError('native_transport_timeout') from None
        except Exception:
            raw.close()
            raise PrivateTLSDenied('h454_private_tls_denied') from None

    return connect
