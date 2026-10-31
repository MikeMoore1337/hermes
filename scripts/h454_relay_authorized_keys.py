"""Prepare a narrowly scoped SSH forwarding change; never write an SSH file."""
from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re


class ForwardAuthorizationError(ValueError):
    pass


def prepare(source: bytes, *, source_sha256: str, public_key: str, relay_ip: str) -> bytes:
    if (not isinstance(source, bytes) or len(source) > 1_048_576 or b"\x00" in source or
        not isinstance(source_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", source_sha256) or
        hashlib.sha256(source).hexdigest() != source_sha256 or not isinstance(public_key, str) or
        len(public_key) > 4096 or any(char in public_key for char in "\r\n\x00") or
        not isinstance(relay_ip, str) or len(relay_ip) > 15):
        raise ForwardAuthorizationError("unreviewed_authorized_keys")
    fields = public_key.split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519" or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", fields[1]):
        raise ForwardAuthorizationError("invalid_public_key")
    try:
        wire = base64.b64decode(fields[1], validate=True)
        address = ipaddress.IPv4Address(relay_ip)
    except (ValueError, binascii.Error) as exc:
        raise ForwardAuthorizationError("invalid_forward_pin") from exc
    if (len(wire) != 51 or wire[:19] != b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" or
        str(address) != relay_ip or not any(address in ipaddress.IPv4Network(net) for net in
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))):
        raise ForwardAuthorizationError("invalid_forward_pin")
    key = b"ssh-ed25519 " + fields[1].encode("ascii")
    key_pattern = rb"(?:^|[ \t])ssh-ed25519[ \t]+" + re.escape(fields[1].encode("ascii")) + rb"(?:[ \t\r\n]|$)"
    lines = source.splitlines(keepends=True)
    matching = [i for i, line in enumerate(lines) if not line.lstrip().startswith(b"#") and
                re.search(key_pattern, line)]
    if len(matching) != 1:
        raise ForwardAuthorizationError("authorized_key_identity")
    index = matching[0]
    old = b'command="/usr/sbin/nologin",restrict,port-forwarding,permitopen="' + relay_ip.encode("ascii") + b':3000"'
    line = lines[index]
    if not line.startswith(old + b" ") or not line[len(old):].lstrip().startswith(key):
        raise ForwardAuthorizationError("authorized_key_policy")
    new = old + b',permitopen="' + relay_ip.encode("ascii") + b':3001"'
    lines[index] = new + line[len(old):]
    return b"".join(lines)
