"""Build pinned Windows tunnel settings in memory from the guarded launcher."""
import hashlib
import ipaddress
import json
import re

from scripts.h15_remote_commander_candidate_audit import AuditError
from scripts.h454_windows_launcher_guard import patch_launcher_bytes


def build(original: bytes, guarded: bytes, *, original_sha256: str, guarded_sha256: str,
          ca_sha256: str, identity_sha256: str, node_sha256: str, public_key_sha256: str) -> bytes:
    pins = (guarded_sha256, ca_sha256, identity_sha256, node_sha256, public_key_sha256)
    if (not isinstance(guarded, bytes) or any(not isinstance(pin, str) or not re.fullmatch(r'[A-Fa-f0-9]{64}', pin) for pin in pins) or
            hashlib.sha256(guarded).hexdigest() != guarded_sha256.lower() or
            patch_launcher_bytes(original, original_sha256) != guarded):
        raise AuditError('unreviewed_wss_config_pins')
    try:
        text = original.decode('utf-8-sig')
    except UnicodeDecodeError as exc:
        raise AuditError('unreviewed_wss_config_source') from exc

    def one(pattern: str) -> str:
        matches = re.findall(pattern, text, flags=re.MULTILINE)
        if len(matches) != 1:
            raise AuditError('unreviewed_wss_config_source')
        return matches[0]

    host = one(r"^[ \t]*\$HOST_ADDR[ \t]*=[ \t]*'([^'\r\n]+)'[ \t]*\r?$")
    relay = one(r"^[ \t]*\$RELAY[ \t]*=[ \t]*'([^'\r\n]+)'[ \t]*\r?$")
    port = int(one(r'^[ \t]*\$SSH_PORT[ \t]*=[ \t]*([0-9]{1,5})[ \t]*\r?$'))
    target = one(r'^[ \t]*\$TUNNEL_TARGET[ \t]*=[ \t]*"([^"\r\n]+)"[ \t]*\r?$')
    if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host) or not 1 <= port <= 65535 or not relay.endswith(':3000'):
        raise AuditError('unreviewed_wss_config_source')
    relay_address = relay[:-5]
    try:
        address = ipaddress.IPv4Address(relay_address)
    except ipaddress.AddressValueError as exc:
        raise AuditError('unreviewed_wss_config_source') from exc
    private_ranges = (ipaddress.IPv4Network('10.0.0.0/8'), ipaddress.IPv4Network('172.16.0.0/12'),
                      ipaddress.IPv4Network('192.168.0.0/16'))
    if str(address) != relay_address or not any(address in network for network in private_ranges):
        raise AuditError('unreviewed_wss_config_source')
    target = target.replace('${HOST_ADDR}', host).replace('$HOST_ADDR', host)
    match = re.fullmatch(r'([a-z_][a-z0-9_-]{0,63})@([A-Za-z0-9.-]{1,253})', target)
    if not match or match.group(2) != host:
        raise AuditError('unreviewed_wss_config_source')
    settings = {'version': 1, 'sshHost': host, 'sshUser': match.group(1), 'sshPort': port,
                'relayAddress': relay_address, 'caSha256': ca_sha256.upper(), 'identitySha256': identity_sha256.upper(),
                'launcherSha256': guarded_sha256.upper(), 'nodeSha256': node_sha256.upper(),
                'publicKeySha256': public_key_sha256.upper()}
    return json.dumps(settings, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
