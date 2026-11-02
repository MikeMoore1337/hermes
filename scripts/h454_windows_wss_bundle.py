"""Prepare the pinned supervisor files in memory; never install them."""
import hashlib
import re

from scripts.h15_remote_commander_candidate_audit import AuditError
from scripts.h454_windows_wss_config import build as build_config
from scripts.h454_windows_wss_tunnel import build as build_supervisor


def _pinned(value: bytes, digest: str, limit: int) -> bool:
    return (isinstance(value, bytes) and 0 < len(value) <= limit and isinstance(digest, str) and
            re.fullmatch(r'[A-Fa-f0-9]{64}', digest) is not None and hashlib.sha256(value).hexdigest() == digest.lower())


def build(original: bytes, guarded: bytes, identity: bytes, module: bytes, public_key: bytes, ca: bytes, *,
          original_sha256: str, guarded_sha256: str, identity_sha256: str, public_key_sha256: str,
          ca_sha256: str, node_sha256: str) -> dict[str, bytes]:
    if (not _pinned(identity, identity_sha256, 65536) or not _pinned(public_key, public_key_sha256, 4096) or
            not _pinned(ca, ca_sha256, 65536) or not isinstance(module, bytes) or not 0 < len(module) <= 16000 or
            not re.fullmatch(rb'ssh-ed25519 [A-Za-z0-9+/]{68} hermes-h454-wss\n', public_key) or
            not re.fullmatch(rb'-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE-----\r?\n?', ca)):
        raise AuditError('unreviewed_wss_bundle_input')
    module_pins = re.findall(rb"(?m)^\$script:h454ModuleHash = '([A-F0-9]{64})'\r?$", identity)
    if len(module_pins) != 1 or hashlib.sha256(module).hexdigest().upper().encode() != module_pins[0]:
        raise AuditError('unreviewed_wss_bundle_module')
    config = build_config(original, guarded, original_sha256=original_sha256, guarded_sha256=guarded_sha256,
                          identity_sha256=identity_sha256, public_key_sha256=public_key_sha256,
                          ca_sha256=ca_sha256, node_sha256=node_sha256)
    supervisor = build_supervisor()
    if len(supervisor) > 65536 or len(config) > 8192:
        raise AuditError('unreviewed_wss_bundle_size')
    return {'h454-wss-identity.ps1': identity, 'h454_windows_wss_identity.mjs': module,
            'wss-relay-ca.pem': ca, 'h454-wss-tunnel.ps1': supervisor,
            'h454-wss-tunnel-config.json': config}
