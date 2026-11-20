"""Offline paired-device release rebinding, without filesystem or service changes."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from device_fabric.native_brc_enrollment import IDENTITY, TOKEN
from device_fabric.native_install_preview import parse_candidate
from device_fabric import native_private_tls as private_tls
from scripts.h454_native_linux_runtime import _parse_config, _unique


class RebindDenied(ValueError):
    """Do not include credential, device identity or original paths."""


@dataclass(frozen=True, repr=False, slots=True)
class Rebound:
    manifest: bytes
    device: bytes

    def __repr__(self) -> str:
        return "Rebound([REDACTED])"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def rebind(manifest: bytes, device: bytes, *, old_release: str,
           new_release: str, bundle_sha256: str) -> Rebound:
    """Rebind only release and manifest digest, preserving identity and bearer."""
    try:
        if (type(old_release) is not str or type(new_release) is not str
            or re.fullmatch(r"[0-9a-f]{40}", old_release) is None
            or re.fullmatch(r"[0-9a-f]{40}", new_release) is None
            or old_release == new_release or "0" * 40 in (old_release, new_release)
            or type(bundle_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", bundle_sha256) is None
            or bundle_sha256 == "0" * 64):
            raise RebindDenied()
        old = parse_candidate(manifest, expected_release=old_release,
                              expected_target="hermes-vps")
        original = _parse_config(device, old)
        if (IDENTITY["hermes-vps"].fullmatch(original.device_id) is None
            or TOKEN.fullmatch(original.token) is None):
            raise RebindDenied()
        manifest_data = json.loads(manifest)
        manifest_data["release_sha"] = new_release
        manifest_data["artifact_sha256"] = bundle_sha256
        new_manifest = _canonical(manifest_data)
        new = parse_candidate(new_manifest, expected_release=new_release,
                              expected_target="hermes-vps")
        if new.roots != old.roots or new.service_identity != old.service_identity:
            raise RebindDenied()
        device_data = json.loads(device)
        device_data["release_sha"] = new_release
        device_data["manifest_sha256"] = hashlib.sha256(new_manifest).hexdigest()
        new_device = _canonical(device_data)
        updated = _parse_config(new_device, new)
        if updated != original:
            raise RebindDenied()
        return Rebound(new_manifest, new_device)
    except Exception:
        raise RebindDenied("native_paired_rebind_denied") from None


def rebind_trust(raw: bytes, ca: bytes, *, old_release: str, new_release: str) -> bytes:
    """Rebind validated private TLS trust without changing the relay or CA."""
    try:
        if (type(raw) is not bytes or not 0 < len(raw) <= 2048
            or type(ca) is not bytes or not 0 < len(ca) <= private_tls.CA_MAX_BYTES
            or type(old_release) is not str or type(new_release) is not str
            or re.fullmatch(r"[0-9a-f]{40}", old_release) is None
            or re.fullmatch(r"[0-9a-f]{40}", new_release) is None
            or old_release == new_release or "0" * 40 in (old_release, new_release)):
            raise RebindDenied()
        info = json.loads(raw.decode("ascii"), object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if (type(info) is not dict or _canonical(info) != raw or set(info) != {
            "schema", "target", "release_sha", "relay_ipv4", "ca_sha256",
            "server_name", "port",
        } or info["schema"] != "h454-private-relay-v1"
            or info["target"] != "hermes-vps" or info["release_sha"] != old_release
            or info["server_name"] != private_tls.HOST
            or type(info["port"]) is not int or info["port"] != private_tls.PORT
            or not private_tls._private_ip(info["relay_ipv4"])
            or info["ca_sha256"] != hashlib.sha256(ca).hexdigest()
            or not ca.startswith(b"-----BEGIN CERTIFICATE-----")
            or not ca.rstrip().endswith(b"-----END CERTIFICATE-----")
            or ca.count(b"-----BEGIN CERTIFICATE-----") != 1):
            raise RebindDenied()
        private_tls._context(ca)
        info["release_sha"] = new_release
        return _canonical(info)
    except Exception:
        raise RebindDenied("native_paired_rebind_denied") from None


def recover_device(device: bytes, old_manifest: bytes, new_manifest: bytes, *,
                   old_release: str, new_release: str) -> bytes:
    """Recover an old device config from either complete release-bound version.

    The caller must authenticate both manifests and the current device
    fingerprint, and protect the returned bearer. This never reads or writes disk.
    """
    try:
        old = parse_candidate(old_manifest, expected_release=old_release,
                              expected_target="hermes-vps")
        new = parse_candidate(new_manifest, expected_release=new_release,
                              expected_target="hermes-vps")
        old_data, new_data = json.loads(old_manifest), json.loads(new_manifest)
        expected_new = dict(old_data, release_sha=new_release,
                            artifact_sha256=new_data["artifact_sha256"])
        if (_canonical(expected_new) != new_manifest or old_release == new_release
            or old.roots != new.roots or old.service_identity != new.service_identity):
            raise RebindDenied()
        try:
            current = _parse_config(device, old)
        except Exception:
            restored = rebind(new_manifest, device, old_release=new_release,
                              new_release=old_release,
                              bundle_sha256=old_data["artifact_sha256"])
            if restored.manifest != old_manifest:
                raise RebindDenied()
            return restored.device
        if (IDENTITY["hermes-vps"].fullmatch(current.device_id) is None
            or TOKEN.fullmatch(current.token) is None):
            raise RebindDenied()
        return device
    except Exception:
        raise RebindDenied("native_paired_rebind_denied") from None
