"""Offline paired-device release rebinding, without filesystem or service changes."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from device_fabric.native_brc_enrollment import IDENTITY, TOKEN
from device_fabric.native_install_preview import parse_candidate
from scripts.h454_native_linux_runtime import _parse_config


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
