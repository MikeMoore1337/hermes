"""Offline paired-device release rebinding, without filesystem or service changes."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from device_fabric.native_brc_enrollment import IDENTITY, TOKEN
from device_fabric.native_install_preview import parse_candidate
from device_fabric import native_private_tls as private_tls
from scripts.h454_native_linux_runtime import _parse_config, _unique
from scripts.h454_native_linux_active_unit import render_active_unit
from scripts.h454_native_linux_unit_candidate import render_preflight_unit
from scripts.h454_native_readonly_bundle import verify_bytes


class RebindDenied(ValueError):
    """Do not include credential, device identity or original paths."""


@dataclass(frozen=True, repr=False, slots=True)
class Rebound:
    manifest: bytes
    device: bytes

    def __repr__(self) -> str:
        return "Rebound([REDACTED])"


@dataclass(frozen=True, repr=False, slots=True)
class Transition:
    manifest: bytes
    device: bytes
    trust: bytes
    active_unit: bytes
    preflight_unit: bytes

    def __repr__(self) -> str:
        return "Transition([REDACTED])"


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


def build_transition(manifest: bytes, device: bytes, trust: bytes, ca: bytes,
                     bundle: bytes, receipt: bytes, *, old_release: str,
                     new_release: str, expected_bundle_sha256: str) -> Transition:
    """Build a validated paired transition in memory; never install or start it."""
    try:
        verified = verify_bytes(bundle, receipt, target="hermes-vps", release_sha=new_release)
        if verified["bundle_sha256"] != expected_bundle_sha256:
            raise RebindDenied()
        paired = rebind(manifest, device, old_release=old_release,
                        new_release=new_release, bundle_sha256=expected_bundle_sha256)
        new_trust = rebind_trust(trust, ca, old_release=old_release,
                                 new_release=new_release)
        relay = json.loads(new_trust)["relay_ipv4"]
        digest = hashlib.sha256(paired.manifest).hexdigest()
        common = {"target": "hermes-vps", "release_sha": new_release,
                  "manifest_sha256": digest}
        active = render_active_unit(paired.manifest, **common, relay_ipv4=relay,
                                    dns_ipv4="", private_relay=True).encode("ascii")
        preflight = render_preflight_unit(paired.manifest, **common).encode("ascii")
        return Transition(paired.manifest, paired.device, new_trust, active, preflight)
    except Exception:
        raise RebindDenied("native_paired_rebind_denied") from None


def replace_frozen_state(directory: Path, name: str, *, expected: bytes,
                         replacement: bytes, trusted_uid: int) -> None:
    """Replace one checked state file while its private directory is frozen.

    The host operator must stop the service, exclude other service-UID
    processes, verify parent directories, freeze this directory under root,
    and journal recovery first.
    A staged file is retained on failure for explicit reconciliation.
    """
    dfd = fd = None
    try:
        if (name not in ("manifest.json", "device.json") or not directory.is_absolute()
            or type(expected) is not bytes or not 0 < len(expected) <= 8192
            or type(replacement) is not bytes or not 0 < len(replacement) <= 8192
            or type(trusted_uid) is not int or trusted_uid != os.geteuid()):
            raise RebindDenied()
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent = os.fstat(dfd)
        if parent.st_uid != trusted_uid or stat.S_IMODE(parent.st_mode) != 0o700:
            raise RebindDenied()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        before = os.fstat(fd)
        data = os.read(fd, 8193)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600 or data != expected):
            raise RebindDenied()
        os.close(fd)
        fd = None
        staged = ".h454-paired-" + name + ".pending"
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=dfd)
        os.fchown(fd, before.st_uid, before.st_gid)
        os.fchmod(fd, 0o600)
        view = memoryview(replacement)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise RebindDenied()
            view = view[n:]
        os.fsync(fd)
        os.close(fd)
        fd = None
        current = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if (current.st_dev, current.st_ino, current.st_size, current.st_ctime_ns) != (
            before.st_dev, before.st_ino, before.st_size, before.st_ctime_ns
        ):
            raise RebindDenied()
        os.replace(staged, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        os.fsync(dfd)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        after = os.fstat(fd)
        if (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
            or stat.S_IMODE(after.st_mode) != 0o600
            or (after.st_uid, after.st_gid) != (before.st_uid, before.st_gid)
            or os.read(fd, 8193) != replacement):
            raise RebindDenied()
    except Exception:
        raise RebindDenied("native_paired_rebind_denied") from None
    finally:
        if fd is not None:
            os.close(fd)
        if dfd is not None:
            os.close(dfd)
