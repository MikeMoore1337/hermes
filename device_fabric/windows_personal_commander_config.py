"""Owner-scoped configuration for a separate personal Windows Commander.

This module only prepares and parses an in-memory configuration. It does not
pair a device, install a process, read project files, or connect to a relay.
The process using it has the Windows owner's ordinary OS permissions.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import ntpath
import re
from typing import Callable

from device_fabric.native_brc_enrollment import TOKEN, Paired
from device_fabric.native_install_preview import WINDOWS_ROOTS
from device_fabric.windows_personal_project_limits import MAX_PROJECT_ROOTS
from device_fabric.windows_personal_commander_enrollment import DEVICE, TARGET
from device_fabric.windows_native_dpapi import (
    MAX_CIPHERTEXT, seal_personal_commander, unseal_personal_commander,
)
from device_fabric.windows_personal_session import SHA40, SHA64, SID
from device_fabric.windows_personal_yfc_psec import YFC_DEV

SCHEMA = "h454-windows-personal-commander-v1"
YFC_SCHEMA = "h454-windows-personal-commander-yfc-dev-v1"
PROJECTS_SCHEMA = "h454-windows-personal-commander-projects-v1"
MAX_CONFIG_BYTES = 8192
PERSONAL_ROOTS = {name: WINDOWS_ROOTS[name] for name in
                  ("hermes", "your-fitness-coach", "financial-horizon")}
YFC_ROOTS = {"yfc-dev": str(YFC_DEV)}
FIELDS = frozenset({"schema", "release_sha", "owner_sid", "ca_sha256",
                    "bundle_sha256", "device_id", "sealed_bearer_b64", "created_at"})


class PersonalCommanderDenied(ValueError):
    """Sanitized denial without paths, credentials or Windows error text."""


@dataclass(frozen=True, slots=True, repr=False)
class PersonalCommanderConfig:
    release_sha: str
    owner_sid: str
    ca_sha256: str
    bundle_sha256: str
    device_id: str
    sealed_bearer: bytes
    created_at: int
    profile: str
    roots: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return "PersonalCommanderConfig([REDACTED])"


def _encode(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PersonalCommanderDenied("personal_commander_denied")
        result[key] = value
    return result


def _validate_project_roots(roots: tuple[str, ...]) -> tuple[str, ...]:
    """Validate a bounded explicit scope under the owner's project directory."""
    if type(roots) is not tuple or not 2 <= len(roots) <= MAX_PROJECT_ROOTS or roots[0] != str(YFC_DEV):
        raise PersonalCommanderDenied("personal_commander_denied")
    parent = ntpath.normcase(r"D:\Pet-projects")
    normalized = []
    reserved = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.I)
    for value in roots:
        if (type(value) is not str or not 3 <= len(value) <= 2048 or ntpath.normpath(value) != value
            or not ntpath.isabs(value) or not ntpath.normcase(value).startswith(parent + "\\")
            or any(ord(char) < 32 or char in ':*?"<>|' for char in value[2:])):
            raise PersonalCommanderDenied("personal_commander_denied")
        parts = value[3:].split("\\")
        if any(not part or part in ('.', '..') or part.endswith((' ', '.')) or reserved.match(part)
               or 'second-brain' in part.casefold() or 'vault' in part.casefold()
               or part.casefold() in ('.ssh', '.aws', '.gnupg', '.kube', 'secrets', 'credentials')
               for part in parts):
            raise PersonalCommanderDenied("personal_commander_denied")
        current = ntpath.normcase(value)
        if any(current == other or current.startswith(other + "\\") or other.startswith(current + "\\")
               for other in normalized):
            raise PersonalCommanderDenied("personal_commander_denied")
        normalized.append(current)
    if normalized[1:] != sorted(normalized[1:]):
        raise PersonalCommanderDenied("personal_commander_denied")
    return roots


def roots_for(profile: str, *, roots: tuple[str, ...] = ()) -> tuple[str, ...]:
    if profile == "legacy":
        return tuple(PERSONAL_ROOTS.values())
    if profile == "yfc-dev":
        return tuple(YFC_ROOTS.values())
    if profile == "owner-projects":
        return _validate_project_roots(roots)
    raise PersonalCommanderDenied("personal_commander_denied")


def policy_digest(ca_sha256: str, bundle_sha256: str, *, profile: str = "legacy",
                  roots: tuple[str, ...] = ()) -> str:
    if (type(ca_sha256) is not str or SHA64.fullmatch(ca_sha256) is None
        or type(bundle_sha256) is not str or SHA64.fullmatch(bundle_sha256) is None
        or type(profile) is not str or profile not in ("legacy", "yfc-dev", "owner-projects")):
        raise PersonalCommanderDenied("personal_commander_denied")
    if profile == "owner-projects":
        schema, policy_roots = PROJECTS_SCHEMA, list(_validate_project_roots(roots))
    else:
        if roots:
            raise PersonalCommanderDenied("personal_commander_denied")
        schema, policy_roots = (SCHEMA, PERSONAL_ROOTS) if profile == "legacy" else (YFC_SCHEMA, YFC_ROOTS)
    return hashlib.sha256(_encode({"schema": schema, "access": "PERSONAL_WRITE_PROCESS",
        "roots": policy_roots, "ca_sha256": ca_sha256,
        "bundle_sha256": bundle_sha256})).hexdigest()


def prepare_config(paired: Paired, *, owner_sid: str, release_sha: str,
                   ca: bytes, bundle_sha256: str, now: int,
                   profile: str = "legacy",
                   roots: tuple[str, ...] = (),
                   seal: Callable[..., bytes] = seal_personal_commander) -> bytes:
    """Bind a newly paired personal bearer to owner, code, CA and roots."""
    try:
        if (type(paired) is not Paired or paired.target != TARGET
            or type(paired.device_id) is not str
            or DEVICE.fullmatch(paired.device_id) is None
            or type(paired.token) is not str or TOKEN.fullmatch(paired.token) is None
            or paired.ws_url not in ("wss://mcp.mikemoore.top/ws", "wss://hermes.mikemoore.top/ws")
            or type(owner_sid) is not str or len(owner_sid) > 184 or SID.fullmatch(owner_sid) is None
            or type(release_sha) is not str or SHA40.fullmatch(release_sha) is None
            or type(ca) is not bytes or not 0 < len(ca) <= 8192
            or not ca.startswith(b"-----BEGIN CERTIFICATE-----")
            or not ca.rstrip().endswith(b"-----END CERTIFICATE-----")
            or ca.count(b"-----BEGIN CERTIFICATE-----") != 1
            or type(now) is not int or not 0 < now < 2**53 or not callable(seal)):
            raise ValueError()
        ca_hash = hashlib.sha256(ca).hexdigest()
        digest = policy_digest(ca_hash, bundle_sha256, profile=profile, roots=roots)
        sealed = seal(paired.token, manifest_sha256=digest, device_id=paired.device_id)
        if type(sealed) is not bytes or not 32 <= len(sealed) <= MAX_CIPHERTEXT:
            raise ValueError()
        obj = {"schema": {"legacy": SCHEMA, "yfc-dev": YFC_SCHEMA, "owner-projects": PROJECTS_SCHEMA}[profile],
            "release_sha": release_sha, "owner_sid": owner_sid,
            "ca_sha256": ca_hash, "bundle_sha256": bundle_sha256, "device_id": paired.device_id,
            "sealed_bearer_b64": base64.b64encode(sealed).decode("ascii"), "created_at": now}
        if profile == "owner-projects":
            obj["roots"] = list(roots)
        raw = _encode(obj)
        parse_config(raw)
        return raw
    except Exception:
        raise PersonalCommanderDenied("personal_commander_denied") from None


def parse_config(raw: bytes) -> PersonalCommanderConfig:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_CONFIG_BYTES:
            raise ValueError()
        obj = json.loads(raw.decode("ascii"), object_pairs_hook=_unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if (type(obj) is not dict or obj.get("schema") not in (SCHEMA, YFC_SCHEMA, PROJECTS_SCHEMA)
            or set(obj) != (FIELDS | {"roots"} if obj["schema"] == PROJECTS_SCHEMA else FIELDS)
            or type(obj["release_sha"]) is not str or SHA40.fullmatch(obj["release_sha"]) is None
            or type(obj["owner_sid"]) is not str or len(obj["owner_sid"]) > 184
            or SID.fullmatch(obj["owner_sid"]) is None
            or type(obj["device_id"]) is not str
            or DEVICE.fullmatch(obj["device_id"]) is None
            or type(obj["sealed_bearer_b64"]) is not str
            or type(obj["created_at"]) is not int or not 0 < obj["created_at"] < 2**53
            or _encode(obj) != raw):
            raise ValueError()
        profile = {SCHEMA: "legacy", YFC_SCHEMA: "yfc-dev", PROJECTS_SCHEMA: "owner-projects"}[obj["schema"]]
        if profile == "owner-projects" and type(obj["roots"]) is not list:
            raise ValueError()
        roots = tuple(obj["roots"]) if profile == "owner-projects" else ()
        policy_digest(obj["ca_sha256"], obj["bundle_sha256"], profile=profile, roots=roots)
        sealed = base64.b64decode(obj["sealed_bearer_b64"], validate=True)
        if not 32 <= len(sealed) <= MAX_CIPHERTEXT:
            raise ValueError()
        return PersonalCommanderConfig(obj["release_sha"], obj["owner_sid"], obj["ca_sha256"],
            obj["bundle_sha256"], obj["device_id"], sealed, obj["created_at"], profile, roots)
    except Exception:
        raise PersonalCommanderDenied("personal_commander_denied") from None


def unseal(config: PersonalCommanderConfig, *, owner_sid: str, ca: bytes,
           bundle_sha256: str, decrypt: Callable[..., str] = unseal_personal_commander) -> str:
    """Refuse credential use if the actual owner, CA or installed bundle differ."""
    try:
        if (type(config) is not PersonalCommanderConfig
            or type(owner_sid) is not str or len(owner_sid) > 184 or SID.fullmatch(owner_sid) is None
            or owner_sid != config.owner_sid
            or type(config.release_sha) is not str or SHA40.fullmatch(config.release_sha) is None
            or type(config.device_id) is not str or DEVICE.fullmatch(config.device_id) is None
            or type(config.created_at) is not int or not 0 < config.created_at < 2**53
            or type(config.sealed_bearer) is not bytes
            or not 32 <= len(config.sealed_bearer) <= MAX_CIPHERTEXT
            or type(ca) is not bytes or hashlib.sha256(ca).hexdigest() != config.ca_sha256
            or type(bundle_sha256) is not str or bundle_sha256 != config.bundle_sha256
            or type(config.profile) is not str or config.profile not in ("legacy", "yfc-dev", "owner-projects")
            or not callable(decrypt)):
            raise ValueError()
        bearer = decrypt(config.sealed_bearer,
            manifest_sha256=policy_digest(config.ca_sha256, config.bundle_sha256, profile=config.profile, roots=config.roots),
            device_id=config.device_id)
        if type(bearer) is not str or TOKEN.fullmatch(bearer) is None:
            raise ValueError()
        return bearer
    except Exception:
        raise PersonalCommanderDenied("personal_commander_denied") from None


def add_project(raw: bytes, project: str, *, owner_sid: str, ca: bytes,
                bundle_sha256: str,
                decrypt: Callable[..., str] = unseal_personal_commander,
                seal: Callable[..., bytes] = seal_personal_commander) -> bytes:
    """Reseal an existing grant to include one explicit original project.

    This only prepares bytes. The caller must validate the actual directory,
    persist the result transactionally, restart and verify the live device.
    """
    try:
        current = parse_config(raw)
        if current.profile not in ("yfc-dev", "owner-projects") or type(project) is not str:
            raise ValueError()
        existing = roots_for(current.profile, roots=current.roots)
        if any(ntpath.normcase(project) == ntpath.normcase(root) for root in existing):
            unseal(current, owner_sid=owner_sid, ca=ca,
                   bundle_sha256=bundle_sha256, decrypt=decrypt)
            return raw
        roots = (existing[0], *sorted((*existing[1:], project), key=ntpath.normcase))
        _validate_project_roots(roots)
        bearer = unseal(current, owner_sid=owner_sid, ca=ca,
                        bundle_sha256=bundle_sha256, decrypt=decrypt)
        paired = Paired(TARGET, current.device_id, bearer, "wss://hermes.mikemoore.top/ws")
        updated = prepare_config(paired, owner_sid=owner_sid, release_sha=current.release_sha,
            ca=ca, bundle_sha256=bundle_sha256, now=current.created_at,
            profile="owner-projects", roots=roots, seal=seal)
        if unseal(parse_config(updated), owner_sid=owner_sid, ca=ca,
                  bundle_sha256=bundle_sha256, decrypt=decrypt) != bearer:
            raise ValueError()
        return updated
    except Exception:
        raise PersonalCommanderDenied("personal_commander_denied") from None
