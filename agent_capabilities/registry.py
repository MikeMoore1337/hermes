"""H-495: conservative, offline agent capability advice.

This is development-time planning data, NOT resident agent permissions or an
execution router. H-09 integrations.registry remains the source of provider
admission decisions. No imports, network, subprocess or protected resource IO.
"""
from __future__ import annotations

import json
from pathlib import Path
import re

from integrations.registry import load as load_integration_registry

CATALOG = Path(__file__).with_name("catalog.json")
FIELDS = frozenset({
    "id", "agent", "integration_id", "action", "data_scope", "permissions",
    "source_revision", "availability", "cost_policy",
})
IDENTIFIER = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
ACTION = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
MAX_SIZE = 16_384
MAX_ENTRIES = 30


class CapabilityError(ValueError):
    """Failures use stable error codes, not untrusted source text."""


def _name(value: object, kind: str) -> str:
    if type(value) is not str or len(value) > 72 or not IDENTIFIER.fullmatch(value):
        raise CapabilityError("invalid_" + kind)
    return value


def validate_catalog(data: object) -> list[dict]:
    if type(data) is not dict or set(data) != {"schema_version", "capabilities"}:
        raise CapabilityError("invalid_catalog")
    if data["schema_version"] != 1 or type(data["capabilities"]) is not list:
        raise CapabilityError("invalid_schema")
    items = data["capabilities"]
    if not 1 <= len(items) <= MAX_ENTRIES:
        raise CapabilityError("invalid_size")
    result, seen = [], set()
    for item in items:
        if type(item) is not dict or set(item) != FIELDS:
            raise CapabilityError("invalid_capability_shape")
        ident = _name(item["id"], "capability_id")
        if ident in seen:
            raise CapabilityError("duplicate_capability_id")
        seen.add(ident)
        _name(item["agent"], "agent")
        _name(item["integration_id"], "integration")
        if type(item["action"]) is not str or not ACTION.fullmatch(item["action"]):
            raise CapabilityError("invalid_action")
        if item["data_scope"] not in (
            "none", "public_metadata", "private_repo_metadata", "sanitized_only", "private_owner_only"
        ):
            raise CapabilityError("invalid_data_scope")
        perms = item["permissions"]
        if (type(perms) is not list or len(perms) > 8 or len(set(map(str, perms))) != len(perms)
                or any(type(p) is not str or not re.fullmatch(r"[A-Za-z][A-Za-z0-9:_-]{0,63}", p)
                       for p in perms)):
            raise CapabilityError("invalid_permissions")
        revision = item["source_revision"]
        if type(revision) is not str or not (revision == "NOT_VERIFIED" or SHA.fullmatch(revision)):
            raise CapabilityError("invalid_source_revision")
        # No mutable JSON flag can declare running services or confer approval.
        if item["availability"] != "NOT_VERIFIED":
            raise CapabilityError("unverified_availability_required")
        if item["cost_policy"] != "zero_spend_only":
            raise CapabilityError("unknown_or_uncontrolled_cost")
        result.append(item)
    return result


def load_catalog(path: Path = CATALOG) -> list[dict]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SIZE:
        raise CapabilityError("unsafe_catalog")
    try:
        content = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates)
    except (OSError, ValueError, UnicodeError) as exc:
        raise CapabilityError("invalid_json") from None
    return validate_catalog(content)


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise CapabilityError("duplicate_json_key")
        obj[k] = v
    return obj


def preview(
    capability_id: str,
    presented_permissions: list[str],
    *,
    catalog: list[dict] | None = None,
    integrations: list[dict] | None = None,
) -> dict:
    """Evaluate a suggestion, never issue a token or execute a capability."""
    baseline = {
        "status": "REFUSED",
        "reason": "UNAVAILABLE",
        "runtime_activation": "NOT_AUTHORIZED",
        "action_executed": False,
        "client_or_service_activated": False,
        "side_effects": "NONE",
    }
    try:
        name = _name(capability_id, "capability_id")
        if (type(presented_permissions) is not list or len(presented_permissions) > 8
                or any(type(p) is not str for p in presented_permissions)):
            raise CapabilityError("invalid_presented_permissions")
        capabilities = load_catalog() if catalog is None else validate_catalog(
            {"schema_version": 1, "capabilities": catalog}
        )
        candidates = load_integration_registry() if integrations is None else integrations
    except (CapabilityError, ValueError, OSError):
        return {**baseline, "reason": "INVALID_INPUT"}
    item = next((x for x in capabilities if x["id"] == name), None)
    if item is None:
        return {**baseline, "reason": "CAPABILITY_UNKNOWN"}
    provider = next((x for x in candidates if x.get("id") == item["integration_id"]), None)
    if provider is None:
        return {**baseline, "reason": "INTEGRATION_UNKNOWN"}
    # Even a GO integration is NOT agent-specific runtime authorization.
    if (provider.get("decision") != "GO" or provider.get("billing") != "zero_guaranteed"
            or provider.get("verified_status") != "checked"
            or provider.get("owner_approved") is not True):
        return {**baseline, "reason": "INTEGRATION_NOT_ADMITTED"}
    if (item["data_scope"] != provider.get("data_scope")
            or sorted(item["permissions"]) != sorted(provider.get("permissions", []))):
        return {**baseline, "reason": "CONTRACT_MISMATCH"}
    if not set(item["permissions"]).issubset(presented_permissions):
        return {**baseline, "reason": "REQUIRED_PERMISSIONS_MISSING"}
    if provider.get("side_effect") not in ("none", "read_only"):
        return {**baseline, "reason": "SIDE_EFFECT_REQUIRES_SEPARATE_GATE"}
    return {
        **baseline,
        "status": "CANDIDATE_ONLY",
        "reason": "RUNTIME_NOT_VERIFIED",
        "capability_id": name,
        "agent": item["agent"],
        "integration_id": item["integration_id"],
        "availability": "NOT_VERIFIED",
        "source_revision": item["source_revision"],
        "permissions_evidence": "UNTRUSTED_DECLARATION_NOT_ENFORCEMENT",
    }
