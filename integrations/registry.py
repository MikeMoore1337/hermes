"""H-09: offline, strict integration admission registry. Never activates integrations."""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

REGISTRY = Path(__file__).with_name("candidates.json")
SCHEMA = "hermes-integration-registry-v1"
ENTRY_FIELDS = frozenset({
    "id", "kind", "decision", "purpose", "documentation", "license",
    "verified_on", "verified_status", "billing", "card_requirement",
    "credentials", "data_scope", "side_effect", "hosts", "owner_approved",
    "permissions", "reasons", "issue",
})
ENTRY_ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
HOST = re.compile(r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]\Z")
PERMISSION = re.compile(r"[A-Za-z][A-Za-z0-9:_-]{0,63}\Z")
REASON = re.compile(r"[a-z][a-z0-9_]{2,70}\Z")
CREDENTIAL_MODES = frozenset({"none", "scoped_file", "developer_contact",
                              "separate_future_auth", "unscoped_pool"})
BILLING_MODES = frozenset({"zero_guaranteed", "free_plan_owner_attested",
                           "unknown", "uncontrolled"})
SIDE_EFFECTS = frozenset({"none", "read_only", "owner_notification",
                          "untrusted_execution"})
SCOPES = frozenset({"none", "public_metadata", "private_repo_metadata",
                    "sanitized_only", "private_vault", "private_owner_only",
                    "unknown"})

# Admission to GO is a CODE REVIEWED allowlist, not a boolean in user-editable JSON.
# Even a forged owner_approved=true cannot grant a new connector runtime authority.
APPROVED_GO_CONTRACTS = {
    "local-evidence-parser": (
        "local", (), "none", "none", (), "none",
    ),
    "github-yfc-public-actions": (
        "api", ("api.github.com",), "read_only", "public_metadata", (), "none",
    ),
    "telegram-ops-watch-owner": (
        "api", ("api.telegram.org",), "owner_notification", "private_owner_only",
        ("sendMessage:verified_private_chat",), "scoped_file",
    ),
}


class RegistryError(ValueError):
    """Static error codes only; never print untrusted field values."""


def _string(value: object, field: str, maximum: int = 180) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise RegistryError("invalid_" + field)
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise RegistryError("invalid_" + field)
    return value


def _url(value: object, field: str) -> str:
    url = _string(value, field, 300)
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.netloc or not parsed.hostname
            or parsed.username or parsed.password or parsed.port
            or "\\" in url or parsed.hostname.endswith(".")):
        raise RegistryError("invalid_" + field)
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise RegistryError("invalid_" + field)
    if parsed.hostname in ("localhost",) or "." not in parsed.hostname:
        raise RegistryError("invalid_" + field)
    return url


def _host(value: object) -> str:
    name = _string(value, "host", 253)
    if (not HOST.fullmatch(name) or ".." in name or name.lower() != name
            or name.startswith("-") or name.endswith("-")):
        raise RegistryError("invalid_host")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise RegistryError("invalid_host")
    if name == "localhost" or "." not in name:
        raise RegistryError("invalid_host")
    return name


def _list_of(value: object, label: str, limit: int) -> list[str]:
    if (type(value) is not list or len(value) > limit
            or any(type(item) is not str for item in value)):
        raise RegistryError("invalid_" + label)
    return value


def evaluate(item: dict[str, object]) -> str:
    """Policy decision derived from bounded evidence, never user text."""
    if (item["billing"] == "uncontrolled"
            or item["credentials"] == "unscoped_pool"
            or item["side_effect"] == "untrusted_execution"):
        return "REJECT"
    if (item["billing"] != "zero_guaranteed"
            or item["card_requirement"] != "none"
            or item["verified_status"] != "checked"
            or item["owner_approved"] is not True):
        return "DEFER"
    if item["side_effect"] == "owner_notification":
        if (item["data_scope"] != "private_owner_only"
                or item["credentials"] != "scoped_file"
                or item["permissions"] != ["sendMessage:verified_private_chat"]):
            return "DEFER"
    elif item["side_effect"] not in ("none", "read_only"):
        return "DEFER"
    if item["data_scope"] in ("private_vault", "unknown"):
        return "DEFER"
    if item["credentials"] in ("developer_contact", "separate_future_auth"):
        return "DEFER"
    if item["kind"] != "local" and not item["hosts"]:
        return "DEFER"
    contract = (
        item["kind"], tuple(item["hosts"]), item["side_effect"],
        item["data_scope"], tuple(item["permissions"]), item["credentials"],
    )
    if APPROVED_GO_CONTRACTS.get(item["id"]) != contract:
        return "DEFER"
    return "GO"


def validate(data: object) -> list[dict[str, object]]:
    if type(data) is not dict or set(data) != {"schema", "candidates"}:
        raise RegistryError("invalid_registry_shape")
    if data["schema"] != SCHEMA:
        raise RegistryError("invalid_registry_schema")
    entries = data["candidates"]
    if type(entries) is not list or not 1 <= len(entries) <= 50:
        raise RegistryError("invalid_registry_size")
    ids = set()
    checked = []
    for item in entries:
        if type(item) is not dict or set(item) != ENTRY_FIELDS:
            raise RegistryError("invalid_candidate_shape")
        name = _string(item["id"], "candidate_id", 70)
        if not ENTRY_ID.fullmatch(name) or name in ids:
            raise RegistryError("invalid_or_duplicate_candidate_id")
        ids.add(name)
        _string(item["purpose"], "purpose", 220)
        _url(item["documentation"], "documentation")
        _url(item["issue"], "issue")
        _string(item["license"], "license", 55)
        if item["kind"] not in ("local", "api", "mcp", "cli"):
            raise RegistryError("invalid_kind")
        if item["decision"] not in ("GO", "DEFER", "REJECT"):
            raise RegistryError("invalid_decision")
        try:
            if (date.fromisoformat(_string(item["verified_on"], "verification_date"))
                    > date.today()):
                raise ValueError
        except ValueError:
            raise RegistryError("invalid_verification_date") from None
        if item["verified_status"] not in ("checked", "pending", "blocked"):
            raise RegistryError("invalid_verified_status")
        if item["billing"] not in BILLING_MODES:
            raise RegistryError("invalid_billing")
        if item["card_requirement"] not in ("none", "required", "unknown"):
            raise RegistryError("invalid_card")
        if item["credentials"] not in CREDENTIAL_MODES:
            raise RegistryError("invalid_credentials")
        if item["data_scope"] not in SCOPES:
            raise RegistryError("invalid_data_scope")
        if item["side_effect"] not in SIDE_EFFECTS:
            raise RegistryError("invalid_side_effect")
        if type(item["owner_approved"]) is not bool:
            raise RegistryError("invalid_owner_approval")
        hosts = _list_of(item["hosts"], "hosts", 5)
        if len(set(hosts)) != len(hosts):
            raise RegistryError("duplicate_hosts")
        for host in hosts:
            _host(host)
        permissions = _list_of(item["permissions"], "permissions", 6)
        if len(set(permissions)) != len(permissions):
            raise RegistryError("duplicate_permissions")
        for scope in permissions:
            if not PERMISSION.fullmatch(scope):
                raise RegistryError("invalid_permission")
        reasons = _list_of(item["reasons"], "reasons", 8)
        if len(reasons) == 0 or len(set(reasons)) != len(reasons):
            raise RegistryError("invalid_reasons")
        for reason in reasons:
            if not REASON.fullmatch(reason):
                raise RegistryError("invalid_reason")
        if item["kind"] == "local" and (hosts or item["credentials"] != "none"):
            raise RegistryError("local_network_or_credentials_denied")
        if item["decision"] != evaluate(item):
            raise RegistryError("declared_decision_conflicts_with_policy")
        checked.append(item)
    return checked


def load(path: Path = REGISTRY) -> list[dict[str, object]]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise RegistryError("unsafe_registry_file")
    try:
        data = json.loads(path.read_text(encoding="utf-8"),
                          object_pairs_hook=_reject_duplicates)
    except (OSError, UnicodeError, ValueError):
        raise RegistryError("invalid_registry_json") from None
    return validate(data)


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out = {}
    for name, value in pairs:
        if name in out:
            raise RegistryError("duplicate_json_key")
        out[name] = value
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Hermes integration candidates offline")
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args(argv)
    try:
        checked = load()
    except RegistryError as error:
        print(json.dumps({"status": "INVALID", "reason": str(error)}))
        return 2
    print(json.dumps({
        "status": "VALID", "total": len(checked),
        "go": sum(x["decision"] == "GO" for x in checked),
        "defer": sum(x["decision"] == "DEFER" for x in checked),
        "reject": sum(x["decision"] == "REJECT" for x in checked),
        "no_install_or_network": True,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
