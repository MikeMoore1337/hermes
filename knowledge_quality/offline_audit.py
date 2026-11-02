"""Pure synthetic knowledge-quality checks. No Second Brain vault or API access."""
from __future__ import annotations
import argparse
import datetime as dt
import json
import re
import sys
from typing import Any

SCHEMA = "hermes-h11-synthetic-fixture-v1"
RESULT_SCHEMA = "hermes-h11-audit-v1"
SRC = re.compile(r"SRC-[a-z0-9]{1,24}")
FACT = re.compile(r"F-[a-z0-9]{1,24}")
TOPIC = re.compile(r"demo-[a-z0-9_-]{1,32}")
VALUES = {"YES", "NO", "UNKNOWN"}

class KnowledgeAuditError(ValueError):
    """Reject malformed input, rather than guessing facts."""

def _date(value: Any) -> dt.date:
    if type(value) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise KnowledgeAuditError("date_invalid")
    try:
        return dt.date.fromisoformat(value)
    except ValueError as exc:
        raise KnowledgeAuditError("date_invalid") from exc

def _ident(value: Any, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        raise KnowledgeAuditError("identifier_invalid")
    return value

def _list(value: Any, size: int) -> list:
    if type(value) is not list or len(value) > size:
        raise KnowledgeAuditError("list_invalid")
    return value

def audit_fixture(data: Any, *, as_of: str, stale_days: int = 30) -> dict[str, Any]:
    """Classify synthetic facts; output contains only fixture IDs and reason codes."""
    now = _date(as_of)
    if type(stale_days) is not int or not 1 <= stale_days <= 365:
        raise KnowledgeAuditError("policy_invalid")
    if type(data) is not dict or set(data) != {"schema", "sources", "facts"} or data["schema"] != SCHEMA:
        raise KnowledgeAuditError("fixture_schema_invalid")
    sources: dict[str, dict] = {}
    for item in _list(data["sources"], 80):
        required = {"id", "updated_on", "access", "origin"}
        if type(item) is not dict or not required <= set(item) or set(item) - (required | {"expires_on"}):
            raise KnowledgeAuditError("source_schema_invalid")
        key = _ident(item["id"], SRC)
        updated = _date(item["updated_on"])
        if key in sources or updated > now or item["access"] not in ("allowed", "revoked") or item["origin"] != "synthetic_only":
            raise KnowledgeAuditError("source_invalid")
        expires = _date(item["expires_on"]) if "expires_on" in item else None
        sources[key] = {"updated": updated, "access": item["access"], "expires": expires}
    facts: dict[str, dict] = {}
    for item in _list(data["facts"], 100):
        required = {"id", "topic", "predicate", "value", "checked_on", "source_ids", "links"}
        if type(item) is not dict or not required <= set(item) or set(item) - (required | {"valid_from", "expires_on"}):
            raise KnowledgeAuditError("fact_schema_invalid")
        key = _ident(item["id"], FACT)
        topic = _ident(item["topic"], TOPIC)
        predicate = _ident(item["predicate"], TOPIC)
        value, checked = item["value"], _date(item["checked_on"])
        refs, links = _list(item["source_ids"], 8), _list(item["links"], 8)
        valid_from = _date(item["valid_from"]) if "valid_from" in item else None
        expires = _date(item["expires_on"]) if "expires_on" in item else None
        if valid_from is not None and expires is not None and valid_from > expires:
            raise KnowledgeAuditError("temporal_interval_invalid")
        if key in facts or type(value) is not str or value not in VALUES or checked > now:
            raise KnowledgeAuditError("fact_invalid")
        if any(type(x) is not str or not SRC.fullmatch(x) for x in refs):
            raise KnowledgeAuditError("source_ref_invalid")
        if any(type(x) is not str or not FACT.fullmatch(x) for x in links):
            raise KnowledgeAuditError("link_ref_invalid")
        if len(refs) != len(set(refs)) or len(links) != len(set(links)):
            raise KnowledgeAuditError("duplicate_ref")
        facts[key] = {"topic": topic, "predicate": predicate, "value": value, "checked": checked,
                      "sources": refs, "links": links, "valid_from": valid_from, "expires": expires}
    # Formal YES/NO conflicts require overlapping stated validity windows.
    # Missing bounds are treated as unbounded, never guessed from checked_on.
    grouped: dict[tuple[str, str], list[tuple[str, dict]]] = {}
    for key, fact in facts.items():
        if fact["value"] != "UNKNOWN":
            grouped.setdefault((fact["topic"], fact["predicate"]), []).append((key, fact))
    conflicting: set[str] = set()
    for group in grouped.values():
        for index, (left_id, left) in enumerate(group):
            for right_id, right in group[index + 1:]:
                if left["value"] == right["value"]:
                    continue
                first = max(left["valid_from"] or dt.date.min, right["valid_from"] or dt.date.min)
                last = min(left["expires"] or dt.date.max, right["expires"] or dt.date.max)
                if first <= last:
                    conflicting.update((left_id, right_id))
    output = []
    for key, fact in sorted(facts.items()):
        reasons: set[str] = set()
        if not fact["sources"] or fact["value"] == "UNKNOWN":
            reasons.add("INSUFFICIENT_PROVENANCE")
        if (now - fact["checked"]).days > stale_days:
            reasons.add("STALE_FACT")
        if fact["valid_from"] is not None and now < fact["valid_from"]:
            reasons.add("NOT_YET_EFFECTIVE")
        if fact["expires"] is not None and now > fact["expires"]:
            reasons.add("EXPIRED_FACT")
        for ref in fact["sources"]:
            src = sources.get(ref)
            if src is None:
                reasons.add("MISSING_SOURCE")
            else:
                if src["access"] == "revoked":
                    reasons.add("REVOKED_SOURCE")
                elif (now - src["updated"]).days > stale_days:
                    reasons.add("STALE_SOURCE")
                if src["expires"] is not None and now > src["expires"]:
                    reasons.add("EXPIRED_SOURCE")
        if any(ref not in facts for ref in fact["links"]):
            reasons.add("ORPHAN_LINK")
        if key in conflicting:
            reasons.add("CONTRADICTION")
        status = "HOLD" if reasons - {"INSUFFICIENT_PROVENANCE"} else "UNKNOWN" if reasons else "READY"
        output.append({"fact_id": key, "status": status, "reason_codes": sorted(reasons)})
    # A present link is not evidence that its target is usable. Conservatively
    # propagate the target's synthetic quality status through linked facts.
    # No raw values or source content enter the output.
    by_id = {row["fact_id"]: row for row in output}
    linked_codes = {"LINKED_FACT_HOLD", "LINKED_FACT_UNKNOWN"}
    for _ in range(len(output)):
        changed = False
        for row in output:
            reasons = set(row["reason_codes"]) - linked_codes
            linked_statuses = {
                by_id[target]["status"]
                for target in facts[row["fact_id"]]["links"]
                if target in by_id
            }
            if "HOLD" in linked_statuses:
                reasons.add("LINKED_FACT_HOLD")
            elif "UNKNOWN" in linked_statuses:
                reasons.add("LINKED_FACT_UNKNOWN")
            status = "HOLD" if reasons - {"INSUFFICIENT_PROVENANCE", "LINKED_FACT_UNKNOWN"} else "UNKNOWN" if reasons else "READY"
            if status != row["status"] or sorted(reasons) != row["reason_codes"]:
                row["status"] = status
                row["reason_codes"] = sorted(reasons)
                changed = True
        if not changed:
            break
    return {"schema": RESULT_SCHEMA, "mode": "SYNTHETIC_ONLY", "integration_verified": False,
            "vault_accessed": False, "model_called": False, "facts": output,
            "summary": {s: sum(x["status"] == s for x in output) for s in ("READY", "UNKNOWN", "HOLD")}}

def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys, including shadowed private fields."""
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise KnowledgeAuditError("duplicate_json_key")
        value[key] = item
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="H-11 offline synthetic-only audit")
    parser.add_argument("--as-of", required=True)
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        data = sys.stdin.buffer.read(16385)
        if len(data) > 16384:
            raise KnowledgeAuditError("input_too_large")
        result = audit_fixture(json.loads(data, object_pairs_hook=_strict_object), as_of=args.as_of)
    except (KnowledgeAuditError, ValueError, TypeError):
        print(json.dumps({"status": "REJECTED", "reason": "invalid_fixture"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
