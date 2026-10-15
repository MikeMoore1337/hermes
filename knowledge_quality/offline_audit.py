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
        if type(item) is not dict or set(item) != {"id", "updated_on", "access", "origin"}:
            raise KnowledgeAuditError("source_schema_invalid")
        key = _ident(item["id"], SRC)
        updated = _date(item["updated_on"])
        if key in sources or updated > now or item["access"] not in ("allowed", "revoked") or item["origin"] != "synthetic_only":
            raise KnowledgeAuditError("source_invalid")
        sources[key] = {"updated": updated, "access": item["access"]}
    facts: dict[str, dict] = {}
    for item in _list(data["facts"], 100):
        if type(item) is not dict or set(item) != {"id", "topic", "predicate", "value", "checked_on", "source_ids", "links"}:
            raise KnowledgeAuditError("fact_schema_invalid")
        key = _ident(item["id"], FACT)
        topic = _ident(item["topic"], TOPIC)
        predicate = _ident(item["predicate"], TOPIC)
        value, checked = item["value"], _date(item["checked_on"])
        refs, links = _list(item["source_ids"], 8), _list(item["links"], 8)
        if key in facts or type(value) is not str or value not in VALUES or checked > now:
            raise KnowledgeAuditError("fact_invalid")
        if any(type(x) is not str or not SRC.fullmatch(x) for x in refs):
            raise KnowledgeAuditError("source_ref_invalid")
        if any(type(x) is not str or not FACT.fullmatch(x) for x in links):
            raise KnowledgeAuditError("link_ref_invalid")
        if len(refs) != len(set(refs)) or len(links) != len(set(links)):
            raise KnowledgeAuditError("duplicate_ref")
        facts[key] = {"topic": topic, "predicate": predicate, "value": value, "checked": checked, "sources": refs, "links": links}
    grouped: dict[tuple[str, str], set[str]] = {}
    for fact in facts.values():
        if fact["value"] != "UNKNOWN":
            grouped.setdefault((fact["topic"], fact["predicate"]), set()).add(fact["value"])
    output = []
    for key, fact in sorted(facts.items()):
        reasons: set[str] = set()
        if not fact["sources"] or fact["value"] == "UNKNOWN":
            reasons.add("INSUFFICIENT_PROVENANCE")
        if (now - fact["checked"]).days > stale_days:
            reasons.add("STALE_FACT")
        for ref in fact["sources"]:
            src = sources.get(ref)
            if src is None:
                reasons.add("MISSING_SOURCE")
            elif src["access"] == "revoked":
                reasons.add("REVOKED_SOURCE")
            elif (now - src["updated"]).days > stale_days:
                reasons.add("STALE_SOURCE")
        if any(ref not in facts for ref in fact["links"]):
            reasons.add("ORPHAN_LINK")
        if len(grouped.get((fact["topic"], fact["predicate"]), set())) > 1:
            reasons.add("CONTRADICTION")
        status = "HOLD" if reasons - {"INSUFFICIENT_PROVENANCE"} else "UNKNOWN" if reasons else "READY"
        output.append({"fact_id": key, "status": status, "reason_codes": sorted(reasons)})
    return {"schema": RESULT_SCHEMA, "mode": "SYNTHETIC_ONLY", "integration_verified": False,
            "vault_accessed": False, "model_called": False, "facts": output,
            "summary": {s: sum(x["status"] == s for x in output) for s in ("READY", "UNKNOWN", "HOLD")}}

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
        result = audit_fixture(json.loads(data), as_of=args.as_of)
    except (KnowledgeAuditError, ValueError, TypeError):
        print(json.dumps({"status": "REJECTED", "reason": "invalid_fixture"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
