"""H-480 pinned negative fixtures for the existing H-26 offline test lane."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re

from .call_contract import SyntheticSession, canonical, digest, fixture

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "tool-calls-v1.json"


def load_cases():
    data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    if (type(data) is not dict or set(data) != {"schema_version", "dataset", "cases"}
            or data["schema_version"] != 1 or
            data["dataset"] != "h480-tool-calling-offline-negative-v1" or
            type(data["cases"]) is not list or len(data["cases"]) != 18):
        raise ValueError("fixture_set_invalid")
    ids = set()
    for case in data["cases"]:
        if (type(case) is not dict or set(case) != {"id", "changes", "expected_reason"}
                or type(case["id"]) is not str or
                not re.fullmatch(r"fc-[0-9]{2}-[a-z0-9-]+", case["id"])
                or case["id"] in ids or type(case["changes"]) is not dict or
                type(case["expected_reason"]) is not str):
            raise ValueError("fixture_case_invalid")
        ids.add(case["id"])
    return data


def run_negative_corpus():
    data = load_cases()
    rows = []
    for case in data["cases"]:
        session = SyntheticSession()
        payload = deepcopy(fixture())
        payload.update(case["changes"])
        if case["id"] == "fc-18-blank-payload":
            raw = ""
        else:
            raw = canonical(payload).decode("utf-8")
        result = session.dispatch(raw)
        passed = (result == {"status": "DENIED", "reason": case["expected_reason"]}
                  and not session.effects
                  and session.files == {"docs/note.txt": "old\n"})
        rows.append({
            "id": case["id"],
            "fixture_sha256": digest(case),
            "result": "PASS" if passed else "FAIL",
            "observed_reason": result["reason"],
        })
    return {
        "schema": "h480-contract-eval-v1",
        "dataset_sha256": digest(data),
        "mode": "offline_synthetic_no_device",
        "total": len(rows),
        "passed": sum(x["result"] == "PASS" for x in rows),
        "results": rows,
        "live_tool_enforcement": "NOT_VERIFIED",
        "model_cost": None,
    }


def main():
    report = run_negative_corpus()
    print(f"H-480 offline call contracts: {report['passed']}/{report['total']} PASS")
    print(f"Dataset SHA256: {report['dataset_sha256']}")
    return 0 if report["passed"] == report["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
