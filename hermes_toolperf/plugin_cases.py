"""Pinned H-464 synthetic manifest replay, not an installer."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re

from .plugin_review import (
    ReviewDenied, SyntheticReader, canonical, sample_manifest, sha256,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "plugin-review-v1.json"


def load_cases():
    dataset = json.loads(FIXTURES.read_text(encoding="utf-8"))
    if (type(dataset) is not dict or set(dataset) != {"schema_version", "dataset", "cases"}
            or type(dataset["schema_version"]) is not int or
            dataset["schema_version"] != 1 or
            dataset["dataset"] != "h464-review-manifest-negative-v1" or
            type(dataset["cases"]) is not list or len(dataset["cases"]) != 16):
        raise ValueError("invalid_plugin_test_dataset")
    seen = set()
    for case in dataset["cases"]:
        if (type(case) is not dict or
                set(case) != {"id", "changes", "expected_reason"} or
                type(case["id"]) is not str or
                not re.fullmatch(r"pl-[0-9]{2}-[a-z0-9-]+", case["id"]) or
                case["id"] in seen or type(case["changes"]) is not dict or
                type(case["expected_reason"]) is not str):
            raise ValueError("invalid_plugin_test_case")
        seen.add(case["id"])
    return dataset


def run_negative_corpus():
    dataset = load_cases()
    results = []
    for case in dataset["cases"]:
        reader = SyntheticReader()
        manifest = deepcopy(sample_manifest())
        manifest.update(case["changes"])
        reason = "NO_DENIAL"
        try:
            reader.read(canonical(manifest).decode("utf-8"),
                        call_id="trial-one", fixture_id="research-record-v1")
        except ReviewDenied as exc:
            reason = str(exc)
        passed = (reason == case["expected_reason"] and
                  reader.effects == [] and reader.calls == set())
        results.append({
            "id": case["id"], "case_sha256": sha256(case),
            "status": "PASS" if passed else "FAIL", "reason": reason,
        })
    return {
        "schema": "h464-plugin-review-offline-v1",
        "dataset_sha256": sha256(dataset),
        "total": len(results),
        "passed": sum(r["status"] == "PASS" for r in results),
        "status": "synthetic_review_only",
        "runtime_plugins_installed": False,
        "external_source_verified": False,
        "results": results,
    }


def main():
    report = run_negative_corpus()
    print(f"H-464 synthetic manifest reviews: {report['passed']}/{report['total']} PASS")
    print("Dataset SHA256: " + report["dataset_sha256"])
    print("Live plugin activation and source authentication: NOT_VERIFIED")
    return 0 if report["passed"] == report["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
