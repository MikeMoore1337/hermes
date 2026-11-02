"""Synthetic-only temporal limits for Hermes H-11, without Second Brain access."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest

from knowledge_quality.offline_audit import KnowledgeAuditError, SCHEMA, audit_fixture

AS_OF = "2026-10-16"


def fixture() -> dict:
    return {
        "schema": SCHEMA,
        "sources": [{"id": "SRC-demo", "updated_on": "2026-10-14",
                     "access": "allowed", "origin": "synthetic_only"}],
        "facts": [{"id": "F-demo", "topic": "demo-product", "predicate": "demo-active",
                   "value": "YES", "checked_on": "2026-10-14",
                   "source_ids": ["SRC-demo"], "links": []}],
    }


def results(data: dict) -> dict:
    return {row["fact_id"]: row for row in audit_fixture(data, as_of=AS_OF)["facts"]}


class H11TemporalValidityTests(unittest.TestCase):
    def test_existing_fixture_without_optional_dates_still_ready(self):
        self.assertEqual(results(fixture())["F-demo"]["status"], "READY")

    def test_source_expiration_is_inclusive_through_its_last_day(self):
        data = fixture()
        data["sources"][0]["expires_on"] = AS_OF
        self.assertEqual(results(data)["F-demo"]["status"], "READY")
        data["sources"][0]["expires_on"] = "2026-10-15"
        self.assertEqual(results(data)["F-demo"]["status"], "HOLD")
        self.assertIn("EXPIRED_SOURCE", results(data)["F-demo"]["reason_codes"])

    def test_fact_expiration_is_inclusive_through_its_last_day(self):
        data = fixture()
        data["facts"][0]["expires_on"] = AS_OF
        self.assertEqual(results(data)["F-demo"]["status"], "READY")
        data["facts"][0]["expires_on"] = "2026-10-15"
        self.assertIn("EXPIRED_FACT", results(data)["F-demo"]["reason_codes"])
        self.assertEqual(results(data)["F-demo"]["status"], "HOLD")

    def test_future_effective_date_is_not_ready(self):
        data = fixture()
        data["facts"][0]["valid_from"] = "2026-10-17"
        self.assertEqual(results(data)["F-demo"]["status"], "HOLD")
        self.assertIn("NOT_YET_EFFECTIVE", results(data)["F-demo"]["reason_codes"])
        data["facts"][0]["valid_from"] = AS_OF
        self.assertEqual(results(data)["F-demo"]["status"], "READY")

    def test_disjoint_historical_versions_are_not_contradictory(self):
        data = fixture()
        old = data["facts"][0]
        old.update({"valid_from": "2026-01-01", "expires_on": "2026-10-15"})
        current = copy.deepcopy(old)
        current.update({"id": "F-current", "value": "NO", "valid_from": AS_OF,
                        "expires_on": "2026-12-31"})
        data["facts"].append(current)
        rows = results(data)
        self.assertNotIn("CONTRADICTION", rows["F-demo"]["reason_codes"])
        self.assertNotIn("CONTRADICTION", rows["F-current"]["reason_codes"])
        self.assertEqual(rows["F-demo"]["status"], "HOLD")
        self.assertEqual(rows["F-current"]["status"], "READY")

    def test_overlapping_conflicting_versions_are_both_held(self):
        data = fixture()
        original = data["facts"][0]
        original.update({"valid_from": "2026-10-01", "expires_on": "2026-10-20"})
        other = copy.deepcopy(original)
        other.update({"id": "F-other", "value": "NO", "valid_from": AS_OF,
                      "expires_on": "2026-11-01"})
        data["facts"].append(other)
        for row in results(data).values():
            self.assertEqual(row["status"], "HOLD")
            self.assertIn("CONTRADICTION", row["reason_codes"])

    def test_unspecified_validity_remains_conservative(self):
        data = fixture()
        other = copy.deepcopy(data["facts"][0])
        other.update({"id": "F-other", "value": "NO", "valid_from": AS_OF})
        data["facts"].append(other)
        self.assertTrue(all("CONTRADICTION" in row["reason_codes"]
                            for row in results(data).values()))

    def test_inverted_temporal_interval_rejected(self):
        data = fixture()
        data["facts"][0].update({"valid_from": "2026-11-01", "expires_on": "2026-10-15"})
        with self.assertRaises(KnowledgeAuditError):
            results(data)

    def test_missing_or_invalid_check_date_rejected(self):
        for date in (None, "2026-02-30", "2026-10-16T00:00:00Z", "2026/10/16"):
            data = fixture()
            data["facts"][0]["checked_on"] = date
            with self.subTest(date=date), self.assertRaises(KnowledgeAuditError):
                results(data)
        data = fixture()
        del data["facts"][0]["checked_on"]
        with self.assertRaises(KnowledgeAuditError):
            results(data)

    def test_invalid_optional_expiry_dates_and_unknown_keys_rejected(self):
        for kind, field in (("sources", "expires_on"), ("facts", "expires_on"),
                            ("facts", "valid_from")):
            for value in (None, 123, "2026-02-30"):
                data = fixture()
                data[kind][0][field] = value
                with self.subTest(kind=kind, field=field, value=value), self.assertRaises(KnowledgeAuditError):
                    results(data)
        data = fixture()
        data["sources"][0]["expiration_url"] = "https://example.com/sensitive"
        with self.assertRaises(KnowledgeAuditError):
            results(data)

    def test_mismatched_or_missing_source_fails_closed(self):
        data = fixture()
        data["facts"][0]["source_ids"] = ["SRC-unrelated"]
        self.assertEqual(results(data)["F-demo"]["status"], "HOLD")
        self.assertIn("MISSING_SOURCE", results(data)["F-demo"]["reason_codes"])

    def test_revocation_and_expiration_are_both_preserved(self):
        data = fixture()
        data["sources"][0].update({"access": "revoked", "expires_on": "2026-10-15"})
        self.assertTrue({"REVOKED_SOURCE", "EXPIRED_SOURCE"} <= set(
            results(data)["F-demo"]["reason_codes"]))

    def test_order_permutations_do_not_change_outcome(self):
        data = fixture()
        for name, value, bounds in (("F-b", "NO", {"valid_from": "2026-10-01"}),
                                    ("F-c", "YES", {"expires_on": "2026-10-15"})):
            fact = copy.deepcopy(data["facts"][0])
            fact.update({"id": name, "value": value, **bounds})
            data["facts"].append(fact)
        baseline = audit_fixture(data, as_of=AS_OF)
        data["facts"] = list(reversed(data["facts"]))
        self.assertEqual(audit_fixture(data, as_of=AS_OF), baseline)

    def test_cli_rejects_invalid_window_without_echoing_payload(self):
        data = fixture()
        data["facts"][0].update({"valid_from": "2026-11-01", "expires_on": "2026-10-15"})
        cmd = [sys.executable, "-m", "knowledge_quality.offline_audit", "--as-of", AS_OF]
        run = subprocess.run(cmd, input=json.dumps(data).encode(), capture_output=True)
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertEqual(json.loads(run.stdout), {"status": "REJECTED", "reason": "invalid_fixture"})
        self.assertNotIn(b"demo-product", run.stdout)

    def test_expired_linked_fact_cannot_make_parent_ready(self):
        data = fixture()
        other = copy.deepcopy(data["facts"][0])
        other.update({"id": "F-old", "expires_on": "2026-10-15"})
        data["facts"][0]["links"] = ["F-old"]
        data["facts"].append(other)
        rows = results(data)
        self.assertIn("LINKED_FACT_HOLD", rows["F-demo"]["reason_codes"])
        self.assertEqual(rows["F-demo"]["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
