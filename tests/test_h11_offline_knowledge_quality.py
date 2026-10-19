"""Only synthetic facts and no vault access; H-11 first-stage acceptance."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest

from knowledge_quality.offline_audit import KnowledgeAuditError, SCHEMA, audit_fixture

def good() -> dict:
    return {
        "schema": SCHEMA,
        "sources": [{"id": "SRC-a", "updated_on": "2026-10-14",
                     "access": "allowed", "origin": "synthetic_only"}],
        "facts": [{"id": "F-a", "topic": "demo-plant", "predicate": "demo-effective",
                   "value": "YES", "checked_on": "2026-10-14",
                   "source_ids": ["SRC-a"], "links": []}],
    }

class H11OfflineTests(unittest.TestCase):
    def check(self, data, expected, reason=None):
        result = audit_fixture(data, as_of="2026-10-16")
        fact = result["facts"][0]
        self.assertEqual(fact["status"], expected)
        if reason:
            self.assertIn(reason, fact["reason_codes"])
        self.assertFalse(result["vault_accessed"])
        self.assertFalse(result["model_called"])
        self.assertFalse(result["integration_verified"])
        self.assertEqual(result["mode"], "SYNTHETIC_ONLY")
        self.assertNotIn("value", fact)

    def test_valid_recent_synthetic_fact(self):
        self.check(good(), "READY")

    def test_stale_fact_and_source_are_held(self):
        for field in ("checked_on", "updated_on"):
            data = good()
            obj = data["facts"][0] if field == "checked_on" else data["sources"][0]
            obj[field] = "2026-01-01"
            self.check(data, "HOLD", "STALE_FACT" if field == "checked_on" else "STALE_SOURCE")

    def test_revoked_access_is_held(self):
        data = good()
        data["sources"][0]["access"] = "revoked"
        self.check(data, "HOLD", "REVOKED_SOURCE")

    def test_no_provenance_is_unknown(self):
        data = good()
        data["facts"][0]["source_ids"] = []
        self.check(data, "UNKNOWN", "INSUFFICIENT_PROVENANCE")

    def test_missing_source_is_held(self):
        data = good()
        data["facts"][0]["source_ids"] = ["SRC-missing"]
        self.check(data, "HOLD", "MISSING_SOURCE")

    def test_orphan_link_is_held(self):
        data = good()
        data["facts"][0]["links"] = ["F-gone"]
        self.check(data, "HOLD", "ORPHAN_LINK")

    def test_conflicting_facts_both_held(self):
        data = good()
        second = copy.deepcopy(data["facts"][0])
        second["id"] = "F-b"
        second["value"] = "NO"
        data["facts"].append(second)
        result = audit_fixture(data, as_of="2026-10-16")
        self.assertEqual(result["summary"]["HOLD"], 2)
        self.assertTrue(all("CONTRADICTION" in row["reason_codes"] for row in result["facts"]))

    def test_future_timestamp_or_non_synthetic_origin_rejected(self):
        for choice in ("future", "origin"):
            data = good()
            if choice == "future":
                data["sources"][0]["updated_on"] = "2026-10-17"
            else:
                data["sources"][0]["origin"] = "private_vault"
            with self.subTest(choice=choice), self.assertRaises(KnowledgeAuditError):
                audit_fixture(data, as_of="2026-10-16")

    def test_no_source_urls_or_sensitive_text_accepted(self):
        for choice in ("path", "content", "url", "large"):
            data = good()
            if choice == "path":
                data["sources"][0]["id"] = "C:\\private\\vault"
            elif choice == "content":
                data["facts"][0]["value"] = "real private user information"
            elif choice == "url":
                data["sources"][0]["source_url"] = "https://example.com/private"
            else:
                data["facts"] = data["facts"] * 101
            with self.subTest(choice=choice), self.assertRaises(KnowledgeAuditError):
                audit_fixture(data, as_of="2026-10-16")

    def test_duplicate_references_and_unknown_key_rejected(self):
        data = good()
        data["facts"][0]["source_ids"] = ["SRC-a", "SRC-a"]
        with self.assertRaises(KnowledgeAuditError):
            audit_fixture(data, as_of="2026-10-16")
        data = good()
        data["unexpected"] = "publish"
        with self.assertRaises(KnowledgeAuditError):
            audit_fixture(data, as_of="2026-10-16")

    def test_existing_link_to_revoked_source_forces_hold(self):
        data = good()
        child = copy.deepcopy(data["facts"][0])
        child["id"] = "F-b"
        child["source_ids"] = ["SRC-b"]
        data["sources"].append({"id": "SRC-b", "updated_on": "2026-10-14",
                                "access": "revoked", "origin": "synthetic_only"})
        data["facts"][0]["links"] = ["F-b"]
        data["facts"].append(child)
        rows = {r["fact_id"]: r for r in audit_fixture(data, as_of="2026-10-16")["facts"]}
        self.assertEqual(rows["F-b"]["status"], "HOLD")
        self.assertEqual(rows["F-a"]["status"], "HOLD")
        self.assertIn("LINKED_FACT_HOLD", rows["F-a"]["reason_codes"])

    def test_existing_link_to_unknown_provenance_is_unknown(self):
        data = good()
        child = copy.deepcopy(data["facts"][0])
        child["id"] = "F-b"
        child["source_ids"] = []
        data["facts"][0]["links"] = ["F-b"]
        data["facts"].append(child)
        rows = {r["fact_id"]: r for r in audit_fixture(data, as_of="2026-10-16")["facts"]}
        self.assertEqual(rows["F-b"]["status"], "UNKNOWN")
        self.assertEqual(rows["F-a"]["status"], "UNKNOWN")
        self.assertIn("LINKED_FACT_UNKNOWN", rows["F-a"]["reason_codes"])

    def test_linked_hold_is_transitive_and_never_exposes_values(self):
        data = good()
        parent = data["facts"][0]
        middle = copy.deepcopy(parent)
        leaf = copy.deepcopy(parent)
        middle["id"], middle["links"] = "F-b", ["F-c"]
        leaf["id"], leaf["checked_on"] = "F-c", "2026-01-01"
        parent["links"] = ["F-b"]
        data["facts"].extend([middle, leaf])
        result = audit_fixture(data, as_of="2026-10-16")
        rows = {r["fact_id"]: r for r in result["facts"]}
        self.assertEqual(result["summary"]["HOLD"], 3)
        self.assertIn("LINKED_FACT_HOLD", rows["F-b"]["reason_codes"])
        self.assertIn("LINKED_FACT_HOLD", rows["F-a"]["reason_codes"])
        self.assertNotIn("value", str(result))

    def test_link_to_valid_synthetic_fact_stays_ready(self):
        data = good()
        child = copy.deepcopy(data["facts"][0])
        child["id"] = "F-b"
        data["facts"][0]["links"] = ["F-b"]
        data["facts"].append(child)
        result = audit_fixture(data, as_of="2026-10-16")
        self.assertEqual(result["summary"], {"READY": 2, "UNKNOWN": 0, "HOLD": 0})

    def test_cycle_with_one_stale_fact_holds_both(self):
        data = good()
        child = copy.deepcopy(data["facts"][0])
        child["id"] = "F-b"
        child["checked_on"] = "2026-01-01"
        child["links"] = ["F-a"]
        data["facts"][0]["links"] = ["F-b"]
        data["facts"].append(child)
        result = audit_fixture(data, as_of="2026-10-16")
        self.assertEqual(result["summary"]["HOLD"], 2)
        self.assertTrue(all("LINKED_FACT_HOLD" in item["reason_codes"]
                            for item in result["facts"]))

    def test_mixed_dependency_statuses_are_order_independent(self):
        data = good()
        parent = data["facts"][0]
        held = copy.deepcopy(parent)
        unknown = copy.deepcopy(parent)
        ready = copy.deepcopy(parent)
        held["id"], held["checked_on"], held["links"] = "F-b", "2026-01-01", ["F-a"]
        unknown["id"], unknown["source_ids"], unknown["links"] = "F-c", [], ["F-d"]
        ready["id"] = "F-d"
        parent["links"] = ["F-b", "F-c"]
        data["facts"].extend([held, unknown, ready])
        baseline = audit_fixture(data, as_of="2026-10-16")
        self.assertEqual(baseline["summary"], {"READY": 1, "UNKNOWN": 1, "HOLD": 2})
        rows = {row["fact_id"]: row for row in baseline["facts"]}
        self.assertIn("LINKED_FACT_HOLD", rows["F-a"]["reason_codes"])
        self.assertNotIn("LINKED_FACT_UNKNOWN", rows["F-a"]["reason_codes"])
        self.assertIn("LINKED_FACT_UNKNOWN", rows["F-c"]["reason_codes"])
        for order in (list(reversed(data["facts"])), [unknown, ready, parent, held]):
            permuted = copy.deepcopy(data)
            permuted["facts"] = order
            self.assertEqual(audit_fixture(permuted, as_of="2026-10-16"), baseline)

    def test_cli_rejects_shadowed_private_json_keys(self):
        cmd = [sys.executable, "-m", "knowledge_quality.offline_audit", "--as-of", "2026-10-16"]
        baseline = json.dumps(good())
        shadowed = (
            ('"origin": "synthetic_only"',
             '"origin": "private_vault", "origin": "synthetic_only"'),
            ('"value": "YES"',
             '"value": "private note content", "value": "YES"'),
            ('"schema": "hermes-h11-synthetic-fixture-v1"',
             '"schema": "forged", "schema": "hermes-h11-synthetic-fixture-v1"'),
        )
        for original, replacement in shadowed:
            self.assertIn(original, baseline)
            payload = baseline.replace(original, replacement, 1).encode("utf-8")
            with self.subTest(duplicate_key=original):
                result = subprocess.run(cmd, input=payload, capture_output=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(json.loads(result.stdout),
                                 {"status": "REJECTED", "reason": "invalid_fixture"})
                self.assertNotIn(b"private note content", result.stdout)

    def test_pure_audit_never_opens_files_sockets_or_processes(self):
        from unittest.mock import patch

        with (patch("builtins.open", side_effect=AssertionError("file access")),
              patch("socket.socket", side_effect=AssertionError("network access")),
              patch("subprocess.Popen", side_effect=AssertionError("process access"))):
            self.assertEqual(audit_fixture(good(), as_of="2026-10-16")["summary"]["READY"], 1)

    def test_cli_read_only_roundtrip_and_rejection(self):
        cmd = [sys.executable, "-m", "knowledge_quality.offline_audit", "--as-of", "2026-10-16"]
        result = subprocess.run(cmd, input=json.dumps(good()).encode("utf-8"), capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["summary"]["READY"], 1)
        for invalid in (b"{", b"x" * 16385):
            result = subprocess.run(cmd, input=invalid, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)["status"], "REJECTED")

if __name__ == "__main__":
    unittest.main()
