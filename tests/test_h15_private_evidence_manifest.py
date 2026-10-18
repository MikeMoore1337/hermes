"""Hermes #349 private output manifest: synthetic-only negative/security tests."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from eval_lane.evidence_manifest import FILES, make_private_hash_manifest
from eval_lane.protocol import AdmissionDenied


NOW = 1800000000.0
SECRET = "sk-test-secret-synthetic-DO-NOT-EXPORT"


def stamp(offset):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(NOW + offset, timezone.utc).isoformat()


def example_job():
    return {
        "schema_version": 1, "kind": "adt_skill_eval_pilot_v1",
        "job_id": "evidence-job-123456789", "approval_id": "owner-grant-123456789",
        "toolkit_sha": "a" * 40, "provider": "codex", "model": "approved-model",
        "case_ids": ["python-api"], "trials": 1,
        "timeout_seconds": 120,
        "resource_limits": {
            "memory_mb": 512, "cpu_seconds": 300, "output_bytes": 65536,
        },
        "budget": {"maximum_usd": "1.00", "provider_hard_cap_id": "hard-cap-12345678"},
        "issued_at": stamp(-10), "expires_at": stamp(600),
    }


class EvidenceManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "private"
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o700)
        self.job = example_job()
        self.observations = {
            "schema_version": 1, "dataset": "adt-controlled-pilot-v1",
            "provider": "codex", "model": "approved-model", "executed": True,
            "records": [],
            # Simulate sensitive content in untrusted metadata. It MUST NOT flow out.
            "host_secret": SECRET,
        }
        for variant in ("baseline", "candidate"):
            name = f"python-api-t1-{variant}"
            folder = self.root / name
            folder.mkdir(mode=0o700)
            claims = {}
            evidence = []
            for file in FILES:
                path = folder / file
                value = (f"secret captured {SECRET}" if file == "agent.stdout.txt"
                         else f"synthetic {file} {variant}").encode("utf-8")
                path.write_bytes(value)
                path.chmod(0o600)
                rel = f"{name}/{file}"
                claims[rel] = hashlib.sha256(value).hexdigest()
                evidence.append(rel)
            self.observations["records"].append({
                "case_id": "python-api", "trial": 1, "variant": variant,
                "fixture_commit_sha": "f" * 40,
                "cli": {"returncode": 0, "timed_out": False},
                "oracle": {"returncode": 0 if variant == "candidate" else 1,
                           "timed_out": False},
                "evidence": evidence, "evidence_sha256": claims,
                "raw_provider_response": SECRET,
            })
        self.resync()

    def resync(self):
        data = json.dumps(self.observations).encode("utf-8")
        path = self.root / "observations.json"
        path.write_bytes(data)
        path.chmod(0o600)
        self.expected = hashlib.sha256(data).hexdigest()

    def report(self, digest=None):
        return make_private_hash_manifest(
            self.root, self.job, expected_sha256=digest or self.expected, clock=NOW)

    def test_sealed_hash_only_index_has_no_raw_secrets(self):
        result = self.report()
        self.assertEqual(result["paired_attempts"], 2)
        self.assertEqual(result["type"], "PRIVATE_HASH_ONLY_NOT_REVIEWED")
        self.assertFalse(result["safe_to_publish"])
        self.assertEqual(result["independent_review"], "NOT_PERFORMED")
        self.assertTrue(result["records"][1]["oracle_passed"])
        self.assertFalse(result["records"][0]["oracle_passed"])
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn("raw_provider_response", json.dumps(result))
        self.assertNotIn("agent.stdout.txt\nsecret captured", json.dumps(result))
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_modified_evidence_detected_even_if_report_not_tampered(self):
        target = self.root / "python-api-t1-baseline" / "agent.stdout.txt"
        target.write_text("tampered after run", encoding="utf-8")
        with self.assertRaisesRegex(AdmissionDenied, "evidence_tampering_detected"):
            self.report()

    def test_modified_observations_digest_denied(self):
        self.observations["host_secret"] = SECRET + "-updated"
        self.resync()
        with self.assertRaisesRegex(AdmissionDenied, "observations_digest_mismatch"):
            self.report(digest="a" * 64)

    def test_symlinks_and_public_folder_rejected(self):
        folder = self.root / "python-api-t1-baseline"
        target = folder / "agent.stdout.txt"
        target.unlink()
        target.symlink_to(self.root / "observations.json")
        with self.assertRaisesRegex(AdmissionDenied, "unsafe_evidence_file"):
            self.report()
        target.unlink()
        self.root.chmod(0o755)
        with self.assertRaisesRegex(AdmissionDenied, "evidence_root_must_be_0700"):
            self.report()

    def test_missing_or_duplicate_pair_refused(self):
        self.observations["records"].pop()
        self.resync()
        with self.assertRaisesRegex(AdmissionDenied, "incomplete_paired_observations"):
            self.report()
        self.observations["records"].append(self.observations["records"][0].copy())
        self.resync()
        with self.assertRaisesRegex(AdmissionDenied, "unexpected_or_duplicate_evidence_run"):
            self.report()

    def test_hidden_extra_evidence_path_refused(self):
        self.observations["records"][0]["evidence"].append("../private")
        self.resync()
        with self.assertRaisesRegex(AdmissionDenied, "evidence_inventory_mismatch"):
            self.report()

    def test_unknown_provider_and_untrusted_claims_fail(self):
        self.observations["provider"] = "malicious"
        self.resync()
        with self.assertRaisesRegex(AdmissionDenied, "observations_context_mismatch"):
            self.report()


if __name__ == "__main__":
    unittest.main()
