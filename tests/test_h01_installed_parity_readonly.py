"""H-01 #33: installed source parity is read-only and never implies model PASS."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts import h01_installed_parity_readonly as parity


class H01InstalledParityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.owner = root / "opt" / "hermes-agent-owner"
        self.marker = root / "var" / "last-success.sha"
        self.reservation = root / "var" / "state.json"
        self.sha = "b" * 40
        release = self.owner / "releases" / ("main-" + self.sha)
        (release / "scripts").mkdir(parents=True)
        (self.owner / "scripts").mkdir()
        self.marker.parent.mkdir()
        self.marker.write_text(self.sha + "\n", encoding="ascii")
        (release / ".deployment-receipt.txt").write_text(
            "SHA=" + self.sha + "\nRESIDENT_ACTIVATED=no\n", encoding="utf-8"
        )
        self.release_script = release / "scripts" / "h01_ops_agent_service.py"
        self.installed_script = self.owner / "scripts" / "h01_ops_agent_service.py"
        self.release_script.write_text("MAX_CALLS_PER_UTC_DAY = 1\n", encoding="utf-8")
        self.installed_script.write_bytes(self.release_script.read_bytes())
        self.reservation.write_text(json.dumps({
            "utc_date": "2026-10-19", "calls": 1,
            "last_event_id": 38, "last_status": "agent_result_unverified",
        }), encoding="utf-8")

    def check(self):
        return parity.probe(self.owner, self.marker, self.reservation)

    def test_exact_source_and_valid_reservation_are_only_partial_evidence(self):
        before = {p.relative_to(self.owner).as_posix(): p.read_bytes()
                  for p in self.owner.rglob("*") if p.is_file()}
        r = self.check()
        self.assertEqual(r["source_parity"], "MATCH")
        self.assertEqual(r["source_release_sha"], self.sha)
        self.assertEqual(r["reservation"], "VALID")
        self.assertEqual(r["reservation_summary"]["last_event_id"], 38)
        self.assertEqual(r["reservation_summary"]["reserved_calls"], 1)
        self.assertEqual(r["reservation_summary"]["last_status_kind"], "OTHER")
        self.assertEqual(r["useful_incident_model_turn"], "NOT_VERIFIED")
        self.assertEqual(r["provider_side_usage"], "NOT_MEASURED")
        after = {p.relative_to(self.owner).as_posix(): p.read_bytes()
                 for p in self.owner.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_stale_installed_source_fails_parity(self):
        self.installed_script.write_text("MAX_CALLS_PER_UTC_DAY = 100\n")
        self.assertEqual(self.check()["source_parity"], "DRIFT")

    def test_missing_or_wrong_receipt_does_not_prove_release(self):
        receipt = self.release_script.parent.parent / ".deployment-receipt.txt"
        receipt.write_text("SHA=" + "a" * 40 + "\n")
        self.assertEqual(self.check()["source_parity"], "NOT_VERIFIED")
        receipt.unlink()
        self.assertEqual(self.check()["source_parity"], "NOT_VERIFIED")

    def test_bad_marker_does_not_claim_source_parity(self):
        self.marker.write_text("../../main\n")
        r = self.check()
        self.assertEqual(r["source_parity"], "NOT_VERIFIED")
        self.assertIsNone(r["source_release_sha"])

    def test_symlinked_installed_file_denied(self):
        self.installed_script.unlink()
        self.installed_script.symlink_to(self.release_script)
        self.assertEqual(self.check()["source_parity"], "NOT_VERIFIED")

    def test_symlinked_installed_directory_denied(self):
        self.installed_script.unlink()
        (self.owner / "scripts").rmdir()
        (self.owner / "scripts").symlink_to(self.release_script.parent, target_is_directory=True)
        self.assertEqual(self.check()["source_parity"], "NOT_VERIFIED")

    def test_invalid_reservation_never_reveals_untrusted_status(self):
        self.reservation.write_text(json.dumps({
            "utc_date": "2026-10-19", "calls": 2,
            "last_event_id": 38, "last_status": "Bearer secret material",
        }))
        r = self.check()
        self.assertEqual(r["source_parity"], "MATCH")
        self.assertEqual(r["reservation"], "NOT_VERIFIED")
        self.assertIsNone(r["reservation_summary"])
        self.assertNotIn("secret", json.dumps(r).lower())

    def test_valid_recorded_pass_is_not_independent_model_proof(self):
        self.reservation.write_text(json.dumps({
            "utc_date": "2026-10-19", "calls": 1,
            "last_event_id": 39, "last_status": "PASS",
        }))
        r = self.check()
        self.assertEqual(r["reservation_summary"]["last_status_kind"], "PASS_RECORDED")
        self.assertEqual(r["useful_incident_model_turn"], "NOT_VERIFIED")

    def test_unavailable_state_leaves_source_evidence_independent(self):
        self.reservation.unlink()
        r = self.check()
        self.assertEqual(r["source_parity"], "MATCH")
        self.assertEqual(r["reservation"], "NOT_VERIFIED")


if __name__ == "__main__":
    unittest.main()
