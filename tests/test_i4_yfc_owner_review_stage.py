"""Offline synthetic source snapshots for protected I4 review-packet stage."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from research_scout import yfc_draft_handoff as handoff
from research_scout import yfc_owner_review_stage as staging


class OwnerReviewStageTests(unittest.TestCase):
    def setUp(self):
        ctx = tempfile.TemporaryDirectory()
        self.addCleanup(ctx.cleanup)
        self.root = Path(ctx.name) / "private"
        self.root.mkdir(mode=0o700)
        self.sources = self.root / "sources"
        self.sources.mkdir(mode=0o700)
        self.destination = self.root / "i4-reviewed-content.json"
        self.fake = {
            "fink2016": b"Fink synthetic evidence for offline tests only.",
            "vann2022": b"Vann synthetic evidence for offline tests only.",
        }
        self.expected = {}
        for name, raw in self.fake.items():
            f = self.sources / (name + ".txt")
            f.write_bytes(raw)
            f.chmod(0o600)
            self.expected[name] = (staging.EXPECTED_SOURCES[name][0],
                                   hashlib.sha256(raw).hexdigest())

    def test_stages_exactly_once_never_promotes_or_submits(self):
        with patch.object(staging, "EXPECTED_SOURCES", self.expected):
            raw = staging.prepare(source_dir=self.sources)
            packet = json.loads(raw)
            self.assertEqual(len(packet["source_receipts"]), 2)
            self.assertEqual(len(packet["article"]["claim_source_matrix"]), 5)
            self.assertTrue(all(row["review_status"] == "pending"
                                for row in packet["article"]["claim_source_matrix"]))
            self.assertIsNone(packet["article"]["domain_reviewer"])
            receipt = staging.stage(raw, destination=self.destination)
            self.assertEqual(receipt, hashlib.sha256(raw).hexdigest())
            self.assertEqual(self.destination.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.destination.read_bytes(), raw)
            with self.assertRaisesRegex(staging.StageHold, "REVIEW_PACKET_ALREADY_EXISTS"):
                staging.stage(raw, destination=self.destination)
            self.assertEqual(self.destination.read_bytes(), raw)

    def test_wrong_sha_and_permission_never_create_review_packet(self):
        with patch.object(staging, "EXPECTED_SOURCES", self.expected):
            (self.sources / "vann2022.txt").write_bytes(b"corrupted")
            with self.assertRaisesRegex(staging.StageHold, "PRIMARY_TEXT_DIGEST_MISMATCH"):
                staging.prepare(source_dir=self.sources)
        self.assertFalse(self.destination.exists())
        (self.sources / "vann2022.txt").write_bytes(self.fake["vann2022"])
        (self.sources / "vann2022.txt").chmod(0o644)
        with patch.object(staging, "EXPECTED_SOURCES", self.expected):
            with self.assertRaisesRegex(staging.StageHold, "SOURCE_FILE_UNTRUSTED"):
                staging.prepare(source_dir=self.sources)
        self.assertFalse(self.destination.exists())

    def test_destination_parent_wrong_mode_or_symlink_denied(self):
        with patch.object(staging, "EXPECTED_SOURCES", self.expected):
            raw = staging.prepare(source_dir=self.sources)
        self.root.chmod(0o755)
        with self.assertRaisesRegex(staging.StageHold, "DESTINATION_UNTRUSTED"):
            staging.stage(raw, destination=self.destination)
        self.root.chmod(0o700)
        self.destination.symlink_to(self.root / "outside")
        with self.assertRaisesRegex(staging.StageHold, "REVIEW_PACKET_ALREADY_EXISTS"):
            staging.stage(raw, destination=self.destination)
        self.assertFalse((self.root / "outside").exists())

    def test_untrusted_candidate_flags_cannot_be_auto_promoted(self):
        document = json.loads(staging.CANDIDATE.read_text(encoding="utf-8"))
        document["article"]["claim_source_matrix"][0]["review_status"] = "verified"
        candidate = self.root / "candidate.json"
        candidate.write_text(json.dumps(document), encoding="utf-8")
        with patch.object(staging, "EXPECTED_SOURCES", self.expected):
            with self.assertRaisesRegex(staging.StageHold, "EDITORIAL_APPROVAL_NOT_ATTESTED"):
                staging.prepare(candidate=candidate, source_dir=self.sources)
        document["article"]["claim_source_matrix"][0]["review_status"] = "pending"
        document["source_receipts"] = [{"source_id": "madeup"}]
        candidate.write_text(json.dumps(document), encoding="utf-8")
        with patch.object(staging, "EXPECTED_SOURCES", self.expected):
            with self.assertRaisesRegex(staging.StageHold, "CANDIDATE_CHANGED"):
                staging.prepare(candidate=candidate, source_dir=self.sources)

    def test_default_cli_has_zero_effects(self):
        with patch.object(staging, "prepare") as builder:
            self.assertEqual(staging.main([]), 0)
            builder.assert_not_called()


if __name__ == "__main__":
    unittest.main()
