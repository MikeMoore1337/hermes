"""H-03 source-bound scientific handoff is not an approval mechanism."""
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone
import io
import json
import unittest
from unittest.mock import patch

from research_scout import science_handoff as handoff

NOW = datetime(2026, 10, 18, 8, 30, tzinfo=UTC)


class ScienceHandoffTests(unittest.TestCase):
    def test_four_fixed_real_dois_and_all_independent_reviews_are_open(self):
        result = handoff.packet(now=NOW)
        self.assertEqual(result["study_count"], 4)
        self.assertEqual(result["generated_at"], "2026-10-18T08:30:00+00:00")
        self.assertEqual({r["pmid"]: r["doi"] for r in result["studies"]},
                         handoff.EXPECTED_DOIS)
        self.assertEqual(result["conclusion"], "HOLD_FOR_INDEPENDENT_SCIENTIFIC_REVIEW")
        self.assertFalse(result["scientific_claims_verified"])
        self.assertFalse(result["external_publication_allowed"])
        self.assertFalse(result["reviewer_signoff_supported_by_this_tool"])
        self.assertFalse(result["full_text_independently_reviewed"])
        self.assertEqual(result["incomplete_gate_count"],
                         sum(len(r["gates"]) for r in result["studies"]))
        self.assertGreaterEqual(result["incomplete_gate_count"], 18)
        for review in result["studies"]:
            self.assertEqual(review["gates_incomplete"], len(review["gates"]))
            self.assertEqual(review["scientific_review_status"], "NEEDS_EXPERT_REVIEW")
            self.assertFalse(review["scientific_claims_verified"])
            self.assertFalse(review["publisher_clearance_verified"])
            self.assertFalse(review["publication_allowed"])
            self.assertFalse(review["reviewer_approval"])
            self.assertEqual(len({g["id"] for g in review["gates"]}), len(review["gates"]))
            for gate in review["gates"]:
                self.assertTrue(gate["reference_url"].startswith("https://"))
                self.assertEqual(gate["review_state"], "NOT_INDEPENDENTLY_REVIEWED")
                self.assertEqual(gate["effect_size"], "NOT_INDEPENDENTLY_VERIFIED")
                self.assertEqual(gate["confidence_interval"], "NOT_INDEPENDENTLY_VERIFIED")
                self.assertFalse(gate["editorial_approval"])
                self.assertIsNone(gate["reviewer"])
                self.assertIsNone(gate["review_signature"])

    def test_all_four_studies_have_study_specific_gate_coverage(self):
        r = {s["pmid"]: s for s in handoff.packet(now=NOW)["studies"]}
        self.assertEqual({g["id"] for g in r["42840492"]["gates"]},
                         {"W1", "W2", "W3", "W4"})
        self.assertEqual({g["id"] for g in r["42771055"]["gates"]},
                         {"I1", "I2", "I3", "I4", "I5"})
        self.assertEqual({g["id"] for g in r["42797032"]["gates"]},
                         {"P1", "P2", "P3", "P4", "P5"})
        self.assertEqual({g["id"] for g in r["42733310"]["gates"]},
                         {"C1", "C2", "C3", "C4", "C5"})
        assert r["42771055"]["original_candidate_status"] == "HOLD"
        corr = next(g for g in r["42771055"]["gates"] if g["id"] == "I4")
        self.assertIn("11294-6", corr["reference_url"])
        secondary = next(g for g in r["42733310"]["gates"] if g["id"] == "C1")
        self.assertEqual(secondary["source_coverage"],
                         "OFFICIAL_REGISTRY_FULL_RECORD_NOT_OBSERVED")
        self.assertIn("Secondary mirrors", secondary["question"])
        self.assertTrue(all(
            g["review_state"] == "NOT_INDEPENDENTLY_REVIEWED"
            for g in r["42733310"]["gates"]
        ))

    def test_false_upgrade_in_curated_record_must_abort_not_generate_packet(self):
        original = handoff.curated_reports()
        bad_cases = [
            {"scientific_claims_verified": True},
            {"full_text_reviewed": True},
            {"expert_review": "COMPLETE"},
            {"review_status": "APPROVED"},
            {"status": "SCIENTIFICALLY_APPROVED"},
            {"doi": "10.1000/replaced"},
        ]
        for changed in bad_cases:
            with self.subTest(changed=changed):
                edited = deepcopy(original)
                edited[0].update(changed)
                with patch.object(handoff, "curated_reports", return_value=edited):
                    with self.assertRaisesRegex(ValueError, "handoff_curated_science_promoted"):
                        handoff.packet(now=NOW)

    def test_ironman_publisher_correction_never_loses_hold(self):
        original = handoff.curated_reports()
        for override in ({"status": "MANUAL_REVIEW"}, {"correction_url": None}):
            with self.subTest(override=override):
                edited = deepcopy(original)
                next(x for x in edited if x["pmid"] == "42771055").update(override)
                with patch.object(handoff, "curated_reports", return_value=edited):
                    with self.assertRaisesRegex(ValueError, "handoff_correction_must_hold"):
                        handoff.packet(now=NOW)

    def test_missing_or_replaced_fixed_source_rejected(self):
        original = handoff.curated_reports()
        for rows in (original[:3], original + [original[0]],
                     [*original[:3], {**original[3], "pmid": "00000000"}]):
            with self.subTest(n=len(rows)):
                with patch.object(handoff, "curated_reports", return_value=rows):
                    with self.assertRaisesRegex(ValueError, "handoff_curated_sources_changed"):
                        handoff.packet(now=NOW)

    def test_bad_gate_id_or_non_https_link_aborts_packet(self):
        base = handoff.REVIEW_GATES["42840492"]
        wrong = ((base[0][0], base[0][1], "http://unexpected.com", base[0][3]), *base[1:])
        for modified in ((base[0], base[0], *base[1:]), wrong):
            with self.subTest(modified=modified):
                with patch.dict(handoff.REVIEW_GATES, {"42840492": modified}):
                    with self.assertRaisesRegex(ValueError, "handoff_gate_invalid"):
                        handoff.packet(now=NOW)

    def test_only_utc_timestamps_are_accepted(self):
        for value in (datetime(2026, 10, 18),
                      datetime(2026, 10, 18, tzinfo=timezone(timedelta(hours=3))),
                      None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "handoff_requires_utc"):
                    handoff.packet(now=value)

    def test_cli_is_offline_and_contains_no_private_or_automatic_review(self):
        out = io.StringIO()
        with patch("sys.stdout", out), patch.object(handoff, "packet",
                                                   wraps=handoff.packet) as call:
            self.assertEqual(handoff.main([]), 0)
            call.assert_called_once()
        report = json.loads(out.getvalue())
        self.assertFalse(report["external_publication_allowed"])
        self.assertFalse(report["scientific_claims_verified"])
        self.assertEqual(report["study_count"], 4)
        self.assertTrue(all(
            g["review_signature"] is None
            for r in report["studies"] for g in r["gates"]
        ))


if __name__ == "__main__":
    unittest.main()
