"""I3 scientific handoff tests: no scientific auto-approval or YFC sends."""
from __future__ import annotations

import copy
from datetime import UTC, datetime
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from research_scout.science_handoff import packet
from research_scout.yfc_editorial_preflight import (
    RESULT_SCHEMA,
    SciencePreflightRefused,
    assess_science_handoff,
    current_preflight,
)

NOW = datetime(2026, 10, 24, 19, 0, tzinfo=UTC)


class ScienceEditorialPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = packet(now=NOW)

    def test_real_four_unapproved_sources_remain_hold(self) -> None:
        result = assess_science_handoff(self.source)
        self.assertEqual(result["schema"], RESULT_SCHEMA)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["study_count"], 4)
        self.assertEqual(result["expert_checks_pending"], 19)
        self.assertEqual(len(result["sources"]), 4)
        self.assertEqual(sum(x["incomplete_gates"] for x in result["sources"]), 19)
        self.assertTrue(all(x["forwardable"] is False for x in result["sources"]))
        self.assertTrue(all(x["claim_text"] is None for x in result["sources"]))
        self.assertEqual(result["network_calls"], 0)
        self.assertIsNone(result["yfc_request_payload"])
        self.assertFalse(result["publication_allowed"])

    def test_ironman_correction_not_silent_clearance(self) -> None:
        result = assess_science_handoff(self.source)
        ironman = next(x for x in result["sources"] if x["pmid"] == "42771055")
        self.assertEqual(ironman["doi"], "10.1007/s00520-026-11251-3")
        self.assertEqual(ironman["correction_status"], "KNOWN_CORRECTION_UNREVIEWED")
        self.assertEqual(ironman["source_freshness"], "NOT_RECHECKED_LIVE")
        self.assertEqual(ironman["publisher_license_clearance"], "NOT_VERIFIED")

    def test_yfc_article_schema_does_not_become_automatic_science_transport(self) -> None:
        result = assess_science_handoff(self.source)
        self.assertEqual(result["yfc_web_article_schema"], "hermes-web-article-intake-v1")
        self.assertEqual(result["yfc_news_intake_schema"], "hermes-editorial-intake-v2")
        self.assertFalse(result["claim_level_contract_compatible"])
        self.assertFalse(result["editorial_approval_verified"])
        self.assertIsNone(result["yfc_request_payload"])

    def test_spoofed_expert_and_editorial_approvals_rejected(self) -> None:
        mutations = (
            lambda p: p.update(scientific_claims_verified=True),
            lambda p: p.update(external_publication_allowed=True),
            lambda p: p["studies"][0].update(reviewer_approval=True),
            lambda p: p["studies"][0].update(publication_allowed=True),
            lambda p: p["studies"][0]["gates"][0].update(reviewer="self_reported"),
            lambda p: p["studies"][0]["gates"][0].update(editorial_approval=True),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(self.source)
            mutate(candidate)
            with self.subTest(mutate=mutate):
                with self.assertRaisesRegex(
                    SciencePreflightRefused, "science_handoff_not_authorized"
                ):
                    assess_science_handoff(candidate)

    def test_source_doi_gate_and_notice_spoofing_rejected(self) -> None:
        mutations = (
            lambda p: p["studies"][0].update(doi="10.0000/fake"),
            lambda p: p["studies"][0]["gates"][0].update(reference_url="https://evil.test"),
            lambda p: p["studies"][0]["gates"][0].update(review_state="APPROVED"),
            lambda p: p["studies"][0].update(gates_incomplete=0),
            lambda p: p["studies"][1].update(pmid=p["studies"][0]["pmid"]),
            lambda p: p["studies"][0]["gates"].pop(),
            lambda p: p.update(incomplete_gate_count=0),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(self.source)
            mutate(candidate)
            with self.subTest(mutate=mutate):
                with self.assertRaises(SciencePreflightRefused):
                    assess_science_handoff(candidate)

    def test_schema_freshness_and_extra_fields_refused(self) -> None:
        for field, value in (
            ("schema", "untrusted-schema"),
            ("generated_at", "yesterday"),
            ("generated_at", "2026-10-24T22:00:00"),
        ):
            candidate = copy.deepcopy(self.source)
            candidate[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(SciencePreflightRefused):
                    assess_science_handoff(candidate)
        candidate = copy.deepcopy(self.source)
        candidate["post_to_yfc"] = True
        with self.assertRaises(SciencePreflightRefused):
            assess_science_handoff(candidate)

    def test_untrusted_source_title_not_forwarded_or_leaked(self) -> None:
        candidate = copy.deepcopy(self.source)
        sensitive = "Bearer CANARY_SECRET_EXAMPLE"
        candidate["studies"][0]["source_title"] = sensitive
        result = assess_science_handoff(candidate)
        self.assertNotIn(sensitive, json.dumps(result))
        self.assertIsNone(result["yfc_request_payload"])

    def test_offline_current_preflight_never_calls_network(self) -> None:
        with patch("socket.create_connection", side_effect=AssertionError("network")):
            result = current_preflight(now=NOW)
        self.assertEqual(result["status"], "HOLD")

    def test_cli_does_not_emit_request_or_publication_authorization(self) -> None:
        run = subprocess.run(
            [sys.executable, "-m", "research_scout.yfc_editorial_preflight"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False,
        )
        self.assertEqual(run.returncode, 0, run.stderr.decode()[-400:])
        value = json.loads(run.stdout)
        self.assertEqual(value["status"], "HOLD")
        self.assertFalse(value["publication_allowed"])
        self.assertIsNone(value["yfc_request_payload"])
        self.assertEqual(value["network_calls"], 0)


if __name__ == "__main__":
    unittest.main()
