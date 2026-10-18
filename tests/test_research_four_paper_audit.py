"""Four-publication Crossref audit: offline fixed-source and conflict regressions."""
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
import io
import json
import unittest
from unittest.mock import Mock, patch

from research_scout import four_paper_audit as audit
from research_scout.crossref_updates import UpdateLookupError

NOW = datetime(2026, 10, 18, 6, tzinfo=UTC)
ORIGINAL = "10.1007/s00520-026-11251-3"
CORRECTION = "10.1007/s00520-026-11294-6"


def source(doi, with_notice=False, truncated=False):
    notices = [{
        "doi": CORRECTION, "notice_type": "CORRECTION_NOTICE",
        "published": "2026-10-02",
        "source": "CROSSREF_REVERSE_UPDATE_METADATA"
    }] if with_notice else []
    return {
        "doi": doi, "source": "CROSSREF",
        "notices": notices,
        "notice_codes": ["CORRECTION_NOTICE"] if with_notice else [],
        "coverage": "CROSSREF_FILTER_TRUNCATED" if truncated else
                    "CROSSREF_REVERSE_UPDATES_ONLY",
        "status": "REVIEW_REQUIRED" if with_notice or truncated else
                  "NOT_FOUND_WITH_COVERAGE",
        "authoritative_notice_clearance": False,
        "scientific_claims_verified": False,
        "automatic_publication": False,
        "manual_review_required": True,
    }


def normal(doi):
    return source(doi, with_notice=(doi == ORIGINAL))


class FourPaperAuditTests(unittest.TestCase):
    def test_exactly_four_public_dois_no_duplicates_and_known_correction(self):
        calls = []
        def inspector(doi):
            calls.append(doi)
            return normal(doi)
        report = audit.review(now=NOW, inspector=inspector)
        self.assertEqual(report["requests_attempted"], 4)
        self.assertEqual(len(calls), 4)
        self.assertEqual(set(calls), {
            "10.1007/s00520-026-11251-3",
            "10.3389/fcimb.2026.1918695",
            "10.3390/nu18183049", "10.1002/ejsc.70246",
        })
        self.assertEqual(report["observed_at"], "2026-10-18T06:00:00+00:00")
        self.assertEqual(report["report_status"], "HOLD_FOR_EXPERT_REVIEW")
        self.assertFalse(report["authoritative_publisher_clearance"])
        self.assertFalse(report["automatic_publication"])
        self.assertFalse(report["scientific_claims_verified"])
        for row in report["results"]:
            self.assertFalse(row["scientific_claims_verified"])
            self.assertFalse(row["publisher_correction_clearance_verified"])
            self.assertFalse(row["automatic_publication"])
        ironman = next(x for x in report["results"] if x["doi"] == ORIGINAL)
        self.assertEqual(ironman["status"], "HOLD")
        self.assertEqual(ironman["publisher_notice_doi"], CORRECTION)
        self.assertEqual(ironman["audit_state"], "CROSSREF_REVIEW_REQUIRED")
        self.assertEqual(ironman["crossref_notice_dois"], [CORRECTION])

    def test_negative_crossref_lookup_never_clears_publisher_notice(self):
        result = audit.review(now=NOW, inspector=lambda doi: source(doi))
        ironman = next(x for x in result["results"] if x["doi"] == ORIGINAL)
        self.assertEqual(ironman["audit_state"],
                         "CROSSREF_PUBLISHER_DISAGREEMENT_REVIEW_REQUIRED")
        self.assertEqual(ironman["status"], "HOLD")
        self.assertEqual(ironman["crossref_notice_dois"], [])
        self.assertEqual(ironman["publisher_notice_state"],
                         "KNOWN_CORRECTION_REVIEW_REQUIRED")
        self.assertTrue(all(x["manual_review_required"] for x in result["results"]))

    def test_wrong_correction_doi_fails_to_reconcile_publisher(self):
        def inspector(doi):
            result = source(doi, with_notice=(doi == ORIGINAL))
            if doi == ORIGINAL:
                result["notices"][0]["doi"] = "10.1000/different"
            return result
        report = audit.review(now=NOW, inspector=inspector)
        ironman = next(x for x in report["results"] if x["doi"] == ORIGINAL)
        self.assertEqual(ironman["audit_state"],
                         "CROSSREF_PUBLISHER_DISAGREEMENT_REVIEW_REQUIRED")

    def test_retraction_in_other_paper_is_hold_not_ordinary_manual_review(self):
        affected = "10.1002/ejsc.70246"
        def inspector(doi):
            if doi != affected:
                return normal(doi)
            row = source(doi)
            row["status"] = "REVIEW_REQUIRED"
            row["notices"] = [{
                "doi": "10.1000/retraction-1",
                "notice_type": "RETRACTION_OR_WITHDRAWAL_NOTICE",
                "published": "2026-10-17",
                "source": "CROSSREF_REVERSE_UPDATE_METADATA",
            }]
            row["notice_codes"] = ["RETRACTION_OR_WITHDRAWAL_NOTICE"]
            return row
        r = audit.review(now=NOW, inspector=inspector)
        item = next(x for x in r["results"] if x["doi"] == affected)
        self.assertEqual(item["status"], "HOLD")
        self.assertEqual(item["audit_state"], "CROSSREF_REVIEW_REQUIRED")
        self.assertFalse(item["scientific_claims_verified"])

    def test_partial_missing_sources_do_not_stop_remaining_lookups(self):
        calls = []
        def inspector(doi):
            calls.append(doi)
            if len(calls) == 2:
                raise UpdateLookupError("update_http_unavailable")
            return normal(doi)
        r = audit.review(now=NOW, inspector=inspector)
        self.assertEqual(len(calls), 4)
        self.assertEqual(sum(x["audit_state"] == "UNKNOWN" for x in r["results"]), 1)
        self.assertTrue(all(x["status"] in ("HOLD","MANUAL_REVIEW") for x in r["results"]))
        self.assertTrue(all(x["status"] == "HOLD" for x in r["results"]
                            if x["audit_state"] == "UNKNOWN"))

    def test_invalid_upstream_metadata_never_shown_as_clean(self):
        for changed in (
            {"source": "FAKE"},
            {"doi": "10.9999/fake"},
            {"scientific_claims_verified": True},
            {"automatic_publication": True},
            {"authoritative_notice_clearance": True},
            {"manual_review_required": False},
            {"status": "SCIENTIFICALLY_APPROVED"},
            {"coverage": "AUTHORITATIVE_PUBLISHER_CLEAR"},
            {"notices": [{"doi":"10.1000/x","notice_type":"CORRECTION_NOTICE",
                          "published":"2026-10-02","source":"EVIL"}],
             "notice_codes":["CORRECTION_NOTICE"],"status":"REVIEW_REQUIRED"},
            {"notice_codes": ["RETRACTION_OR_WITHDRAWAL_NOTICE"]},
            {"coverage": "CROSSREF_FILTER_TRUNCATED", "status": "NOT_FOUND_WITH_COVERAGE"},
            {"notices": "evil"},
            {"notices": [{"doi": CORRECTION, "notice_type": "CORRECTION_NOTICE",
                          "published": "2026-02-30",
                          "source": "CROSSREF_REVERSE_UPDATE_METADATA"}]},
        ):
            with self.subTest(changed=changed):
                def inspector(doi):
                    if doi != ORIGINAL:
                        return normal(doi)
                    return {**normal(doi), **deepcopy(changed)}
                r = audit.review(now=NOW, inspector=inspector)
                item = next(x for x in r["results"] if x["doi"] == ORIGINAL)
                self.assertEqual(item["audit_state"], "UNKNOWN")
                self.assertFalse(item["scientific_claims_verified"])
                self.assertEqual(item["status"], "HOLD")

    def test_truncation_is_never_missing_updates_clearance(self):
        r = audit.review(now=NOW, inspector=lambda doi: source(
            doi, with_notice=doi == ORIGINAL, truncated=True,
        ))
        self.assertEqual(r["report_status"], "HOLD_FOR_EXPERT_REVIEW")
        self.assertTrue(all(x["audit_state"] !=
                            "NO_CROSSREF_UPDATE_FOUND_NOT_PUBLISHER_CLEARANCE"
                            for x in r["results"]))
        self.assertTrue(all(x["crossref_coverage"] == "CROSSREF_FILTER_TRUNCATED"
                            for x in r["results"]))

    def test_time_requirements(self):
        for dt in (datetime(2026,10,18), datetime(2026,10,18,tzinfo=UTC)+timedelta(days=0)):
            if dt.tzinfo is not None:
                continue
            with self.assertRaisesRegex(ValueError, "audit_time_must_be_utc"):
                audit.review(now=dt, inspector=Mock())
        from datetime import timezone
        with self.assertRaisesRegex(ValueError, "audit_time_must_be_utc"):
            audit.review(now=datetime(2026,10,18,tzinfo=timezone(timedelta(hours=3))),
                         inspector=Mock())

    def test_fixed_source_set_must_not_change(self):
        original = audit.curated_reports
        try:
            audit.curated_reports = lambda: original()[:3]
            with self.assertRaisesRegex(ValueError, "audit_fixed_sources_invalid"):
                audit.review(now=NOW, inspector=Mock())
        finally:
            audit.curated_reports = original

    def test_live_operator_cli_paces_all_four_lookups_without_retry(self):
        looked_up, pauses = [], []
        def pretend_registry(doi):
            looked_up.append(doi)
            return normal(doi)
        out = io.StringIO()
        with patch.object(audit, "inspect", side_effect=pretend_registry), \
             patch.object(audit.time, "sleep", side_effect=pauses.append), \
             patch("sys.stdout", out):
            code = audit.main(["--execute"])
        self.assertEqual(code, 0)
        self.assertEqual(len(looked_up), 4)
        self.assertEqual(len(set(looked_up)), 4)
        self.assertEqual(pauses, [audit.MIN_INTERVAL_SECONDS] * 3)
        self.assertEqual(len(json.loads(out.getvalue())["results"]), 4)

    def test_error_code_is_sanitized_but_known_429_retained(self):
        def failure(code):
            def inspector(_doi):
                raise UpdateLookupError(code)
            return audit.review(now=NOW, inspector=inspector)
        unknown = failure("secret API detail from untrusted inspector")
        self.assertTrue(all(row["status"] == "HOLD" for row in unknown["results"]))
        self.assertTrue(all(row["lookup_error_code"] == "audit_result_invalid"
                            for row in unknown["results"]))
        self.assertNotIn("secret API detail", json.dumps(unknown))
        throttled = failure("update_http_429")
        self.assertTrue(all(row["lookup_error_code"] == "update_http_429"
                            for row in throttled["results"]))
        confirmed = audit.review(now=NOW, inspector=normal)
        self.assertTrue(all(row["lookup_error_code"] is None for row in confirmed["results"]))

    def test_default_cli_is_strictly_offline(self):
        out = io.StringIO()
        with patch.object(audit, "review") as run, patch("sys.stdout", out):
            status = audit.main([])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(out.getvalue()),
                         {"status":"NOT_EXECUTED","requests_attempted":0})
        run.assert_not_called()

    def test_explicit_cli_returns_nonzero_for_unknown_and_no_secret_leaks(self):
        report = audit.review(now=NOW, inspector=lambda doi: (
            (_ for _ in ()).throw(UpdateLookupError("private secret=xyz"))
            if doi == ORIGINAL else normal(doi)))
        buf = io.StringIO()
        with patch.object(audit, "review", return_value=report), patch("sys.stdout", buf):
            self.assertEqual(audit.main(["--execute"]), 2)
        self.assertNotIn("private secret", buf.getvalue())
        self.assertTrue(all(row["lookup_error_code"] == "audit_result_invalid"
                            for row in json.loads(buf.getvalue())["results"]
                            if row["audit_state"] == "UNKNOWN"))
        self.assertTrue(json.loads(buf.getvalue())["manual_review_required"])


if __name__ == "__main__":
    unittest.main()
