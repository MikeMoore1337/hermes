"""H-24 #191 offline GSC adapter regressions: no network or credentials."""
from __future__ import annotations

import copy
import unittest

from marketing.gsc_analytics import (
    GscEvidenceError, normalize_analytics, normalize_sitemaps,
    to_h12_observations,
)


def snapshot(dimensions=None, rows=None):
    return {
        "property": "sc-domain:your-fitness-coach.ru",
        "transport": "windsor_ai",
        "period_start": "2026-10-03",
        "period_end": "2026-10-16",
        "observed_at": "2026-10-19",
        "data_latest_date": "2026-10-16",
        "search_type": "web",
        "dimensions": [] if dimensions is None else dimensions,
        "ctr_unit": "fraction",
        "rows": [{"clicks": 0, "impressions": 16, "ctr": 0, "position": 22.1875}]
                if rows is None else rows,
    }


def page_row(page="https://your-fitness-coach.ru/nutrition"):
    return {"page": page, "clicks": 0, "impressions": 3,
            "ctr": 0, "position": 15.6667}


class GscAnalyticsTests(unittest.TestCase):
    def test_site_baseline_is_not_synthetic_or_provider_attested(self):
        r = normalize_analytics(snapshot())
        self.assertEqual(r["rows"][0]["metrics"]["impressions"], 16)
        self.assertEqual(r["quality_status"], "AVAILABLE")
        self.assertEqual(r["completeness"], "PROPERTY_AGGREGATE")
        self.assertEqual(r["source"], "google_search_console")
        self.assertEqual(r["provider"], "windsor_ai")
        self.assertFalse(r["provider_attested"])
        self.assertFalse(r["hermes_runtime_source_verified"])
        self.assertFalse(r["live_api_used_by_hermes"])
        self.assertFalse(r["publication_allowed"])
        self.assertFalse(r["yfc_write_allowed"])
        self.assertEqual(len(r["evidence_sha256"]), 64)
        self.assertEqual(r, normalize_analytics(snapshot()))

    def test_page_results_are_not_site_total(self):
        rows = [page_row(), dict(page_row(), page="https://your-fitness-coach.ru/calculators/1rm",
                                 impressions=10, position=21.1)]
        r = normalize_analytics(snapshot(["page"], rows))
        self.assertEqual(r["completeness"], "PAGE_AGGREGATED_NOT_SITE_TOTAL")
        self.assertEqual(len(r["rows"]), 2)
        self.assertNotIn("site_total", r)

    def test_query_privacy_and_h12_bridge_fail_closed(self):
        s = snapshot(["query"], [{
            "query": "калькулятор на раз", "clicks": 0, "impressions": 1,
            "ctr": 0, "position": 44,
        }])
        r = normalize_analytics(s)
        self.assertEqual(r["completeness"], "QUERY_ROWS_NOT_EXHAUSTIVE")
        h12 = to_h12_observations(
            r, query="калькулятор на раз", intent="informational",
            as_of="2026-10-19")
        self.assertEqual(len(h12), 1)
        self.assertEqual(h12[0]["source"], "google_search_console")
        self.assertEqual(h12[0]["data_quality"], "OWNER_EXPORT_UNVERIFIED")
        self.assertEqual(h12[0]["metrics"]["impressions"], 1)
        self.assertEqual(to_h12_observations(r, query="недоступный запрос",
                                            intent="informational", as_of="2026-10-19"), [])

    def test_page_query_bridge(self):
        row = dict(page_row(), query="жим лежа")
        r = normalize_analytics(snapshot(["page", "query"], [row]))
        v = to_h12_observations(r, query="жим лежа", intent="informational",
                                as_of="2026-10-19")
        self.assertEqual(v[0]["page"], row["page"])
        self.assertNotIn("country", v[0])

    def test_device_and_country_are_separate(self):
        devices = normalize_analytics(snapshot(["device"], [
            {"device": "DESKTOP", "clicks": 0, "impressions": 10},
            {"device": "MOBILE", "clicks": 0, "impressions": 6},
        ]))
        self.assertEqual([r["device"] for r in devices["rows"]], ["DESKTOP", "MOBILE"])
        countries = normalize_analytics(snapshot(["country"], [
            {"country": "Russia", "clicks": 0, "impressions": 8},
        ]))
        self.assertEqual(countries["rows"][0]["country"], "Russia")
        with self.assertRaisesRegex(GscEvidenceError, "report_not_admitted"):
            to_h12_observations(countries, query="q", intent="informational",
                                as_of="2026-10-19")

    def test_date_zero_windsor_position_does_not_become_zero_ranking(self):
        r = normalize_analytics(snapshot(["date"], [
            {"date": "2026-10-12", "clicks": 0, "impressions": 0,
             "ctr": None, "position": 0},
        ]))
        self.assertEqual(r["rows"][0]["quality_status"], "NO_IMPRESSIONS")
        self.assertNotIn("average_position", r["rows"][0]["metrics"])
        self.assertNotIn("ctr", r["rows"][0]["metrics"])

    def test_absent_metrics_are_not_zero(self):
        r = normalize_analytics(snapshot(["query"], [
            {"query": "x", "impressions": 1},
        ]))
        self.assertEqual(r["rows"][0]["quality_status"], "PARTIAL_METRICS")
        self.assertNotIn("clicks", r["rows"][0]["metrics"])
        self.assertNotIn("ctr", r["rows"][0]["metrics"])
        self.assertEqual(normalize_analytics(snapshot(rows=[]))["quality_status"], "NO_DATA")

    def test_freshness_and_incomplete_dates(self):
        s = snapshot()
        s["data_latest_date"] = "2026-10-15"
        self.assertEqual(normalize_analytics(s)["quality_status"], "PARTIAL")
        s["data_latest_date"] = None
        self.assertEqual(normalize_analytics(s)["quality_status"], "LATEST_DATE_UNKNOWN")
        s["data_latest_date"] = "2026-10-03"
        self.assertEqual(normalize_analytics(s)["quality_status"], "STALE")

    def test_explicit_ctr_units(self):
        s = snapshot()
        s["rows"][0].update(clicks=1, impressions=20, ctr=5)
        s["ctr_unit"] = "percent"
        r = normalize_analytics(s)
        self.assertAlmostEqual(r["rows"][0]["metrics"]["ctr"], 0.05)
        s["ctr_unit"] = "fraction"
        with self.assertRaises(GscEvidenceError):
            normalize_analytics(s)

    def test_sitemap_and_deprecated_indexed(self):
        s = snapshot(["sitemap"], [{
            "path": "https://your-fitness-coach.ru/sitemap.xml",
            "submitted": 29, "errors": 0, "warnings": 0,
            "last_downloaded": "2026-10-16T00:32:20.695Z",
            "last_submitted": "2026-09-13T18:22:36.946Z",
            "indexed": 0,
        }, {"path": None, "submitted": 0, "errors": 0, "warnings": 0}])
        r = normalize_sitemaps(s)
        self.assertEqual(r["rows"][0]["submitted_url_count"], 29)
        self.assertEqual(len(r["rows"]), 1)
        self.assertNotIn("indexed", r["rows"][0])
        self.assertEqual(r["completeness"], "SITEMAP_DIAGNOSTICS_ONLY")
        with self.assertRaisesRegex(GscEvidenceError, "analytics_dimensions_invalid"):
            normalize_analytics(s)

    def test_sitemap_unexpected_real_placeholder_and_duplicates_denied(self):
        s = snapshot(["sitemap"], [{"path": None, "submitted": 4}])
        with self.assertRaises(GscEvidenceError):
            normalize_sitemaps(s)
        s["rows"] = [{"path": "https://your-fitness-coach.ru/sitemap.xml"}] * 2
        with self.assertRaisesRegex(GscEvidenceError, "duplicate_row"):
            normalize_sitemaps(s)

    def test_malformed_analytics_rows_fail_closed(self):
        bad = [
            {"clicks": 1, "impressions": 0},
            {"clicks": -1, "impressions": 1},
            {"clicks": True, "impressions": 1},
            {"impressions": -1},
            {"impressions": float("nan")},
            {"clicks": 0, "impressions": 4, "ctr": 0.9},
            {"clicks": 0, "impressions": 1, "position": 0},
            {"clicks": 0, "impressions": 0, "position": 5},
            {"clicks": None},
            {"clicks": 0, "impressions": 1, "secret_token": "must-not-log"},
        ]
        for row in bad:
            with self.subTest(row=str(row)), self.assertRaises(GscEvidenceError):
                normalize_analytics(snapshot(rows=[row]))

    def test_invalid_property_transport_dates_and_scope(self):
        mutations = [
            {"property": "sc-domain:another-site.com"},
            {"transport": "unapproved_source"},
            {"transport": []},
            {"search_type": []},
            {"ctr_unit": "unknown"},
            {"ctr_unit": []},
            {"period_end": "2026-10-02"},
            {"observed_at": "2026-09-01"},
            {"data_latest_date": "2026-10-20"},
            {"dimensions": ["query", "query"]},
            {"dimensions": ["impressions"]},
            {"dimensions": ["query", "device", "page", "country"]},
        ]
        for change in mutations:
            s = snapshot()
            s.update(change)
            with self.subTest(change=change), self.assertRaises(GscEvidenceError):
                normalize_analytics(s)

    def test_bad_pages_and_dimensions(self):
        for page in ("http://your-fitness-coach.ru/nutrition",
                     "https://evil.example/", "https://your-fitness-coach.ru@evil.example/",
                     "https://your-fitness-coach.ru/#fragment"):
            with self.subTest(page=page), self.assertRaises(GscEvidenceError):
                normalize_analytics(snapshot(["page"], [page_row(page)]))
        with self.assertRaisesRegex(GscEvidenceError, "dimension_missing"):
            normalize_analytics(snapshot(["query"], [{"impressions": 1}]))
        with self.assertRaisesRegex(GscEvidenceError, "duplicate_row"):
            normalize_analytics(snapshot(["query"], [
                {"query": "x", "impressions": 1},
                {"query": "x", "impressions": 2},
            ]))
        with self.assertRaisesRegex(GscEvidenceError, "site_aggregate_ambiguous"):
            normalize_analytics(snapshot(rows=[{"impressions": 1}, {"impressions": 2}]))

    def test_limits_and_redacted_errors(self):
        s = snapshot()
        s["rows"] = [{"impressions": 0}] * 1001
        with self.assertRaisesRegex(GscEvidenceError, "rows_invalid"):
            normalize_analytics(s)
        s = snapshot(["query"], [{"query": "<script>token</script>", "impressions": 1}])
        with self.assertRaises(GscEvidenceError) as cm:
            normalize_analytics(s)
        self.assertNotIn("token", str(cm.exception))
        s = snapshot(rows=[{"impressions": 0, "extra": "credential=secret"}])
        with self.assertRaises(GscEvidenceError) as cm:
            normalize_analytics(s)
        self.assertNotIn("secret", str(cm.exception))

    def test_no_fake_inspection_data(self):
        s = snapshot(rows=[{"impressions": 0, "indexed": 1}])
        with self.assertRaisesRegex(GscEvidenceError, "row_fields_invalid"):
            normalize_analytics(s)
        s = snapshot(["sitemap"], [{"path": "https://your-fitness-coach.ru/sitemap.xml",
                                     "inspection_verdict": "PASS"}])
        with self.assertRaisesRegex(GscEvidenceError, "sitemap_row_invalid"):
            normalize_sitemaps(s)


if __name__ == "__main__":
    unittest.main()
