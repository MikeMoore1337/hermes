"""Hermes #397: synthetic official Yandex.Webmaster v4 JSON. No live access."""
from __future__ import annotations

from datetime import date
import copy
import json
import unittest

from marketing.yandex_webmaster import (
    WebmasterDenied, read_plan, normalize_export, classify_http_status, INPUT_SCHEMA, HOST,
)

DAY = date(2026, 10, 23)


def fixture():
    return {
        "schema": INPUT_SCHEMA, "source_type": "synthetic_fixture",
        "owner_attested": False, "host_id": HOST,
        "observed_at": "2026-10-20", "period_start": "2026-10-01",
        "period_end": "2026-10-19", "device": "ALL",
        "search_intent": "informational",
        "popular": {
            "queries": [
                {"query_id": "a08b", "query_text": "восстановление после тренировки",
                 "indicators": {
                     "TOTAL_SHOWS": 100.0, "TOTAL_CLICKS": 5.0,
                     "AVG_SHOW_POSITION": 14.5,
                 }},
            ],
            "date_from": "2026-10-01", "date_to": "2026-10-19",
            "count": "2",
        },
        "all_history": {
            "indicators": {
                "TOTAL_SHOWS": [
                    {"date": "2026-10-17T00:00:00.000+03:00", "value": 21.0},
                    {"date": "2026-10-18T00:00:00.000+03:00", "value": 26.0},
                ],
                "TOTAL_CLICKS": [
                    {"date": "2026-10-17T00:00:00.000+03:00", "value": 1.0},
                ],
            },
        },
        "index_history": {
            "indicators": {
                "HTTP_2XX": [
                    {"date": "2026-10-18T00:00:00,000+0300", "value": 29},
                ],
                "HTTP_4XX": [],
            },
        },
        "sitemaps": {"sitemaps": [
            {"sitemap_id": "c7-fe:80-c0", "sitemap_url": "https://your-fitness-coach.ru/sitemap.xml",
             "last_access_date": "2026-10-19T00:00:00,000+0300",
             "errors_count": 0, "urls_count": 29, "children_count": 0,
             "sources": ["ROBOTS_TXT"], "sitemap_type": "SITEMAP"},
        ]},
    }


class YandexWebmasterOfflineTests(unittest.TestCase):
    def test_get_plan_exact_readonly_six_calls(self):
        p = read_plan(user_id=123, host_id=HOST, start="2026-10-01", end="2026-10-19")
        self.assertEqual(6, p["max_requests"])
        self.assertEqual(0, p["network_calls"])
        self.assertFalse(p["mutations_allowed"])
        self.assertEqual("webmaster:hostinfo", p["required_oauth_scope"])
        self.assertTrue(all(x["method"] == "GET" for x in p["requests"]))
        self.assertTrue(all(x["url"].startswith("https://api.webmaster.yandex.net/v4/")
                            for x in p["requests"]))
        self.assertIn("order_by=TOTAL_SHOWS", p["requests"][2]["url"])
        self.assertIn("limit=50", p["requests"][2]["url"])
        self.assertIn("query_indicator=TOTAL_CLICKS", p["requests"][2]["url"])
        self.assertIn("query_indicator=AVG_SHOW_POSITION", p["requests"][3]["url"])
        self.assertNotIn("wordstat", json.dumps(p).lower())
        self.assertNotIn("recrawl", json.dumps(p).lower())
        self.assertNotIn("Bearer", json.dumps(p))

    def test_get_plan_fails_closed_on_host_user_date_device(self):
        for patch in (
            {"user_id": 0}, {"user_id": True}, {"host_id": "https:evil.net:443"},
            {"host_id": "http:your-fitness-coach.ru:80"}, {"device": "ANY"},
            {"start": "2026-10-20", "end": "2026-10-01"},
            {"start": "2026-09-01", "end": "2026-10-20"},
            {"start": "2026-02-30"},
        ):
            with self.subTest(patch=patch):
                params = {"user_id": 123, "host_id": HOST,
                          "start": "2026-10-01", "end": "2026-10-19"}
                params.update(patch)
                with self.assertRaises(WebmasterDenied):
                    read_plan(**params)

    def test_popular_real_shape_converts_to_existing_h12_research_contract(self):
        r = normalize_export(fixture(), as_of=DAY)
        self.assertEqual("OFFLINE_SOURCE_NOT_PROVIDER_VERIFIED", r["status"])
        self.assertEqual("yandex_webmaster", r["source"])
        self.assertEqual(1, len(r["seo_research_observations"]))
        o = r["seo_research_observations"][0]
        self.assertEqual("SYNTHETIC_TEST_ONLY", o["data_quality"])
        self.assertEqual(100, o["metrics"]["impressions"])
        self.assertEqual(5, o["metrics"]["clicks"])
        self.assertEqual(0.05, o["metrics"]["ctr"])
        self.assertEqual(14.5, o["metrics"]["average_position"])
        self.assertNotIn("page", o)
        self.assertNotIn("country", o)
        self.assertFalse(r["search_metrics_combined"])
        self.assertFalse(r["publication_allowed"])

    def test_provider_popular_period_accepts_offset_aware_datetimes(self):
        for start, end in (
            ("2026-10-01T00:00:00.000+03:00", "2026-10-19T00:00:00,000+0300"),
            ("2026-10-01T00:00:00Z", "2026-10-19T00:00:00+00:00"),
        ):
            with self.subTest(start=start, end=end):
                sample = fixture()
                sample["popular"]["date_from"] = start
                sample["popular"]["date_to"] = end
                report = normalize_export(sample, as_of=DAY)
                self.assertEqual("2026-10-01", report["popular_coverage"]["period_start"])
                self.assertEqual("2026-10-19", report["popular_coverage"]["period_end"])
                self.assertEqual("OFFLINE_SOURCE_NOT_PROVIDER_VERIFIED", report["status"])

    def test_provider_popular_period_rejects_ambiguous_dates(self):
        for value in (
            "2026-10-01T00:00:00", "2026-10-01T25:00:00+03:00",
            "2026-10-01T00:00:00+99:00", "2026-10-01T00:00:00+03:00junk",
            "2026-13-01", "2026-10-01 00:00:00+03:00",
        ):
            with self.subTest(value=value):
                sample = fixture()
                sample["popular"]["date_from"] = value
                with self.assertRaises(WebmasterDenied):
                    normalize_export(sample, as_of=DAY)

    def test_section_diagnostic_safe_fixed_reason_and_default_unchanged(self):
        from marketing.yandex_webmaster import (
            WebmasterContractDiagnosticDenied,
        )
        for section, corrupt in (
            ("POPULAR_DATA", lambda p: p["popular"].update(count="invalid")),
            ("ALL_HISTORY_DATA", lambda p: p["all_history"].update(indicators=[])),
            ("INDEXING_DATA", lambda p: p["index_history"].update(indicators=[])),
            ("SITEMAPS_DATA", lambda p: p["sitemaps"].update(sitemaps="invalid")),
        ):
            with self.subTest(section=section):
                sample = fixture()
                corrupt(sample)
                with self.assertRaises(WebmasterDenied) as original:
                    normalize_export(sample, as_of=DAY)
                self.assertNotIsInstance(
                    original.exception, WebmasterContractDiagnosticDenied,
                )
                with self.assertRaises(WebmasterContractDiagnosticDenied) as diag:
                    normalize_export(sample, as_of=DAY, diagnostic=True)
                self.assertEqual(section, diag.exception.section)
                self.assertNotIn("secret", str(diag.exception))
                self.assertNotIn("восстановление", str(diag.exception))

    def test_site_history_indexing_and_sitemaps_stay_separate(self):
        r = normalize_export(fixture(), as_of=DAY)
        self.assertEqual(21, r["site_history"]["TOTAL_SHOWS"][0]["value"])
        self.assertEqual(29, r["indexing_http_status_history"]["HTTP_2XX"][0]["value"])
        self.assertFalse(r["indexing_is_search_visibility"])
        self.assertEqual(0, r["sitemaps"][0]["errors"])
        self.assertEqual(29, r["sitemaps"][0]["urls"])
        self.assertFalse(r["page_metrics_available"])
        self.assertFalse(r["region_metrics_available"])

    def test_owner_export_requires_explicit_attestation_and_never_provider_verified(self):
        sample = fixture()
        sample["source_type"] = "owner_export"
        r = normalize_export(sample, as_of=DAY)
        self.assertEqual("OWNER_EXPORT_UNVERIFIED", r["seo_research_observations"][0]["data_quality"])
        sample["owner_attested"] = True
        r = normalize_export(sample, as_of=DAY)
        self.assertEqual("OWNER_ATTESTED_NOT_PROVIDER_VERIFIED",
                         r["seo_research_observations"][0]["data_quality"])
        self.assertFalse(r["authorization_verified"])
        self.assertFalse(r["live_api_used"])
        self.assertEqual(0, r["network_calls"])
        self.assertEqual(64, len(r["evidence_sha256"]))

    def test_missing_source_sections_are_unknown_not_zero(self):
        sample = fixture()
        sample.update(popular=None, all_history=None, index_history=None, sitemaps=None)
        result = normalize_export(sample, as_of=DAY)
        self.assertIsNone(result["popular_coverage"])
        self.assertIsNone(result["site_history"])
        self.assertIsNone(result["indexing_http_status_history"])
        self.assertIsNone(result["sitemaps"])
        self.assertEqual([], result["seo_research_observations"])

    def test_partial_query_coverage_not_counted_as_full_demand(self):
        r = normalize_export(fixture(), as_of=DAY)
        self.assertEqual(2, r["popular_coverage"]["available_query_count"])
        self.assertEqual(1, r["popular_coverage"]["returned_rows"])
        self.assertTrue(r["popular_coverage"]["truncated"])
        self.assertEqual("ALL", r["device"])

    def test_optional_metric_is_missing_not_zero(self):
        sample = fixture()
        sample["popular"]["queries"][0]["indicators"] = {"TOTAL_SHOWS": 9.0}
        r = normalize_export(sample, as_of=DAY)
        metrics = r["seo_research_observations"][0]["metrics"]
        self.assertEqual(9, metrics["impressions"])
        self.assertNotIn("ctr", metrics)
        self.assertNotIn("clicks", metrics)
        self.assertNotIn("average_position", metrics)

    def test_zero_impressions_does_not_invent_ctr_zero(self):
        sample = fixture()
        sample["popular"]["queries"][0]["indicators"] = {
            "TOTAL_SHOWS": 0.0, "TOTAL_CLICKS": 0.0}
        metrics = normalize_export(sample, as_of=DAY)["seo_research_observations"][0]["metrics"]
        self.assertEqual(0, metrics["impressions"])
        self.assertEqual(0, metrics["clicks"])
        self.assertNotIn("ctr", metrics)

    def test_absent_vs_actual_zero_and_staleness(self):
        sample = fixture()
        sample["popular"]["queries"] = []
        sample["popular"]["count"] = "0"
        r = normalize_export(sample, as_of=DAY)
        self.assertEqual([], r["seo_research_observations"])
        older = fixture()
        older["popular"]["date_from"] = "2026-07-01"
        older["popular"]["date_to"] = "2026-07-10"
        older["period_start"] = "2026-07-01"
        older["period_end"] = "2026-07-10"
        older["observed_at"] = "2026-07-12"
        older["all_history"] = None
        older["index_history"] = None
        older["sitemaps"] = None
        stale = normalize_export(older, as_of=DAY)
        self.assertTrue(stale["seo_research_observations"][0]["stale"])

    def test_fractional_counts_and_inconsistent_clicks_rejected(self):
        for metrics in (
            {"TOTAL_SHOWS": 1.1},
            {"TOTAL_SHOWS": -1},
            {"TOTAL_SHOWS": True},
            {"TOTAL_SHOWS": float("nan")},
            {"TOTAL_SHOWS": 2, "TOTAL_CLICKS": 3},
            {"AVG_SHOW_POSITION": 0},
        ):
            with self.subTest(metrics=metrics):
                sample = fixture()
                sample["popular"]["queries"][0]["indicators"] = metrics
                with self.assertRaises(WebmasterDenied):
                    normalize_export(sample, as_of=DAY)

    def test_unknown_export_fields_and_poison_payload_refused(self):
        for mutation in (
            {"authorization": "Bearer super-secret"},
            {"source_type": "provider_verified"},
            {"host_id": "https:another-site.ru:443"},
            {"device": "MOBILE_5G"},
            {"search_intent": "automated_publish"},
            {"owner_attested": "true"},
        ):
            with self.subTest(mutation=mutation):
                sample = fixture()
                sample.update(mutation)
                with self.assertRaises(WebmasterDenied):
                    normalize_export(sample, as_of=DAY)

    def test_query_injection_rejected_by_existing_h12_validator(self):
        sample = fixture()
        sample["popular"]["queries"][0]["query_text"] = "восстановление <script>"
        with self.assertRaisesRegex(WebmasterDenied, "seo_packet_denied"):
            normalize_export(sample, as_of=DAY)

    def test_duplicate_query_id_and_context_rejected(self):
        sample = fixture()
        sample["popular"]["queries"].append(copy.deepcopy(sample["popular"]["queries"][0]))
        sample["popular"]["count"] = "2"
        with self.assertRaises(WebmasterDenied):
            normalize_export(sample, as_of=DAY)
        sample = fixture()
        sample["popular"]["date_to"] = "2026-12-01"
        with self.assertRaises(WebmasterDenied):
            normalize_export(sample, as_of=DAY)

    def test_unverified_sites_do_not_automatically_create_success(self):
        sample = fixture()
        sample["popular"] = None
        sample["owner_attested"] = True
        with self.assertRaises(WebmasterDenied):
            normalize_export(sample, as_of=DAY)
        sample["owner_attested"] = False
        r = normalize_export(sample, as_of=DAY)
        self.assertFalse(r["authorization_verified"])

    def test_http_statuses_are_denials_not_zero_and_never_retry(self):
        expected = {200: "RESPONSE_REQUIRES_VALIDATION",
                    401: "AUTH_REQUIRED", 403: "ACCESS_DENIED",
                    404: "HOST_NOT_VERIFIED_OR_UNAVAILABLE",
                    429: "RATE_LIMITED", 500: "UPSTREAM_UNAVAILABLE",
                    503: "UPSTREAM_UNAVAILABLE"}
        for code, status in expected.items():
            with self.subTest(code=code):
                result = classify_http_status(code)
                self.assertEqual(status, result["status"])
                self.assertEqual(0, result["retries"])
                self.assertFalse(result["fallback_paid"])
                self.assertFalse(result["live_api_verified"])
        for bad in (True, "429", None, -1, 999):
            with self.assertRaises(WebmasterDenied):
                classify_http_status(bad)

    def test_h12_market_research_packet_reuses_existing_contract(self):
        from marketing.seo_research import build_packet
        source = normalize_export(fixture(), as_of=DAY)
        selected = "восстановление после тренировки"
        result = build_packet({
            "schema": "hermes-h12-seo-offline-input-v1",
            "theme": "market_research",
            "selected_query": selected,
            "as_of": "2026-10-23",
            "research_item": None,
            "site_gap": {
                "site": "https://your-fitness-coach.ru",
                "clusters": [{
                    "cluster": selected, "phrases": [selected],
                    "volume": None, "covered_by": None,
                    "maybe_covered": False, "nearest": None,
                }],
            },
            "observations": source["seo_research_input_observations"],
        })
        self.assertEqual(1, len(source["seo_research_observations"]))
        self.assertEqual(1, len(result["observations"]))
        self.assertEqual("yandex_webmaster", result["observations"][0]["source"])
        self.assertEqual("SYNTHETIC_ONLY", result["evidence_kind"])
        self.assertFalse(result["publication_allowed"])
        self.assertFalse(result["search_metrics_combined"])
        self.assertFalse(result["live_api_used"])

    def test_clicks_without_impressions_not_interpreted_as_zero_impressions(self):
        sample = fixture()
        sample["popular"]["queries"][0]["indicators"] = {"TOTAL_CLICKS": 5}
        report = normalize_export(sample, as_of=DAY)
        self.assertEqual([], report["seo_research_observations"])
        self.assertEqual(1, report["popular_coverage"]["returned_rows"])

    def test_huge_numeric_counter_fails_closed_without_overflow(self):
        sample = fixture()
        sample["popular"]["queries"][0]["indicators"]["TOTAL_SHOWS"] = 10**1000
        with self.assertRaises(WebmasterDenied):
            normalize_export(sample, as_of=DAY)

    def test_no_page_or_region_inference_and_no_wordstat_mixing(self):
        r = normalize_export(fixture(), as_of=DAY)
        self.assertNotIn("wordstat", json.dumps(r))
        self.assertNotIn("google_search_console", json.dumps(r))
        self.assertNotIn("search_volume", json.dumps(r))
        self.assertFalse(r["paid_api_used"])

    def test_invalid_series_duplicate_dates_and_unknown_status_refused(self):
        sample = fixture()
        sample["index_history"]["indicators"]["HTTP_2XX"].append(
            copy.deepcopy(sample["index_history"]["indicators"]["HTTP_2XX"][0]))
        with self.assertRaises(WebmasterDenied):
            normalize_export(sample, as_of=DAY)
        sample = fixture()
        sample["index_history"]["indicators"]["HTTP_599"] = []
        with self.assertRaises(WebmasterDenied):
            normalize_export(sample, as_of=DAY)
        sample = fixture()
        sample["all_history"]["indicators"]["TOTAL_SHOWS"][0]["value"] = -1
        with self.assertRaises(WebmasterDenied):
            normalize_export(sample, as_of=DAY)

    def test_optional_sitemap_last_access_date_remains_unknown(self):
        for present in (False, True):
            with self.subTest(present=present):
                sample = fixture()
                item = sample["sitemaps"]["sitemaps"][0]
                if present:
                    item["last_access_date"] = None
                else:
                    del item["last_access_date"]
                report = normalize_export(sample, as_of=DAY)
                self.assertIsNone(report["sitemaps"][0]["last_access_date"])
                self.assertEqual(0, report["sitemaps"][0]["errors"])
                self.assertFalse(report["publication_allowed"])

    def test_optional_sitemap_date_rejects_bad_values_and_extra_fields(self):
        for change in (
            lambda row: row.update(last_access_date="bad-date"),
            lambda row: row.update(last_access_date="2026-11-01T00:00:00+03:00"),
            lambda row: row.update(raw_response="secrets"),
        ):
            sample = fixture()
            change(sample["sitemaps"]["sitemaps"][0])
            with self.assertRaises(WebmasterDenied):
                normalize_export(sample, as_of=DAY)

    def test_untrusted_sitemap_redirects_or_credentials_refused(self):
        for url in (
            "http://your-fitness-coach.ru/sitemap.xml",
            "https://evil.example/sitemap.xml",
            "https://user:password@your-fitness-coach.ru/sitemap.xml",
            "https://your-fitness-coach.ru/sitemap.xml?key=secret",
        ):
            with self.subTest(url=url):
                sample = fixture()
                sample["sitemaps"]["sitemaps"][0]["sitemap_url"] = url
                with self.assertRaises(WebmasterDenied):
                    normalize_export(sample, as_of=DAY)

    def test_deterministic_snapshot_and_no_side_effects(self):
        sample = fixture()
        orig = copy.deepcopy(sample)
        result = normalize_export(sample, as_of=DAY)
        self.assertEqual(orig, sample)
        self.assertEqual(result, normalize_export(sample, as_of=DAY))
        self.assertFalse(result["mutations_allowed"])
        self.assertEqual(0, result["network_calls"])
        self.assertFalse(result["publication_allowed"])


if __name__ == "__main__":
    unittest.main()
