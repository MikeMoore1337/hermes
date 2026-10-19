"""H-12 #64 offline E2E: existing Research Scout -> vendor gap -> draft."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest

from marketing.seo_research import SeoResearchDenied, build_packet, normalize_observations

QUERY = "восстановление после тренировки"


def input_packet():
    return {
        "schema": "hermes-h12-seo-offline-input-v1",
        "theme": "training_recovery",
        "selected_query": QUERY,
        "as_of": "2026-10-19",
        "research_item": {
            "topic": "recovery_training",
            "title": "Plant-Derived Whole Foods and Food-Based Supplements on Post-Exercise Recovery",
            "identifier": "42797032",
            "source_url": "https://europepmc.org/article/MED/42797032",
            "doi": "10.3390/nu18183049",
            "status": "MANUAL_REVIEW",
            "reason": "metadata_only",
            "publication_date": "2026-09-18",
            "crossref_doi_status": "NOT_CHECKED",
            "article_notice_state": "NOT_CHECKED",
            "article_notice_codes": [],
            "scientific_claims_verified": False,
        },
        "site_gap": {
            "site": "https://example.org",
            "threshold": 0.75,
            "pages": {"articles": 1, "commerce_ignored": 0, "other": 0},
            "clusters": [{
                "cluster": QUERY, "phrases": [QUERY],
                "volume": None, "covered_by": None,
                "maybe_covered": False,
                "nearest": {
                    "url": "https://example.org/training",
                    "title": "Программа тренировок",
                    "score": 0.23, "kind": "article",
                },
                "fit": 0.7, "score": 0,
            }],
            "commercial": [],
        },
        "observations": [],
    }


def mock_search():
    return {
        "source": "google_search_console",
        "source_type": "synthetic_fixture",
        "observed_at": "2026-10-18", "period_start": "2026-10-01",
        "period_end": "2026-10-18", "query": QUERY,
        "search_intent": "informational", "country": "RU", "language": "ru",
        "page": "https://example.org/training",
        "impressions": 100, "clicks": 5, "ctr": 0.05,
        "average_position": 12.4,
        "limitations": "Synthetic contract test: not real search demand",
    }


class H12OfflineResearchTests(unittest.TestCase):
    def test_full_offline_e2e_synthetic_not_real_demand(self):
        data = input_packet()
        data["observations"] = [mock_search()]
        packet = build_packet(data)
        self.assertEqual(packet["status"], "READY_FOR_REVIEW")
        self.assertEqual(packet["evidence_kind"], "SYNTHETIC_ONLY")
        self.assertEqual(packet["observations"][0]["data_quality"], "SYNTHETIC_TEST_ONLY")
        self.assertEqual(packet["research_brief"]["status"], "MANUAL_REVIEW")
        self.assertIn("europepmc.org", packet["markdown"])
        self.assertIn("H1:", packet["markdown"])
        self.assertIn("Ограничения исследования", packet["markdown"])
        self.assertFalse(packet["publication_allowed"])
        self.assertFalse(packet["yfc_write_allowed"])
        self.assertFalse(packet["outbound_messages_allowed"])
        self.assertFalse(packet["paid_api_used"])
        self.assertFalse(packet["live_api_used"])

    def test_absent_observations_are_not_zero(self):
        p = build_packet(input_packet())
        self.assertEqual(p["status"], "NO_DATA")
        self.assertEqual(p["evidence_kind"], "NO_CONFIRMED_DEMAND")
        self.assertEqual(p["observations"], [])
        self.assertIn("NO_DATA -", p["markdown"])

    def test_owner_export_never_becomes_provider_verified(self):
        data = input_packet()
        observation = mock_search()
        observation.update(source_type="owner_export", evidence_sha256="a" * 64,
                           owner_attested=True)
        data["observations"] = [observation]
        result = build_packet(data)
        self.assertEqual(result["status"], "READY_FOR_REVIEW")
        self.assertEqual(result["evidence_kind"], "OWNER_ATTESTED_NOT_PROVIDER_VERIFIED")

    def test_unattested_export_is_not_evidence(self):
        data = input_packet()
        item = mock_search()
        item.update(source_type="owner_export", evidence_sha256="a" * 64)
        data["observations"] = [item]
        self.assertEqual(build_packet(data)["status"], "NO_DATA")

    def test_stale_demand_is_no_data(self):
        data = input_packet()
        item = mock_search()
        item.update(period_end="2026-05-01", observed_at="2026-05-02",
                    period_start="2026-04-01")
        data["observations"] = [item]
        self.assertEqual(build_packet(data)["status"], "NO_DATA")
        self.assertTrue(build_packet(data)["observations"][0]["stale"])

    def test_scientific_hold_cannot_be_promoted(self):
        data = input_packet()
        data["research_item"]["status"] = "HOLD"
        data["observations"] = [mock_search()]
        p = build_packet(data)
        self.assertEqual(p["status"], "HOLD")
        self.assertIn("SCIENTIFIC_HOLD", p["reasons"])

    def test_existing_or_nearby_page_is_not_a_new_article(self):
        data = input_packet()
        data["observations"] = [mock_search()]
        cluster = data["site_gap"]["clusters"][0]
        cluster["covered_by"] = "https://example.org/training"
        self.assertEqual(build_packet(data)["status"], "HOLD")
        cluster["covered_by"] = None
        cluster["maybe_covered"] = True
        self.assertEqual(build_packet(data)["status"], "HOLD")

    def test_same_source_duplicate_and_repeated_job(self):
        data = input_packet()
        item = mock_search()
        data["observations"] = [item, copy.deepcopy(item)]
        with self.assertRaisesRegex(SeoResearchDenied, "duplicate_observation"):
            build_packet(data)
        data["observations"] = [item]
        self.assertEqual(build_packet(data), build_packet(data))

    def test_different_source_metrics_are_not_aggregated(self):
        data = input_packet()
        wordstat = {
            "source": "yandex_wordstat", "source_type": "synthetic_fixture",
            "observed_at": "2026-10-18", "period_start": "2026-10-01",
            "period_end": "2026-10-18", "query": QUERY,
            "search_intent": "informational", "country": "RU",
            "search_volume": 31, "limitations": "Synthetic Wordstat count",
        }
        data["observations"] = [mock_search(), wordstat]
        p = build_packet(data)
        self.assertEqual(len(p["observations"]), 2)
        self.assertFalse(p["search_metrics_combined"])
        self.assertNotIn("search_volume", p["observations"][0]["metrics"])
        self.assertNotIn("impressions", p["observations"][1]["metrics"])

    def test_conflicting_search_intent_requires_hold(self):
        data = input_packet()
        other = dict(mock_search())
        other.update(source="yandex_webmaster", search_intent="commercial")
        data["observations"] = [mock_search(), other]
        self.assertEqual(build_packet(data)["status"], "HOLD")

    def test_unknown_source_and_paid_fallback_denied(self):
        for mutation in (
            {"source": "unknown"},
            {"source": "paid_seo_api"},
            {"paid_api_fallback": True},
            {"search_volume": 1000000},
            {"competition": 0.8},
        ):
            data = input_packet()
            item = mock_search()
            item.update(mutation)
            data["observations"] = [item]
            with self.subTest(mutation=mutation), self.assertRaises(SeoResearchDenied):
                build_packet(data)

    def test_invalid_canonical_region_and_date(self):
        for change in (
            {"page": "http://127.0.0.1/admin"},
            {"country": "??"},
            {"period_start": "2026-12-01"},
            {"observed_at": "2026-11-01"},
        ):
            data = input_packet()
            item = mock_search()
            item.update(change)
            data["observations"] = [item]
            with self.subTest(change=change), self.assertRaises(SeoResearchDenied):
                build_packet(data)

    def test_numeric_validation(self):
        for change in (
            {"impressions": True},
            {"impressions": -1},
            {"impressions": float("nan")},
            {"clicks": 101},
            {"ctr": 2},
            {"average_position": 0},
        ):
            data = input_packet()
            item = mock_search()
            item.update(change)
            data["observations"] = [item]
            with self.subTest(change=change), self.assertRaises(SeoResearchDenied):
                build_packet(data)

    def test_false_wordstat_frequencies_from_gap_denied(self):
        data = input_packet()
        data["site_gap"]["clusters"][0]["volume"] = 998
        with self.assertRaisesRegex(SeoResearchDenied, "gap_unverified_volume_denied"):
            build_packet(data)

    def test_deduplicated_cluster(self):
        data = input_packet()
        data["site_gap"]["clusters"].append(copy.deepcopy(data["site_gap"]["clusters"][0]))
        with self.assertRaises(SeoResearchDenied):
            build_packet(data)

    def test_html_injection_and_publish_claims_denied(self):
        data = input_packet()
        data["selected_query"] = "<script>publish('yes')</script>"
        with self.assertRaises(SeoResearchDenied):
            build_packet(data)
        data = input_packet()
        data["publication_allowed"] = True
        with self.assertRaises(SeoResearchDenied):
            build_packet(data)
        data = input_packet()
        data["research_item"]["scientific_claims_verified"] = True
        with self.assertRaises(SeoResearchDenied):
            build_packet(data)

    def test_cli_json_and_markdown_without_external_access(self):
        data = input_packet()
        data["observations"] = [mock_search()]
        for fmt in ("json", "markdown"):
            p = subprocess.run(
                [sys.executable, "-m", "scripts.hermes_seo_research",
                 "--format", fmt],
                input=json.dumps(data, ensure_ascii=False).encode("utf-8"),
                capture_output=True, timeout=15, check=False,
            )
            self.assertEqual(p.returncode, 0, p.stderr)
            if fmt == "json":
                self.assertEqual(json.loads(p.stdout)["status"], "READY_FOR_REVIEW")
            else:
                self.assertIn("YFC owner READY", p.stdout.decode("utf-8"))

    def test_cli_refuses_oversized_or_malformed_input(self):
        for raw in (b" " * 262145, b"not-json"):
            p = subprocess.run(
                [sys.executable, "-m", "scripts.hermes_seo_research"],
                input=raw, capture_output=True, timeout=15, check=False,
            )
            self.assertEqual(p.returncode, 2)
            self.assertEqual(json.loads(p.stdout)["status"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
