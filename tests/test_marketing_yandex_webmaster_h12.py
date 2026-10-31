"""Hermes #397 -> #64: synthetic, in-memory only; never call live Yandex."""
from __future__ import annotations

import copy
import json
import unittest
from datetime import date
from unittest.mock import patch

from marketing.yandex_webmaster_direct import collect
from marketing.yandex_webmaster_h12 import (
    YandexH12Denied, build_h12_handoff, summarized_h12_handoff,
    build_h12_observed_batch, summarized_h12_batch,
)
from tests.test_marketing_yandex_webmaster_direct import AS_OF, TOKEN, mocked_sequence

QUERY = "восстановление после тренировки"


def site_gap(query=QUERY):
    # Synthetic Statejnik-shape gap; never assert it reflects actual YFC pages.
    return {
        "site": "https://your-fitness-coach.ru",
        "threshold": 0.75,
        "pages": {"articles": 0},
        "clusters": [{
            "cluster": query,
            "phrases": [query],
            "volume": None,
            "covered_by": None,
            "maybe_covered": False,
            "nearest": None,
        }],
        "commercial": [],
    }


def synthetic_read():
    sender, calls = mocked_sequence()
    result = collect(as_of=AS_OF, token=TOKEN, transport=sender)
    assert len(calls) == 6
    return result


class YandexWebmasterH12Tests(unittest.TestCase):
    def test_real_h12_packet_contract_from_synthetic_yandex_report(self):
        report = synthetic_read()
        gap = site_gap()
        original_report = copy.deepcopy(report)
        original_gap = copy.deepcopy(gap)
        with patch("marketing.yandex_webmaster_direct._transport",
                   side_effect=AssertionError("handoff must be offline")):
            handoff = build_h12_handoff(
                report, as_of=AS_OF, selected_query=QUERY, site_gap=gap,
            )
        packet = handoff["packet"]
        self.assertEqual("hermes-h12-seo-research-packet-v1", packet["schema"])
        self.assertEqual("NO_DATA", packet["status"])
        self.assertIn("NO_FRESH_ATTESTED_SEARCH_DEMAND", packet["reasons"])
        self.assertEqual("NO_CONFIRMED_DEMAND", packet["evidence_kind"])
        self.assertEqual(1, len(packet["observations"]))
        observation = packet["observations"][0]
        self.assertEqual("yandex_webmaster", observation["source"])
        self.assertEqual("OWNER_EXPORT_UNVERIFIED", observation["data_quality"])
        self.assertEqual(100, observation["metrics"]["impressions"])
        self.assertEqual(5, observation["metrics"]["clicks"])
        self.assertFalse(packet["publication_allowed"])
        self.assertFalse(packet["yfc_write_allowed"])
        self.assertFalse(packet["outbound_messages_allowed"])
        self.assertFalse(handoff["publication_allowed"])
        self.assertEqual(0, handoff["provider_gets_during_handoff"])
        self.assertEqual(0, handoff["filesystem_writes"])
        self.assertEqual(original_report, report)
        self.assertEqual(original_gap, gap)

    def test_summarized_handoff_contains_no_raw_queries_or_metrics(self):
        handoff = build_h12_handoff(
            synthetic_read(), as_of=AS_OF,
            selected_query=QUERY, site_gap=site_gap(),
        )
        receipt = summarized_h12_handoff(handoff)
        output = json.dumps(receipt, ensure_ascii=False)
        self.assertEqual("IN_MEMORY_H12_PACKET_UNATTESTED", receipt["status"])
        self.assertEqual("NO_DATA", receipt["packet_status"])
        self.assertEqual(1, receipt["matching_observation_count"])
        self.assertEqual("SYNTHETIC_TRANSPORT_CHECK", receipt["source_transport"])
        self.assertEqual("OFFLINE_SOURCE_NOT_PROVIDER_VERIFIED",
                         receipt["source_provenance"])
        for private in (QUERY, TOKEN, "100", "14.5", "https://your-fitness-coach"):
            self.assertNotIn(private, output)

    def test_handoff_never_upgrades_successful_get_to_verified_demand(self):
        report = synthetic_read()
        report["status"] = "LIVE_GET_RESPONSE_UNATTESTED"
        handoff = build_h12_handoff(
            report, as_of=AS_OF, selected_query=QUERY, site_gap=site_gap(),
        )
        packet = handoff["packet"]
        self.assertEqual("LIVE_GET_RESPONSE_UNATTESTED",
                         handoff["transport_status"])
        self.assertEqual("NO_CONFIRMED_DEMAND", packet["evidence_kind"])
        self.assertEqual("NO_DATA", packet["status"])
        self.assertFalse(packet["publication_allowed"])

    def test_bulk_h12_gapless_uses_only_observed_queries_in_memory(self):
        original = synthetic_read()
        original_copy = copy.deepcopy(original)
        with patch("marketing.yandex_webmaster_direct._transport",
                   side_effect=AssertionError("handoff never makes HTTP")):
            batch = build_h12_observed_batch(original, as_of=AS_OF)
        receipt = summarized_h12_batch(batch)
        self.assertEqual("IN_MEMORY_H12_BATCH_UNATTESTED", receipt["status"])
        self.assertEqual("SYNTHETIC_TRANSPORT_CHECK", receipt["source_transport"])
        self.assertEqual(1, receipt["h12_packet_count"])
        self.assertEqual(1, receipt["h12_observation_count"])
        self.assertFalse(receipt["site_gap_assessed"])
        self.assertEqual("NO_DATA", receipt["h12_packet_status"])
        self.assertEqual("NO_CONFIRMED_DEMAND", receipt["h12_evidence_kind"])
        self.assertEqual(0, receipt["provider_gets_during_handoff"])
        self.assertEqual(0, receipt["filesystem_writes"])
        self.assertFalse(receipt["publication_allowed"])
        self.assertEqual(original_copy, original)
        packet = batch["handoffs"][0]["packet"]
        self.assertEqual(QUERY, packet["selected_query"])
        self.assertIsNone(packet["site_gap"])
        self.assertIn("SITE_GAP_NOT_ASSESSED", packet["reasons"])
        self.assertEqual("OWNER_EXPORT_UNVERIFIED",
                         packet["observations"][0]["data_quality"])
        self.assertNotIn(QUERY, json.dumps(receipt, ensure_ascii=False))
        self.assertNotIn(TOKEN, json.dumps(receipt, ensure_ascii=False))

    def test_gapless_batch_cannot_claim_provider_attestation(self):
        report = synthetic_read()
        report["status"] = "LIVE_GET_RESPONSE_UNATTESTED"
        batch = build_h12_observed_batch(report, as_of=AS_OF)
        receipt = summarized_h12_batch(batch)
        self.assertEqual("LIVE_GET_RESPONSE_UNATTESTED", receipt["source_transport"])
        self.assertEqual("NO_CONFIRMED_DEMAND", receipt["h12_evidence_kind"])
        self.assertEqual("NO_DATA", receipt["h12_packet_status"])

    def test_gapless_batch_refuses_missing_or_untrusted_queries(self):
        report = synthetic_read()
        report["data"]["seo_research_input_observations"] = []
        with self.assertRaisesRegex(YandexH12Denied, "^H12_NO_OBSERVED_QUERIES$"):
            build_h12_observed_batch(report, as_of=AS_OF)
        report = synthetic_read()
        report["data"]["seo_research_input_observations"][0]["query"] = "X<secret"
        with self.assertRaisesRegex(YandexH12Denied, "^H12_PACKET_REJECTED$"):
            build_h12_observed_batch(report, as_of=AS_OF)

    def test_gapless_single_handoff_refuses_unobserved_query(self):
        with self.assertRaisesRegex(YandexH12Denied, "^H12_QUERY_NOT_OBSERVED$"):
            build_h12_handoff(
                synthetic_read(), as_of=AS_OF,
                selected_query="not present", site_gap=None,
            )

    def test_gapless_batch_summary_refuses_privilege_tampering(self):
        batch = build_h12_observed_batch(synthetic_read(), as_of=AS_OF)
        for key, invalid in (
            ("publication_allowed", True),
            ("source_provenance", "PROVIDER_VERIFIED"),
            ("filesystem_writes", 1),
            ("site_gap_assessed", True),
            ("status", "PRIVILEGE_UPGRADED"),
        ):
            with self.subTest(key=key):
                damaged = copy.deepcopy(batch)
                damaged[key] = invalid
                with self.assertRaises(YandexH12Denied):
                    summarized_h12_batch(damaged)

    def test_unknown_query_remains_no_data_and_does_not_invent_demand(self):
        other = "несуществующий запрос"
        handoff = build_h12_handoff(
            synthetic_read(), as_of=AS_OF,
            selected_query=other, site_gap=site_gap(query=other),
        )
        self.assertEqual([], handoff["packet"]["observations"])
        self.assertEqual("NO_DATA", handoff["packet"]["status"])
        self.assertEqual(0, summarized_h12_handoff(handoff)["matching_observation_count"])

    def test_invalid_read_result_is_refused_without_network(self):
        scenarios = (
            ("schema", "bad"),
            ("status", "PROVIDER_VERIFIED"),
            ("host_id", "http:other.example:80"),
            ("source", "google_search_console"),
            ("requests", 2),
            ("retries", 1),
            ("external_publication_allowed", True),
            ("paid_api_allowed", True),
            ("seo_changes_applied", 1),
        )
        report = synthetic_read()
        for field, invalid in scenarios:
            with self.subTest(field=field):
                malicious = copy.deepcopy(report)
                malicious[field] = invalid
                with patch("marketing.yandex_webmaster_direct._transport",
                           side_effect=AssertionError("offline")):
                    with self.assertRaisesRegex(YandexH12Denied, "^H12_READ_EVIDENCE_INVALID$"):
                        build_h12_handoff(
                            malicious, as_of=AS_OF,
                            selected_query=QUERY, site_gap=site_gap(),
                        )

    def test_provenance_spoofing_and_inconsistent_dates_refused(self):
        report = synthetic_read()
        for field, bad in (
            ("source_type", "synthetic_fixture"),
            ("owner_attested", True),
            ("authorization_verified", True),
            ("publication_allowed", True),
            ("status", "PROVIDER_VERIFIED"),
            ("requested_period", ["2026-01-01", "2026-01-30"]),
        ):
            with self.subTest(field=field):
                attempt = copy.deepcopy(report)
                attempt["data"][field] = bad
                with self.assertRaisesRegex(YandexH12Denied, "^H12_PROVENANCE_INVALID$"):
                    build_h12_handoff(
                        attempt, as_of=AS_OF, selected_query=QUERY,
                        site_gap=site_gap(),
                    )
        with self.assertRaisesRegex(YandexH12Denied, "^H12_PROVENANCE_INVALID$"):
            build_h12_handoff(
                report, as_of=date(2026, 10, 24),
                selected_query=QUERY, site_gap=site_gap(),
            )

    def test_bad_observation_digest_or_fake_owner_attestation_refused(self):
        report = synthetic_read()
        for key, value in (
            ("owner_attested", True),
            ("evidence_sha256", "0" * 64),
            ("source", "google_search_console"),
        ):
            with self.subTest(key=key):
                attempt = copy.deepcopy(report)
                attempt["data"]["seo_research_input_observations"][0][key] = value
                with self.assertRaisesRegex(YandexH12Denied, "^H12_OBSERVATIONS_INVALID$"):
                    build_h12_handoff(
                        attempt, as_of=AS_OF,
                        selected_query=QUERY, site_gap=site_gap(),
                    )

    def test_wrong_site_and_malicious_query_are_refused_safely(self):
        report = synthetic_read()
        for site in ("https://evil.example", "http://your-fitness-coach.ru",
                     "https://your-fitness-coach.ru.evil.example"):
            with self.subTest(site=site):
                gap = site_gap()
                gap["site"] = site
                with self.assertRaisesRegex(YandexH12Denied, "^H12_SITE_GAP_INVALID$"):
                    build_h12_handoff(
                        report, as_of=AS_OF, selected_query=QUERY,
                        site_gap=gap,
                    )
        with self.assertRaisesRegex(YandexH12Denied, "^H12_PACKET_REJECTED$"):
            build_h12_handoff(
                report, as_of=AS_OF, selected_query="SECRET<query",
                site_gap=site_gap(query="SECRET<query"),
            )
        with self.assertRaisesRegex(YandexH12Denied, "^H12_PACKET_REJECTED$"):
            build_h12_handoff(
                report, as_of=AS_OF, selected_query="missing cluster",
                site_gap=site_gap(),
            )

    def test_receipt_cannot_expose_tampered_privilege_or_packet(self):
        handoff = build_h12_handoff(
            synthetic_read(), as_of=AS_OF,
            selected_query=QUERY, site_gap=site_gap(),
        )
        for field, value in (
            ("publication_allowed", True),
            ("source_provenance", "PROVIDER_VERIFIED"),
            ("filesystem_writes", 1),
            ("source", "google_search_console"),
        ):
            with self.subTest(field=field):
                attempt = copy.deepcopy(handoff)
                attempt[field] = value
                with self.assertRaisesRegex(YandexH12Denied, "^H12_RECEIPT_INVALID$"):
                    summarized_h12_handoff(attempt)
        attempt = copy.deepcopy(handoff)
        attempt["packet"]["publication_allowed"] = True
        with self.assertRaisesRegex(YandexH12Denied, "^H12_RECEIPT_INVALID$"):
            summarized_h12_handoff(attempt)


if __name__ == "__main__":
    unittest.main()
