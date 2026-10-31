"""Offline QA for owner-gated Yandex -> H12 one-shot; no live HTTP."""
from __future__ import annotations

import contextlib
import io
import json
import unittest
from datetime import date
from unittest.mock import patch

from marketing.yandex_webmaster import HOST
from scripts.hermes_yandex_h12_once import execute_one_shot, main
from tests.test_marketing_yandex_webmaster import fixture
from tests.test_marketing_yandex_webmaster_direct import (
    AS_OF, TOKEN, mocked_sequence,
)


def simulated_responses():
    return [
        {"user_id": 100},
        {"hosts": [{
            "host_id": HOST, "verified": True,
            "ascii_host_url": "https://your-fitness-coach.ru/",
        }]},
        fixture()["popular"],
        fixture()["all_history"],
        fixture()["index_history"],
        fixture()["sitemaps"],
    ]


class H397YandexOneShotTests(unittest.TestCase):
    def test_one_full_synthetic_read_handoff_reuses_existing_h12_without_write(self):
        send, calls = mocked_sequence(responses=simulated_responses())
        receipt = execute_one_shot(as_of=AS_OF, token=TOKEN, transport=send)
        self.assertEqual(6, len(calls))
        self.assertTrue(all("webmaster.yandex.net/v4/" in u for u in calls))
        self.assertEqual("SYNTHETIC_H12_IN_MEMORY_UNATTESTED", receipt["status"])
        self.assertEqual("SYNTHETIC_TRANSPORT_CHECK", receipt["source_read_status"])
        self.assertEqual("OFFLINE_SOURCE_NOT_PROVIDER_VERIFIED",
                         receipt["source_provenance"])
        self.assertEqual(1, receipt["h12_packet_count"])
        self.assertEqual(1, receipt["observed_query_rows"])
        self.assertEqual(6, receipt["request_count"])
        self.assertEqual(0, receipt["handoff_extra_gets"])
        self.assertTrue(receipt["indexing_available"])
        self.assertEqual(1, receipt["sitemaps"])
        self.assertFalse(receipt["site_gap_assessed"])
        self.assertEqual("NO_DATA", receipt["h12_packet_status"])
        self.assertEqual("NO_CONFIRMED_DEMAND", receipt["h12_evidence_kind"])
        for field in ("publication_allowed", "yfc_write_allowed",
                      "independent_provider_attestation", "history_persisted"):
            self.assertFalse(receipt[field])

    def test_two_distinct_provider_queries_make_two_real_h12_packets_no_fake_gap(self):
        source = simulated_responses()
        source[2]["queries"].append({
            "query_id": "b09", "query_text": "упражнения на плечи",
            "indicators": {
                "TOTAL_SHOWS": 12.0, "TOTAL_CLICKS": 0.0,
                "AVG_SHOW_POSITION": 6.5,
                "AVG_CLICK_POSITION": None,
            },
        })
        send, calls = mocked_sequence(responses=source)
        receipt = execute_one_shot(as_of=AS_OF, token=TOKEN, transport=send)
        self.assertEqual(6, len(calls))
        self.assertEqual(2, receipt["h12_packet_count"])
        self.assertEqual(2, receipt["observed_query_rows"])
        self.assertFalse(receipt["publication_allowed"])
        out = json.dumps(receipt, ensure_ascii=False)
        self.assertNotIn("упражнения на плечи", out)
        self.assertNotIn("восстановление после тренировки", out)
        self.assertNotIn(TOKEN, out)
        self.assertNotIn("100", out)

    def test_zero_query_rows_means_no_observations_not_zero_impressions(self):
        responses = simulated_responses()
        responses[2]["queries"] = []
        responses[2]["count"] = "0"
        send, calls = mocked_sequence(responses=responses)
        receipt = execute_one_shot(as_of=AS_OF, token=TOKEN, transport=send)
        self.assertEqual(6, len(calls))
        self.assertEqual("SYNTHETIC_NO_OBSERVED_QUERIES", receipt["status"])
        self.assertEqual(0, receipt["h12_packet_count"])
        self.assertEqual(0, receipt["observed_query_rows"])
        self.assertEqual("NO_CONFIRMED_DEMAND", receipt["h12_evidence_kind"])
        self.assertNotIn("impressions", receipt)
        self.assertFalse(receipt["publication_allowed"])

    def test_explicit_dry_run_does_not_read_token_or_contact_yandex(self):
        with patch("scripts.hermes_yandex_h12_once.read_private_token",
                   side_effect=AssertionError("no token access")), patch(
            "scripts.hermes_yandex_h12_once.collect",
            side_effect=AssertionError("no provider calls"),
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = main(["--date", "2026-10-23"])
        self.assertEqual(0, rc)
        result = json.loads(output.getvalue())
        self.assertEqual("NOT_EXECUTED", result["status"])
        self.assertEqual("NOT_EXECUTED", result["h12_handoff"])
        self.assertFalse(result["publication_allowed"])

    def test_explicit_token_and_date_gates_fail_before_network(self):
        for cmd, expected in (
            (["--date", "2026-10-23", "--execute-read"],
             "TOKEN_FILE_REQUIRED"),
            (["--date", "invalid", "--execute-read", "--token-file", "/tmp/bad"],
             "DATE_INVALID"),
            (["--date", "2026-02-30", "--execute-read", "--token-file", "/tmp/bad"],
             "DATE_INVALID"),
        ):
            with self.subTest(reason=expected), patch(
                "scripts.hermes_yandex_h12_once.read_private_token",
                side_effect=AssertionError("no token access"),
            ), patch(
                "scripts.hermes_yandex_h12_once.collect",
                side_effect=AssertionError("no network"),
            ):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    rc = main(cmd)
            self.assertEqual(2, rc)
            receipt = json.loads(output.getvalue())
            self.assertEqual(expected, receipt["reason"])
            self.assertEqual("PREFLIGHT", receipt["stage"])
            self.assertEqual(0, receipt["requests_attempted"])

    def test_sanitized_cli_success_never_exposes_query_or_token(self):
        sender, calls = mocked_sequence(responses=simulated_responses())
        with patch("scripts.hermes_yandex_h12_once.read_private_token",
                   return_value=TOKEN), patch(
            "marketing.yandex_webmaster_direct._transport",
            side_effect=sender,
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = main([
                    "--date", "2026-10-23", "--execute-read",
                    "--token-file", "/private/test",
                ])
        self.assertEqual(0, rc)
        self.assertEqual(6, len(calls))
        data = json.loads(output.getvalue())
        self.assertEqual("LIVE_H12_IN_MEMORY_UNATTESTED", data["status"])
        self.assertEqual("LIVE_GET_RESPONSE_UNATTESTED", data["source_read_status"])
        self.assertEqual(1, data["h12_packet_count"])
        self.assertEqual("NO_DATA", data["h12_packet_status"])
        self.assertFalse(data["independent_provider_attestation"])
        for secret in (TOKEN, "восстановление", "100.0", "14.5", '"user_id"'):
            self.assertNotIn(secret, output.getvalue())

    def test_sanitized_cli_yandex_denial_no_retry(self):
        sender, calls = mocked_sequence(error=(2, "ACCESS_DENIED"))
        with patch("scripts.hermes_yandex_h12_once.read_private_token",
                   return_value=TOKEN), patch(
            "marketing.yandex_webmaster_direct._transport",
            side_effect=sender,
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = main([
                    "--date", "2026-10-23", "--execute-read",
                    "--token-file", "/private/test",
                ])
        self.assertEqual(2, rc)
        self.assertEqual(3, len(calls))
        data = json.loads(output.getvalue())
        self.assertEqual("REFUSED", data["status"])
        self.assertEqual("POPULAR", data["stage"])
        self.assertEqual("ACCESS_DENIED", data["reason"])
        self.assertEqual(3, data["requests_attempted"])
        self.assertFalse(data["publication_allowed"])

    def test_sanitized_cli_h12_error_after_six_reads_does_not_repeat(self):
        source = simulated_responses()
        source[2]["queries"][0]["query_text"] = "x<secret"
        sender, calls = mocked_sequence(responses=source)
        with patch("scripts.hermes_yandex_h12_once.read_private_token",
                   return_value=TOKEN), patch(
            "marketing.yandex_webmaster_direct._transport",
            side_effect=sender,
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = main([
                    "--date", "2026-10-23", "--execute-read",
                    "--token-file", "/private/test",
                ])
        self.assertEqual(2, rc)
        self.assertEqual(6, len(calls))
        data = json.loads(output.getvalue())
        self.assertEqual("H12_HANDOFF", data["stage"])
        self.assertEqual("H12_PACKET_REJECTED", data["reason"])
        self.assertEqual(6, data["requests_attempted"])
        self.assertNotIn("secret", output.getvalue())

    def test_provider_exception_text_is_never_printed(self):
        with patch("scripts.hermes_yandex_h12_once.read_private_token",
                   side_effect=RuntimeError("TOPSECRET TOKEN")):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = main([
                    "--date", "2026-10-23", "--execute-read",
                    "--token-file", "/private/test",
                ])
        self.assertEqual(2, rc)
        data = json.loads(output.getvalue())
        self.assertEqual("H12_INTERNAL_REFUSED", data["reason"])
        self.assertNotIn("TOPSECRET", output.getvalue())


if __name__ == "__main__":
    unittest.main()
