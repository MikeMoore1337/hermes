"""Issue #397: real request-layer wiring only against mocked Yandex transport."""
from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

from marketing.yandex_webmaster import BASE, HOST
from marketing.yandex_webmaster_direct import (
    YandexLiveDenied, _json_unique, _parse_response, _safe_url, _uid,
    _verify_host, collect, main, probe_user, probe_host, read_private_token,
    summarized_receipt,
)
from tests.test_marketing_yandex_webmaster import fixture

TOKEN = "A" * 40
AS_OF = date(2026, 10, 23)


def mocked_sequence(*, responses=None, error=None):
    data = responses if responses is not None else [
        {"user_id": 100},
        {"hosts": [
            {"host_id": HOST, "verified": True,
             "main_mirror": {"host_id": HOST, "verified": True},
             "ascii_host_url": "https://your-fitness-coach.ru/"}
        ]},
        fixture()["popular"], fixture()["all_history"],
        fixture()["index_history"], fixture()["sitemaps"],
    ]
    index = 0
    called = []

    def send(url, token):
        nonlocal index
        called.append(url)
        if error is not None and index == error[0]:
            raise YandexLiveDenied(error[1])
        item = data[index]
        index += 1
        return json.dumps(item).encode("utf-8")

    return send, called


class YandexLiveProbeTests(unittest.TestCase):
    def test_six_gets_in_order_all_ready_but_not_provider_attested(self):
        send, calls = mocked_sequence()
        result = collect(as_of=AS_OF, token=TOKEN, transport=send)
        self.assertEqual(6, len(calls))
        self.assertEqual(6, result["requests"])
        self.assertEqual(BASE + "/user", calls[0])
        self.assertTrue(calls[1].endswith("/user/100/hosts"))
        self.assertIn("/search-queries/popular", calls[2])
        self.assertIn("/search-queries/all/history", calls[3])
        self.assertIn("/indexing/history", calls[4])
        self.assertIn("/sitemaps?", calls[5])
        self.assertEqual("SYNTHETIC_TRANSPORT_CHECK", result["status"])
        self.assertEqual("OFFLINE_SOURCE_NOT_PROVIDER_VERIFIED", result["data"]["status"])
        self.assertEqual("OWNER_EXPORT_UNVERIFIED", result["data"]["seo_research_observations"][0]["data_quality"])
        self.assertFalse(result["external_publication_allowed"])
        self.assertEqual(0, result["seo_changes_applied"])

    def test_receipt_never_outputs_raw_queries_or_token(self):
        send, _ = mocked_sequence()
        full = collect(as_of=AS_OF, token=TOKEN, transport=send)
        output = json.dumps(summarized_receipt(full), ensure_ascii=False)
        self.assertNotIn(TOKEN, output)
        self.assertNotIn("восстановление", output)
        self.assertNotIn("100.0", output)
        self.assertEqual(1, summarized_receipt(full)["query_rows"])

    def test_host_missing_refuses_before_query_endpoint(self):
        for item in (
            {"hosts": []},
            {"hosts": [{"host_id": HOST, "verified": False}]},
            {"hosts": [{"host_id": HOST, "verified": True, "main_mirror": {"host_id": "http:your-fitness-coach.ru:80"}}]},
            {"hosts": [{"host_id": HOST, "verified": True}, {"host_id": HOST, "verified": True}]},
            {"hosts": [{"host_id": HOST, "verified": True, "host_data_status": "NOT_LOADED"}]},
            {"hosts": [{"host_id": HOST, "verified": True,
                        "ascii_host_url": "https://attacker.example/",
                        "main_mirror": {"host_id": HOST}}]},
            {"hosts": [{"host_id": HOST, "verified": True,
                        "ascii_host_url": "http://your-fitness-coach.ru/",
                        "main_mirror": {"host_id": HOST}}]},
        ):
            with self.subTest(item=item):
                data = mocked_sequence()[0]
                send, calls = mocked_sequence(responses=[{"user_id": 100}, item])
                with self.assertRaises(YandexLiveDenied):
                    collect(as_of=AS_OF, token=TOKEN, transport=send)
                self.assertEqual(2, len(calls))

    def test_host_identity_requires_exact_https_ascii_origin(self):
        for ascii_url in (
            None, "", "http://your-fitness-coach.ru/",
            "https://your-fitness-coach.ru.evil.example/",
            "https://your-fitness-coach.ru:8443/",
        ):
            with self.subTest(ascii_url=ascii_url):
                send, calls = mocked_sequence(responses=[
                    {"user_id": 100},
                    {"hosts": [{
                        "host_id": HOST, "verified": True,
                        "ascii_host_url": ascii_url,
                        "main_mirror": {"host_id": HOST},
                    }]},
                ])
                with self.assertRaisesRegex(
                    YandexLiveDenied, "TARGET_HOST_URL_MISMATCH",
                ):
                    collect(as_of=AS_OF, token=TOKEN, transport=send)
                self.assertEqual(2, len(calls))  # no query, sitemap or index GET

    def test_user_id_malformed_refused_after_first_get(self):
        for value in (None, True, "123", -1, 0):
            with self.subTest(value=value):
                send, calls = mocked_sequence(responses=[{"user_id": value}])
                with self.assertRaisesRegex(YandexLiveDenied, "USER_ID_INVALID"):
                    collect(as_of=AS_OF, token=TOKEN, transport=send)
                self.assertEqual(1, len(calls))

    def test_all_http_failure_classes_no_retry(self):
        for state in ("AUTH_REQUIRED", "ACCESS_DENIED", "RATE_LIMITED",
                      "UPSTREAM_UNAVAILABLE", "HOST_NOT_VERIFIED_OR_UNAVAILABLE"):
            for at in (0, 2, 5):
                with self.subTest(state=state, at=at):
                    send, calls = mocked_sequence(error=(at, state))
                    with self.assertRaisesRegex(YandexLiveDenied, state):
                        collect(as_of=AS_OF, token=TOKEN, transport=send)
                    self.assertEqual(at + 1, len(calls))

    def test_url_allowlist_and_redirect_destination_never_accepted(self):
        for url in (
            "http://api.webmaster.yandex.net/v4/user",
            "https://evil.example/v4/user",
            "https://api.webmaster.yandex.net.evil.example/v4/user",
            "https://api.webmaster.yandex.net:8443/v4/user",
            "https://user:pass@api.webmaster.yandex.net/v4/user",
            "https://api.webmaster.yandex.net/v3/user",
            "https://api.webmaster.yandex.net/v4/user#secret",
        ):
            with self.subTest(url=url), self.assertRaisesRegex(YandexLiveDenied, "URL_NOT_ALLOWED"):
                _safe_url(url)
        _safe_url("https://api.webmaster.yandex.net/v4/user")

    def test_response_duplicate_key_nonfinite_invalid_json_and_oversize_refused(self):
        for raw in (
            b'{"user_id":10,"user_id":11}', b'{"user_id":NaN}',
            b'{"user_id":Infinity}', b"[]", b"", b"{}" * 33000,
        ):
            with self.subTest(raw=raw[:20]), self.assertRaises(YandexLiveDenied):
                _parse_response(raw)
        self.assertEqual({"user_id": 1}, _parse_response(b'{"user_id":1}'))

    def test_response_shape_change_fails_closed_without_issuing_more_gets(self):
        bad = fixture()
        bad["popular"]["count"] = "INVALID_COUNT"
        responses = mocked_sequence()[0]
        send, calls = mocked_sequence(responses=[
            {"user_id": 100},
            {"hosts": [{"host_id": HOST, "verified": True,
                        "ascii_host_url": "https://your-fitness-coach.ru/",
                        "main_mirror": {"host_id": HOST}}]},
            bad["popular"], bad["all_history"], bad["index_history"], bad["sitemaps"],
        ])
        with self.assertRaisesRegex(YandexLiveDenied, "Yandex_RESPONSE_CONTRACT_CHANGED"):
            collect(as_of=AS_OF, token=TOKEN, transport=send)
        self.assertEqual(6, len(calls))

    def test_response_byte_budget_or_transport_exception_has_fixed_refusal(self):
        send, calls = mocked_sequence()
        def huge(url, token):
            calls.append(url)
            return b"x" * (65536 + 1)
        with self.assertRaisesRegex(YandexLiveDenied, "RESPONSE_SIZE_INVALID"):
            collect(as_of=AS_OF, token=TOKEN, transport=huge)
        self.assertEqual(1, len(calls))

        def poison(url, token):
            raise ValueError("secret_token_please_do_not_show")
        with self.assertRaisesRegex(YandexLiveDenied, "^REQUEST_FAILED$") as found:
            collect(as_of=AS_OF, token=TOKEN, transport=poison)
        self.assertNotIn("secret", str(found.exception))

    @unittest.skipUnless(os.name == "posix", "POSIX token ACL only")
    def test_token_file_mode_symlink_owner_path_guard(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "yandex_oauth"
            path.write_text(TOKEN + "\n")
            os.chmod(path, 0o600)
            self.assertEqual(TOKEN, read_private_token(str(path)))
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(YandexLiveDenied, "TOKEN_FILE_UNSAFE"):
                read_private_token(str(path))
            os.chmod(path, 0o600)
            link = Path(folder) / "link"
            link.symlink_to(path)
            with self.assertRaises(YandexLiveDenied):
                read_private_token(str(link))
            with self.assertRaises(YandexLiveDenied):
                read_private_token("relative/path")

    def test_single_user_auth_probe_does_not_access_host_or_query(self):
        send, called = mocked_sequence(responses=[{"user_id": 100}])
        result = probe_user(token=TOKEN, transport=send)
        self.assertEqual([BASE + "/user"], called)
        self.assertEqual("SYNTHETIC_USER_ENDPOINT_ONLY", result["status"])
        self.assertEqual(1, result["request_count"])
        self.assertEqual(1, result["request_limit"])
        self.assertFalse(result["host_verified"])
        self.assertFalse(result["search_metrics_verified"])
        self.assertFalse(result["publication_allowed"])
        self.assertNotIn("user_id", result)

    def test_user_probe_invalid_token_does_not_call_transport(self):
        calls = []
        def fake(*args):
            calls.append(args)
            return b'{"user_id":100}'
        for bad in ("", "not-valid", None, " " * 40):
            with self.subTest(bad_type=type(bad).__name__), self.assertRaises(
                YandexLiveDenied,
            ):
                probe_user(token=bad, transport=fake)
        self.assertEqual([], calls)

    def test_cli_probe_requires_explicit_execution_and_private_token_path(self):
        for argv, reason in (
            (["--date", "2026-10-23", "--probe-user"],
             "EXPLICIT_EXECUTION_REQUIRED"),
            (["--date", "2026-10-23", "--execute-read", "--probe-user"],
             "TOKEN_FILE_REQUIRED"),
        ):
            with self.subTest(reason=reason):
                with patch("marketing.yandex_webmaster_direct._transport",
                           side_effect=AssertionError("must not request")):
                    output = io.StringIO()
                    with patch("sys.stdout", output):
                        rc = main(argv)
                self.assertEqual(2, rc)
                result = json.loads(output.getvalue())
                self.assertEqual("REFUSED", result["status"])
                self.assertEqual(reason, result["reason"])
                self.assertEqual(1, result["request_limit"])
                self.assertFalse(result["publication_allowed"])

    def test_cli_probe_prints_only_redacted_fixed_codes(self):
        cmd = ["--date", "2026-10-23", "--probe-user", "--execute-read",
               "--token-file", "/private/synthetic"]
        for provider_error, expected in (
            ("ACCESS_DENIED", "ACCESS_DENIED"),
            ("AUTH_REQUIRED", "AUTH_REQUIRED"),
            ("NETWORK_UNAVAILABLE", "NETWORK_UNAVAILABLE"),
            ("secret=do-not-echo", "AUTH_OR_RESPONSE_NOT_VERIFIED"),
        ):
            with self.subTest(reason=expected):
                calls = []
                def denied(url, token):
                    calls.append(url)
                    raise YandexLiveDenied(provider_error)
                with patch("marketing.yandex_webmaster_direct.read_private_token",
                           return_value=TOKEN), patch(
                        "marketing.yandex_webmaster_direct._transport",
                        side_effect=denied):
                    output = io.StringIO()
                    with patch("sys.stdout", output):
                        rc = main(cmd)
                self.assertEqual(2, rc)
                self.assertEqual([BASE + "/user"], calls)
                self.assertEqual(expected, json.loads(output.getvalue())["reason"])
                self.assertNotIn("secret=", output.getvalue())
                self.assertNotIn(TOKEN, output.getvalue())

    def test_cli_probe_one_success_still_does_not_verify_site(self):
        cmd = ["--date", "2026-10-23", "--probe-user", "--execute-read",
               "--token-file", "/private/synthetic"]
        calls = []
        def ok(url, token):
            calls.append(url)
            return b'{"user_id":123456}'
        with patch("marketing.yandex_webmaster_direct.read_private_token",
                   return_value=TOKEN), patch(
                   "marketing.yandex_webmaster_direct._transport", side_effect=ok):
            output = io.StringIO()
            with patch("sys.stdout", output):
                rc = main(cmd)
        data = json.loads(output.getvalue())
        self.assertEqual(0, rc)
        self.assertEqual([BASE + "/user"], calls)
        self.assertEqual("LIVE_USER_ENDPOINT_ONLY", data["status"])
        self.assertEqual(1, data["request_count"])
        self.assertFalse(data["host_verified"])
        self.assertFalse(data["publication_allowed"])
        self.assertNotIn("123456", output.getvalue())
        self.assertNotIn(TOKEN, output.getvalue())

    def test_two_get_host_probe_verified_without_accessing_search_data(self):
        send, calls = mocked_sequence()
        result = probe_host(token=TOKEN, transport=send)
        self.assertEqual([BASE + "/user", BASE + "/user/100/hosts"], calls)
        self.assertEqual("SYNTHETIC_VERIFIED_YFC_HOST_ONLY", result["status"])
        self.assertTrue(result["host_verified"])
        self.assertEqual(2, result["request_count"])
        self.assertEqual(2, result["request_limit"])
        self.assertFalse(result["search_metrics_verified"])
        self.assertFalse(result["indexing_verified"])
        self.assertFalse(result["sitemap_verified"])
        self.assertFalse(result["publication_allowed"])
        self.assertNotIn("100", json.dumps(result))
        self.assertNotIn(TOKEN, json.dumps(result))

    def test_host_probe_fails_closed_on_missing_site_and_bad_mirror(self):
        for target, expected in (
            ({"hosts": []}, "TARGET_HOST_NOT_VERIFIED"),
            ({"hosts": [{"host_id": HOST, "verified": True,
                        "ascii_host_url": "http://your-fitness-coach.ru/"}]},
             "TARGET_HOST_URL_MISMATCH"),
            ({"hosts": [{"host_id": HOST, "verified": True,
                        "ascii_host_url": "https://your-fitness-coach.ru/",
                        "main_mirror": {"host_id": "http:your-fitness-coach.ru:80"}}]},
             "PRIMARY_MIRROR_MISMATCH"),
        ):
            with self.subTest(expected=expected):
                send, calls = mocked_sequence(responses=[{"user_id": 100}, target])
                with self.assertRaises(YandexLiveDenied) as ctx:
                    probe_host(token=TOKEN, transport=send)
                self.assertEqual(expected, str(ctx.exception))
                self.assertEqual("HOSTS", ctx.exception.stage)
                self.assertEqual(2, len(calls))

    def test_host_probe_stage_and_http_errors_only_fixed_safe_codes(self):
        cmd = ["--date", "2026-10-23", "--execute-read", "--probe-host",
               "--token-file", "/private/synthetic"]
        for stage, error_at, reason in (
            ("USER", 0, "AUTH_REQUIRED"),
            ("USER", 0, "RATE_LIMITED"),
            ("HOSTS", 1, "ACCESS_DENIED"),
            ("HOSTS", 1, "UPSTREAM_UNAVAILABLE"),
            ("HOSTS", 1, "HOST_NOT_VERIFIED_OR_UNAVAILABLE"),
            ("HOSTS", 1, "secret=do-not-echo"),
        ):
            with self.subTest(stage=stage, reason=reason):
                send, calls = mocked_sequence(error=(error_at, reason))
                with patch("marketing.yandex_webmaster_direct.read_private_token",
                           return_value=TOKEN), patch(
                           "marketing.yandex_webmaster_direct._transport",
                           side_effect=send):
                    output = io.StringIO()
                    with patch("sys.stdout", output):
                        rc = main(cmd)
                self.assertEqual(2, rc)
                receipt = json.loads(output.getvalue())
                self.assertEqual(stage, receipt["stage"])
                self.assertEqual(min(error_at + 1, 2), len(calls))
                self.assertEqual(2, receipt["request_limit"])
                self.assertEqual("REFUSED", receipt["status"])
                self.assertEqual(
                    "AUTH_OR_RESPONSE_NOT_VERIFIED" if reason.startswith("secret=")
                    else reason, receipt["reason"])
                self.assertFalse(receipt["publication_allowed"])
                self.assertNotIn(TOKEN, output.getvalue())
                self.assertNotIn("secret=", output.getvalue())
                self.assertNotIn("100", output.getvalue())

    def test_host_probe_transport_poison_redacted(self):
        def poison(url, token):
            raise RuntimeError("sensitive token=" + token + " user=100")
        with patch("marketing.yandex_webmaster_direct.read_private_token",
                   return_value=TOKEN), patch(
                   "marketing.yandex_webmaster_direct._transport",
                   side_effect=poison):
            output = io.StringIO()
            with patch("sys.stdout", output):
                rc = main(["--date", "2026-10-23", "--execute-read", "--probe-host",
                           "--token-file", "/private/synthetic"])
        self.assertEqual(2, rc)
        receipt = json.loads(output.getvalue())
        self.assertEqual("REQUEST_FAILED", receipt["reason"])
        self.assertEqual("USER", receipt["stage"])
        self.assertNotIn("sensitive", output.getvalue())
        self.assertNotIn(TOKEN, output.getvalue())

    def test_host_probe_requires_explicit_execution_and_token(self):
        for argv, reason in (
            (["--date", "2026-10-23", "--probe-host"], "EXPLICIT_EXECUTION_REQUIRED"),
            (["--date", "2026-10-23", "--probe-host", "--execute-read"],
             "TOKEN_FILE_REQUIRED"),
        ):
            with self.subTest(reason=reason), patch(
                "marketing.yandex_webmaster_direct._transport",
                side_effect=AssertionError("network forbidden")):
                output = io.StringIO()
                with patch("sys.stdout", output):
                    rc = main(argv)
            self.assertEqual(2, rc)
            receipt = json.loads(output.getvalue())
            self.assertEqual(reason, receipt["reason"])
            self.assertEqual("PREFLIGHT", receipt["stage"])
            self.assertEqual(2, receipt["request_limit"])

    def test_host_probe_cli_success_only_asserts_host_not_metrics(self):
        send, called = mocked_sequence()
        with patch("marketing.yandex_webmaster_direct.read_private_token",
                   return_value=TOKEN), patch(
                   "marketing.yandex_webmaster_direct._transport",
                   side_effect=send):
            output = io.StringIO()
            with patch("sys.stdout", output):
                rc = main(["--date", "2026-10-23", "--execute-read", "--probe-host",
                           "--token-file", "/private/synthetic"])
        self.assertEqual(0, rc)
        self.assertEqual(2, len(called))
        receipt = json.loads(output.getvalue())
        self.assertEqual("LIVE_VERIFIED_YFC_HOST_ONLY", receipt["status"])
        self.assertTrue(receipt["host_verified"])
        self.assertFalse(receipt["search_metrics_verified"])
        self.assertFalse(receipt["publication_allowed"])
        self.assertNotIn("100", output.getvalue())
        self.assertNotIn(TOKEN, output.getvalue())

    def test_diagnose_full_reports_fixed_stage_and_attempts(self):
        cmd = ["--date", "2026-10-23", "--execute-read", "--diagnose-full",
               "--token-file", "/private/synthetic"]
        for index, stage_name in (
            (0, "USER"), (1, "HOSTS"), (2, "POPULAR"),
            (3, "ALL_HISTORY"), (4, "INDEXING"), (5, "SITEMAPS"),
        ):
            with self.subTest(stage=stage_name):
                send, called = mocked_sequence(error=(index, "ACCESS_DENIED"))
                with patch("marketing.yandex_webmaster_direct.read_private_token",
                           return_value=TOKEN), patch(
                           "marketing.yandex_webmaster_direct._transport",
                           side_effect=send):
                    output = io.StringIO()
                    with patch("sys.stdout", output):
                        rc = main(cmd)
                report = json.loads(output.getvalue())
                self.assertEqual(2, rc)
                self.assertEqual("REFUSED", report["status"])
                self.assertEqual("ACCESS_DENIED", report["reason"])
                self.assertEqual(stage_name, report["stage"])
                self.assertEqual(index + 1, report["requests_attempted"])
                self.assertEqual(index + 1, len(called))
                self.assertEqual(6, report["request_limit"])
                self.assertFalse(report["publication_allowed"])
                self.assertNotIn(TOKEN, output.getvalue())
                self.assertNotIn("100", output.getvalue())

    def test_diagnose_full_contract_error_after_six_gets(self):
        bad = fixture()
        bad["popular"]["count"] = "bad"
        seq, called = mocked_sequence(responses=[
            {"user_id": 100},
            {"hosts": [{"host_id": HOST, "verified": True,
                        "ascii_host_url": "https://your-fitness-coach.ru/"}]},
            bad["popular"], bad["all_history"],
            bad["index_history"], bad["sitemaps"],
        ])
        with patch("marketing.yandex_webmaster_direct.read_private_token",
                   return_value=TOKEN), patch(
                   "marketing.yandex_webmaster_direct._transport", side_effect=seq):
            output = io.StringIO()
            with patch("sys.stdout", output):
                rc = main(["--date", "2026-10-23", "--execute-read",
                           "--diagnose-full", "--token-file", "/private/synthetic"])
        result = json.loads(output.getvalue())
        self.assertEqual(2, rc)
        self.assertEqual("POPULAR_DATA", result["stage"])
        self.assertEqual("counter_invalid", result["reason"])
        self.assertEqual(6, result["requests_attempted"])
        self.assertEqual(6, len(called))
        self.assertNotIn(TOKEN, output.getvalue())
        self.assertNotIn("bad", output.getvalue())

    def test_diagnose_full_sanitizes_which_api_section_failed(self):
        for stage_name, index, invalid in (
            ("POPULAR_DATA", 2, {"queries": [], "date_from": "bad",
                                 "date_to": "2026-10-19", "count": 0}),
            ("ALL_HISTORY_DATA", 3, {"indicators": {"TOTAL_SHOWS": "bad"}}),
            ("INDEXING_DATA", 4, {"indicators": {"HTTP_2XX": "bad"}}),
            ("SITEMAPS_DATA", 5, {"sitemaps": "bad"}),
        ):
            with self.subTest(stage=stage_name):
                payloads = [
                    {"user_id": 100},
                    {"hosts": [{"host_id": HOST, "verified": True,
                                "ascii_host_url": "https://your-fitness-coach.ru/"}]},
                    fixture()["popular"], fixture()["all_history"],
                    fixture()["index_history"], fixture()["sitemaps"],
                ]
                payloads[index] = invalid
                seq, calls = mocked_sequence(responses=payloads)
                with patch("marketing.yandex_webmaster_direct.read_private_token",
                           return_value=TOKEN), patch(
                           "marketing.yandex_webmaster_direct._transport",
                           side_effect=seq):
                    output = io.StringIO()
                    with patch("sys.stdout", output):
                        rc = main(["--date", "2026-10-23", "--execute-read",
                                   "--diagnose-full",
                                   "--token-file", "/private/synthetic"])
                receipt = json.loads(output.getvalue())
                self.assertEqual(2, rc)
                self.assertEqual(stage_name, receipt["stage"])
                self.assertEqual(6, receipt["requests_attempted"])
                self.assertEqual(6, len(calls))
                self.assertNotIn("100", output.getvalue())
                self.assertNotIn(TOKEN, output.getvalue())

    def test_diagnose_full_redacts_poison_and_unknown_errors(self):
        def poison(*args):
            raise ValueError("secret=" + TOKEN + " user=100")
        with patch("marketing.yandex_webmaster_direct.read_private_token",
                   return_value=TOKEN), patch(
                   "marketing.yandex_webmaster_direct._transport", side_effect=poison):
            output = io.StringIO()
            with patch("sys.stdout", output):
                rc = main(["--date", "2026-10-23", "--diagnose-full",
                           "--execute-read", "--token-file", "/private/synthetic"])
        result = json.loads(output.getvalue())
        self.assertEqual(2, rc)
        self.assertEqual("USER", result["stage"])
        self.assertEqual(1, result["requests_attempted"])
        self.assertEqual("REQUEST_FAILED", result["reason"])
        self.assertNotIn(TOKEN, output.getvalue())
        self.assertNotIn("secret=", output.getvalue())

    def test_diagnose_full_preflight_without_any_get(self):
        for argv, reason in (
            (["--date", "2026-10-23", "--diagnose-full"],
             "EXPLICIT_EXECUTION_REQUIRED"),
            (["--date", "2026-10-23", "--execute-read", "--diagnose-full"],
             "TOKEN_FILE_REQUIRED"),
            (["--date", "invalid", "--execute-read", "--diagnose-full"],
             "DATE_INVALID"),
        ):
            with self.subTest(reason=reason), patch(
                    "marketing.yandex_webmaster_direct._transport",
                    side_effect=AssertionError("must not call")):
                output = io.StringIO()
                with patch("sys.stdout", output):
                    rc = main(argv)
            report = json.loads(output.getvalue())
            self.assertEqual(2, rc)
            self.assertEqual("PREFLIGHT", report["stage"])
            self.assertEqual(0, report["requests_attempted"])
            self.assertEqual(reason, report["reason"])
            self.assertEqual(6, report["request_limit"])

    def test_diagnose_full_positive_retains_unattested_provenance(self):
        seq, called = mocked_sequence()
        with patch("marketing.yandex_webmaster_direct.read_private_token",
                   return_value=TOKEN), patch(
                   "marketing.yandex_webmaster_direct._transport", side_effect=seq):
            output = io.StringIO()
            with patch("sys.stdout", output):
                rc = main(["--date", "2026-10-23", "--diagnose-full",
                           "--execute-read", "--token-file", "/private/synthetic"])
        self.assertEqual(0, rc)
        self.assertEqual(6, len(called))
        report = json.loads(output.getvalue())
        self.assertEqual("LIVE_GET_RESPONSE_UNATTESTED", report["status"])
        self.assertEqual("OFFLINE_SOURCE_NOT_PROVIDER_VERIFIED",
                         report["source_provenance"])
        self.assertFalse(report["publication_allowed"])
        self.assertNotIn(TOKEN, output.getvalue())

    def test_full_collect_accepts_real_null_click_position_without_fabrication(self):
        responses = [
            {"user_id": 100},
            {"hosts": [{"host_id": HOST, "verified": True,
                        "ascii_host_url": "https://your-fitness-coach.ru/"}]},
            fixture()["popular"], fixture()["all_history"],
            fixture()["index_history"], fixture()["sitemaps"],
        ]
        responses[2]["queries"][0]["indicators"]["AVG_CLICK_POSITION"] = None
        responses[2]["queries"][0]["indicators"]["TOTAL_CLICKS"] = 0
        send, calls = mocked_sequence(responses=responses)
        report = collect(as_of=AS_OF, token=TOKEN, transport=send, diagnostic=True)
        self.assertEqual(6, len(calls))
        self.assertEqual(6, report["requests"])
        self.assertEqual("SYNTHETIC_TRANSPORT_CHECK", report["status"])
        observation = report["data"]["seo_research_observations"][0]
        self.assertEqual(0, observation["metrics"]["clicks"])
        self.assertEqual(100, observation["metrics"]["impressions"])
        self.assertEqual(0, observation["metrics"]["ctr"])
        self.assertEqual(14.5, observation["metrics"]["average_position"])
        self.assertNotIn("average_click_position",
                         report["data"]["seo_research_input_observations"][0])
        self.assertFalse(report["external_publication_allowed"])

    def test_cli_full_diagnostic_with_null_click_position_sanitizes_summary(self):
        responses = [
            {"user_id": 100},
            {"hosts": [{"host_id": HOST, "verified": True,
                        "ascii_host_url": "https://your-fitness-coach.ru/"}]},
            fixture()["popular"], fixture()["all_history"],
            fixture()["index_history"], fixture()["sitemaps"],
        ]
        responses[2]["queries"][0]["indicators"]["AVG_CLICK_POSITION"] = None
        send, calls = mocked_sequence(responses=responses)
        with patch("marketing.yandex_webmaster_direct.read_private_token",
                   return_value=TOKEN), patch(
                   "marketing.yandex_webmaster_direct._transport",
                   side_effect=send):
            output = io.StringIO()
            with patch("sys.stdout", output):
                rc = main(["--date", "2026-10-23", "--execute-read",
                           "--diagnose-full", "--token-file", "/private/synthetic"])
        self.assertEqual(0, rc)
        self.assertEqual(6, len(calls))
        result = json.loads(output.getvalue())
        self.assertEqual("LIVE_GET_RESPONSE_UNATTESTED", result["status"])
        self.assertEqual(1, result["query_rows"])
        self.assertEqual("OFFLINE_SOURCE_NOT_PROVIDER_VERIFIED",
                         result["source_provenance"])
        self.assertFalse(result["publication_allowed"])
        self.assertNotIn(TOKEN, output.getvalue())
        self.assertNotIn("восстановление", output.getvalue())
        self.assertNotIn("100.0", output.getvalue())

    def test_diagnose_position_reads_only_three_authenticated_endpoints(self):
        cmd = ["--date", "2026-10-23", "--execute-read",
               "--diagnose-position", "--token-file", "/private/synthetic"]
        for position, indicator, category in (
            (0, "AVG_SHOW_POSITION", "ZERO"),
            (None, "NONE", "NO_INVALID_POSITION"),
            ("2.0", "AVG_SHOW_POSITION", "NUMERIC_STRING"),
        ):
            with self.subTest(category=category):
                payloads = [p for p in [
                    {"user_id": 100},
                    {"hosts": [{"host_id": HOST, "verified": True,
                                "ascii_host_url": "https://your-fitness-coach.ru/"}]},
                    fixture()["popular"],
                ]]
                indicators = payloads[2]["queries"][0]["indicators"]
                indicators.pop("AVG_SHOW_POSITION", None)
                indicators[indicator] = position
                sent, calls = mocked_sequence(responses=payloads)
                with patch("marketing.yandex_webmaster_direct.read_private_token",
                           return_value=TOKEN), patch(
                    "marketing.yandex_webmaster_direct._transport",
                    side_effect=sent,
                ):
                    output = io.StringIO()
                    with patch("sys.stdout", output):
                        rc = main(cmd)
                result = json.loads(output.getvalue())
                self.assertEqual(0, rc)
                self.assertEqual([BASE + "/user", BASE + "/user/100/hosts"],
                                 calls[:2])
                self.assertEqual(3, len(calls))
                self.assertIn("/search-queries/popular?", calls[2])
                self.assertEqual("LIVE_POPULAR_POSITION_CLASS_ONLY", result["status"])
                self.assertTrue(result["host_verified"])
                self.assertEqual(3, result["request_count"])
                self.assertEqual(3, result["request_limit"])
                self.assertEqual(indicator, result["position_indicator"])
                self.assertEqual(category, result["position_value_class"])
                for field in ("search_metrics_verified", "indexing_verified",
                              "sitemap_verified", "publication_allowed"):
                    self.assertFalse(result[field])
                self.assertNotIn("восстановление", output.getvalue())
                self.assertNotIn(TOKEN, output.getvalue())
                self.assertNotIn("100", output.getvalue())

    def test_diagnose_position_preflight_refuses_without_network(self):
        for flags, reason in (
            (["--date", "2026-10-23", "--diagnose-position"],
             "EXPLICIT_EXECUTION_REQUIRED"),
            (["--date", "2026-10-23", "--diagnose-position", "--execute-read"],
             "TOKEN_FILE_REQUIRED"),
            (["--date", "bad", "--diagnose-position", "--execute-read"],
             "DATE_INVALID"),
        ):
            with self.subTest(reason=reason), patch(
                "marketing.yandex_webmaster_direct._transport",
                side_effect=AssertionError("network must not run"),
            ):
                output = io.StringIO()
                with patch("sys.stdout", output):
                    rc = main(flags)
            result = json.loads(output.getvalue())
            self.assertEqual(2, rc)
            self.assertEqual("PREFLIGHT", result["stage"])
            self.assertEqual(reason, result["reason"])
            self.assertEqual(0, result["requests_attempted"])
            self.assertEqual(3, result["request_limit"])

    def test_diagnose_position_stops_on_host_mismatch_and_transport_error(self):
        cmd = ["--date", "2026-10-23", "--execute-read",
               "--diagnose-position", "--token-file", "/private/synthetic"]
        bad_hosts = {"hosts": [{"host_id": HOST, "verified": False}]}
        for error_at, reason, responses in (
            (None, "TARGET_HOST_NOT_VERIFIED", [{"user_id":100}, bad_hosts]),
            (0, "RATE_LIMITED", None),
            (2, "UPSTREAM_UNAVAILABLE", None),
        ):
            with self.subTest(reason=reason):
                sent, calls = mocked_sequence(
                    responses=responses, error=(error_at, reason)
                    if error_at is not None else None,
                )
                with patch("marketing.yandex_webmaster_direct.read_private_token",
                           return_value=TOKEN), patch(
                    "marketing.yandex_webmaster_direct._transport",
                    side_effect=sent,
                ):
                    output = io.StringIO()
                    with patch("sys.stdout", output):
                        rc = main(cmd)
                result = json.loads(output.getvalue())
                self.assertEqual(2, rc)
                self.assertEqual(reason, result["reason"])
                self.assertTrue(result["requests_attempted"] <= 3)
                self.assertEqual(3, result["request_limit"])
                self.assertNotIn(TOKEN, output.getvalue())

    def test_diagnose_position_keeps_normal_collect_unchanged(self):
        sent, calls = mocked_sequence()
        result = collect(as_of=AS_OF, token=TOKEN, transport=sent)
        self.assertEqual(6, result["requests"])
        self.assertEqual(6, len(calls))
        self.assertEqual("SYNTHETIC_TRANSPORT_CHECK", result["status"])
        with self.assertRaisesRegex(YandexLiveDenied,
                                    "EXPLICIT_EXECUTION_REQUIRED"):
            collect(
                as_of=AS_OF, token=TOKEN, transport=lambda *_: b"{}",
                popular_position_probe=True, diagnostic=False,
            )

    def test_no_exec_cli_does_not_load_credentials_or_network(self):
        stdout = io.StringIO()
        with patch("sys.stdout", stdout):
            result = main(["--date", "2026-10-23"])
        self.assertEqual(0, result)
        self.assertEqual("NOT_EXECUTED", json.loads(stdout.getvalue())["status"])
        self.assertNotIn(TOKEN, stdout.getvalue())

    def test_cli_refuses_live_without_private_token_file(self):
        stdout = io.StringIO()
        with patch("sys.stdout", stdout):
            result = main(["--date", "2026-10-23", "--execute-read"])
        self.assertEqual(2, result)
        self.assertEqual("REFUSED", json.loads(stdout.getvalue())["status"])

    def test_bad_date_and_tokens_refuse_without_transport(self):
        for v in ("x", "123", "", None):
            with self.subTest(v=v), self.assertRaises(YandexLiveDenied):
                collect(as_of=AS_OF, token=v, transport=lambda *_: b"{}")
        with self.assertRaises(YandexLiveDenied):
            collect(as_of="2026-10-23", token=TOKEN, transport=lambda *_: b"{}")


if __name__ == "__main__":
    unittest.main()
