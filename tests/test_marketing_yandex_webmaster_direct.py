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
    _verify_host, collect, main, read_private_token, summarized_receipt,
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
        ):
            with self.subTest(item=item):
                data = mocked_sequence()[0]
                send, calls = mocked_sequence(responses=[{"user_id": 100}, item])
                with self.assertRaises(YandexLiveDenied):
                    collect(as_of=AS_OF, token=TOKEN, transport=send)
                self.assertEqual(2, len(calls))

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
            {"hosts": [{"host_id": HOST, "verified": True, "main_mirror": {"host_id": HOST}}]},
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
