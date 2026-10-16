"""H12 outer worker kill budget, output admission and no-network negatives."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from scripts.bounded_subprocess import BoundedProcessError, run_bounded
from statejnik_integration import html_review
from statejnik_integration import supervised_fetch as sf
from statejnik_integration import runner

URL = "https://news.example.org/blog/running"
HOSTS = frozenset({"news.example.org"})
HTML = b"<html><title>Public title</title><h1>Public heading</h1></html>"


def valid_packet():
    return html_review.parse_public_html(URL, HTML, allowed_hosts=HOSTS)


def mock_process(packet=None):
    return subprocess.CompletedProcess(
        ["<redacted command>"], 0,
        json.dumps(packet if packet is not None else valid_packet()).encode("utf-8"), b"",
    )


class SupervisedFetchTests(unittest.TestCase):
    def test_default_rejects_before_any_child_or_dns(self):
        with patch.object(sf, "run_bounded") as running:
            with self.assertRaisesRegex(sf.SupervisedFetchDenied,
                                        "network_not_enabled"):
                sf.fetch_metadata(URL, allowed_hosts=HOSTS)
            running.assert_not_called()

    def test_explicit_child_argv_has_isolated_interpreter_and_exact_host(self):
        with patch.object(sf, "run_bounded", return_value=mock_process()) as running:
            packet = sf.fetch_metadata(URL, allowed_hosts=HOSTS,
                                       network_authorized=True)
        running.assert_called_once()
        args, opts = running.call_args
        cmd = args[0]
        self.assertEqual(cmd[:3], [sys.executable, "-I", "-B"])
        self.assertEqual(cmd[3], str(sf.WORKER))
        self.assertEqual(cmd[4:], [URL, "news.example.org"])
        self.assertEqual(opts["timeout"], 20)
        self.assertEqual(opts["stdout_limit"], 8192)
        self.assertEqual(opts["stderr_limit"], 2048)
        self.assertEqual(set(opts["env"]), {"PATH", "PYTHONDONTWRITEBYTECODE"})
        self.assertEqual(packet["page"]["h1"], "Public heading")
        self.assertFalse(packet["publication_allowed"])
        self.assertIsNone(packet["wordstat_volume"])

    def test_url_with_query_credentials_bad_dns_or_metadata_denied_before_child(self):
        for url in (
            URL + "?token=sensitive", URL + "#fragment", "http://news.example.org/",
            "https://127.0.0.1/", "https://169.254.169.254/latest/meta-data/",
            "https://news.example.org.evil.org/path", "https://evil.org",
            "https://user@news.example.org/", "https://news.example.org:8443/",
        ):
            with self.subTest(url=url):
                with patch.object(sf, "run_bounded") as running:
                    with self.assertRaises(sf.SupervisedFetchDenied):
                        sf.fetch_metadata(url, allowed_hosts=HOSTS,
                                          network_authorized=True)
                    running.assert_not_called()

    def test_timeout_and_child_error_are_sanitized(self):
        for error in (BoundedProcessError("child_timeout"),
                      BoundedProcessError("output_limit_exceeded"),
                      BoundedProcessError("child_nonzero_exit"),
                      OSError("private path secret")):
            with self.subTest(error=type(error).__name__):
                with patch.object(sf, "run_bounded", side_effect=error):
                    with self.assertRaisesRegex(
                        sf.SupervisedFetchDenied, "worker_timeout_or_failure"
                    ) as denied:
                        sf.fetch_metadata(URL, allowed_hosts=HOSTS,
                                          network_authorized=True)
                    self.assertNotIn("private", str(denied.exception))
                    self.assertNotIn("news.example.org", str(denied.exception))

    def test_forged_stdout_status_flags_and_extra_private_content_denied(self):
        base = valid_packet()
        for key, value in (
            ("status", "VERIFIED"), ("requested_url", "https://evil.org"),
            ("source_authenticity_verified", True),
            ("final_redirect_url_verified", True),
            ("search_demand_verified", True),
            ("wordstat_volume", 9999999), ("publication_allowed", True),
            ("yfc_write_allowed", True),
            ("source_sha256", "not-a-sha"), ("source_bytes", 10**10),
            ("page", {"url": URL, "title": "[click](https://evil.org)", "h1": "h"}),
            ("page", {"url": "https://evil.org", "title": "x", "h1": "y"}),
        ):
            with self.subTest(key=key):
                packet = dict(base)
                packet[key] = value
                with patch.object(sf, "run_bounded",
                                  return_value=mock_process(packet)):
                    with self.assertRaisesRegex(
                        sf.SupervisedFetchDenied, "worker_response_denied"
                    ):
                        sf.fetch_metadata(URL, allowed_hosts=HOSTS,
                                          network_authorized=True)
        added = {**base, "PRIVATE_CREDENTIAL": "SECRET"}
        with patch.object(sf, "run_bounded", return_value=mock_process(added)):
            result = sf.fetch_metadata(URL, allowed_hosts=HOSTS,
                                       network_authorized=True)
            self.assertNotIn("PRIVATE_CREDENTIAL", str(result))
            self.assertNotIn("SECRET", str(result))

    def test_invalid_output_utf8_json_or_truncated_denied(self):
        for blob in (b"\xff", b"{", b"[]", b"null", b'{"status":"DENIED"}', b""):
            with self.subTest(blob=blob[:12]):
                completed = subprocess.CompletedProcess([], 0, blob, b"")
                with patch.object(sf, "run_bounded", return_value=completed):
                    with self.assertRaises(sf.SupervisedFetchDenied):
                        sf.fetch_metadata(URL, allowed_hosts=HOSTS,
                                          network_authorized=True)

    def test_real_worker_denies_private_and_invalid_url_without_dns(self):
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(sf.WORKER),
             "http://127.0.0.1/latest/meta-data/", "news.example.org"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8, check=False,
            env={"PATH": os.environ.get("PATH", ""),
                 "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout), {"status": "DENIED"})
        self.assertEqual(result.stderr, b"")

    def test_real_outer_supervisor_kills_stuck_child_process(self):
        began = time.monotonic()
        with self.assertRaisesRegex(BoundedProcessError, "child_timeout"):
            run_bounded(
                [sys.executable, "-I", "-c", "import time;time.sleep(8)"],
                timeout=0.18, stdout_limit=64, stderr_limit=64,
                env={"PATH": os.environ.get("PATH", "")},
            )
        # OS process gets killed, no 8-second wait. Child is reaped.
        self.assertLess(time.monotonic() - began, 6.5)

    def test_no_registration_in_active_agent_runner(self):
        self.assertFalse(runner.catalog()["network_enabled"])
        self.assertFalse(runner.catalog()["paid_providers_enabled"])
        self.assertFalse(runner.catalog()["automatic_publication_enabled"])
        self.assertNotIn("supervised_fetch", runner.run.__code__.co_names)
        self.assertNotIn("fetch_metadata", runner.run.__code__.co_names)


if __name__ == "__main__":
    unittest.main()
