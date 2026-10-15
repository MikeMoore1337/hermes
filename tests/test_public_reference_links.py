"""H-16 external reference probes: fixed public URLs, no redirects or CI."""
from __future__ import annotations

import io
import json
import socket
import unittest
from unittest.mock import Mock, patch

from scripts import check_public_reference_links as audit


class PublicReferenceTests(unittest.TestCase):
    def test_http_status_distinguishes_broken_and_transient(self):
        expectations = {
            200: "HEALTHY", 204: "HEALTHY", 404: "BROKEN",
            410: "BROKEN", 301: "REDIRECT_UNFOLLOWED",
            302: "REDIRECT_UNFOLLOWED", 307: "REDIRECT_UNFOLLOWED",
            308: "REDIRECT_UNFOLLOWED", 403: "UNKNOWN",
            429: "UNKNOWN", 500: "UNKNOWN", 503: "UNKNOWN",
            0: "UNKNOWN", "200": "UNKNOWN",
        }
        for status, expected in expectations.items():
            with self.subTest(status=status):
                self.assertEqual(audit.classify(status), expected)

    def test_all_ok_requires_both_real_healthy_observations(self):
        result = audit.audit(runner=lambda _: 200)
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["probes_attempted"], 2)
        self.assertFalse(result["redirections_followed"])

    def test_404_requires_review_not_background_repair(self):
        values = iter((200, 404))
        result = audit.audit(runner=lambda _: next(values))
        self.assertEqual(result["status"], "REVIEW")
        self.assertEqual(result["results"][1]["state"], "BROKEN")

    def test_redirect_429_forbidden_timeout_do_not_become_broken(self):
        for second in (301, 403, 429, 503):
            with self.subTest(second=second):
                outcomes = iter((200, second))
                r = audit.audit(runner=lambda _: next(outcomes))
                self.assertEqual(r["status"], "UNKNOWN")
                self.assertNotIn("BROKEN", [x["state"] for x in r["results"]])
        r = audit.audit(runner=lambda _: (_ for _ in ()).throw(
            audit.PublicProbeDenied("network_or_timeout")))
        self.assertEqual(r["status"], "UNKNOWN")

    def test_dns_with_private_or_mixed_addresses_is_refused(self):
        def record(addr, family=socket.AF_INET):
            return (family, socket.SOCK_STREAM, 6, "", (addr, 443))
        for rows in (
            [record("127.0.0.1")],
            [record("8.8.8.8"), record("192.168.1.2")],
            [],
        ):
            with self.subTest(rows=rows):
                with patch.object(audit.socket, "getaddrinfo", return_value=rows):
                    with self.assertRaises(audit.PublicProbeDenied):
                        audit.public_address("api.crossref.org")

    def test_arbitrary_domain_rejected_before_dns(self):
        with patch.object(audit.socket, "getaddrinfo") as dns:
            with self.assertRaisesRegex(audit.PublicProbeDenied,
                                        "host_not_allowlisted"):
                audit.public_address("127.0.0.1")
        dns.assert_not_called()

    def test_fixed_https_head_without_redirect_or_response_body(self):
        client = Mock()
        client.getresponse.return_value.status = 200
        with patch.object(audit, "public_address", return_value="8.8.8.8"):
            with patch.object(audit, "PinnedTLS", return_value=client) as factory:
                self.assertEqual(audit.request_one("crossref-public-doi"), 200)
        factory.assert_called_once_with("api.crossref.org", "8.8.8.8")
        args, kw = client.request.call_args
        self.assertEqual(args[0], "HEAD")
        self.assertTrue(args[1].startswith("/works/"))
        self.assertNotIn("Authorization", kw["headers"])
        self.assertNotIn("Cookie", kw["headers"])
        client.close.assert_called_once()
        client.getresponse.return_value.read.assert_not_called()

    def test_unknown_probe_never_makes_network_call(self):
        with patch.object(audit, "PinnedTLS") as client:
            with self.assertRaises(audit.PublicProbeDenied):
                audit.request_one("https://private.example/secret")
        client.assert_not_called()

    def test_default_cli_has_no_network_or_file_writes(self):
        with patch.object(audit, "audit") as observer:
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(audit.main([]), 0)
        observer.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())["status"], "NOT_EXECUTED")

    def test_manual_unknown_has_non_success_exit_without_sensitive_urls(self):
        with patch.object(audit, "audit", return_value={
            "status": "UNKNOWN", "results": [],
        }):
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(audit.main(["--execute"]), 2)
        self.assertNotIn("http", out.getvalue())
        self.assertEqual(json.loads(out.getvalue())["status"], "UNKNOWN")

    def test_no_new_hosts_or_crawling_without_source_change(self):
        self.assertEqual(len(audit.PROBES), audit.MAX_PROBES)
        self.assertEqual({x[0] for x in audit.PROBES.values()},
                         {"api.crossref.org", "europepmc.org"})
        for _, path in audit.PROBES.values():
            self.assertTrue(path.startswith("/"))
            self.assertNotIn("?", path)


if __name__ == "__main__":
    unittest.main()
