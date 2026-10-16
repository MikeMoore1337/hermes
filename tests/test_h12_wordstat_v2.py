"""Yandex Wordstat contract and billing NO-GO: synthetic offline cases."""
from __future__ import annotations

import json
import unittest
from decimal import Decimal
from io import StringIO
from unittest.mock import patch

from statejnik_integration import wordstat_v2 as ws


class WordstatOfflineTests(unittest.TestCase):
    def test_current_official_provider_and_fixed_post_routes(self):
        c = ws.catalog()
        self.assertEqual(c["api_host"], "searchapi.api.cloud.yandex.net")
        self.assertEqual(c["http_method"], "POST")
        self.assertEqual(c["requires_provider_role"], "search-api.webSearch.user")
        self.assertEqual(c["required_scope"], "yc.search-api.execute")
        self.assertEqual(c["methods"]["GetTop"]["path"],
                         "https://searchapi.api.cloud.yandex.net/v2/wordstat/topRequests")
        self.assertEqual(c["methods"]["GetDynamics"]["path"],
                         "https://searchapi.api.cloud.yandex.net/v2/wordstat/dynamics")
        self.assertEqual(c["methods"]["GetRegionsDistribution"]["path"],
                         "https://searchapi.api.cloud.yandex.net/v2/wordstat/regions")
        self.assertEqual(c["methods"]["GetRegionsTree"]["path"],
                         "https://searchapi.api.cloud.yandex.net/v2/wordstat/getRegionsTree")
        self.assertNotIn("api.wordstat.yandex.net", json.dumps(c))

    def test_no_provider_billing_or_publishing_enabled(self):
        c = ws.catalog()
        for flag in ("provider_access_verified", "billing_hard_limit_verified",
                     "automatic_retries", "paid_requests_enabled",
                     "free_requests_enabled", "credentials_loaded",
                     "any_request_executed", "yfc_write_enabled",
                     "publication_enabled"):
            self.assertFalse(c[flag])
        self.assertEqual(c["daily_spend_cap_rub"], "0")

    def test_static_price_reference_not_account_verified(self):
        for method, unit in (("GetTop", Decimal("20")),
                             ("GetDynamics", Decimal("20")),
                             ("GetRegionsDistribution", Decimal("50")),
                             ("GetRegionsTree", Decimal("0"))):
            for calls in (0, 1, 1000, 10_000):
                with self.subTest(method=method, calls=calls):
                    p = ws.reference_estimate(method, calls)
                    self.assertEqual(Decimal(p["reference_cost_rub"]),
                                     unit * Decimal(calls) / Decimal(1000))
                    self.assertFalse(p["request_sent"])
                    self.assertFalse(p["provider_account_cost_confirmed"])
                    self.assertEqual(p["daily_spend_cap_rub"], "0")

    def test_invalid_methods_and_call_counts_fail_closed(self):
        for method, count in (("legacy_wordstat", 1), ("GetTop", -1),
                              ("GetTop", True), ("GetTop", 100_001),
                              ("GetTop", 2.5), (None, 1), ("", 1)):
            with self.subTest(method=method, count=count):
                with self.assertRaises(ws.WordstatDenied):
                    ws.reference_estimate(method, count)

    def test_no_network_or_token_imports_and_no_sensitive_cli_output(self):
        import inspect
        source = inspect.getsource(ws)
        for token in ("import requests", "import urllib", "socket.", "http.client",
                      "subprocess", "getenv(", "environ[", "authorization:", "api-key "):
            self.assertNotIn(token, source.lower())
        with patch("sys.stdout", new_callable=StringIO) as output:
            self.assertEqual(ws.main(), 0)
        packet = json.loads(output.getvalue())
        self.assertEqual(packet["status"], "PROVIDER_ADMISSION_BLOCKED")
        self.assertNotIn("WORDSTAT_TOKEN", output.getvalue())
        self.assertNotIn("API_KEY=", output.getvalue())


if __name__ == "__main__":
    unittest.main()
