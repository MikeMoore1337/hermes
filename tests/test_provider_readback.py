"""#295 read-back only emits fixed metadata and proves no-cookie API denial."""
from __future__ import annotations

from urllib.error import HTTPError
from unittest.mock import Mock, patch
from contextlib import contextmanager
import json
import unittest

from scripts.h15_provider_readback import assess, local_http, PROVIDER_IDS, main

def snapshot():
    return {"schema":1,"read_only":True,"providers":[{
        "id":id_,"status":"unknown","source_kind":"unknown","windows":[],
        "notes":"secret-example", "title":"token-secret-account", "observed_at":None,
    } for id_ in PROVIDER_IDS]}

class Response:
    status=200
    def __enter__(self): return self
    def __exit__(self,*args): return None


class ProviderReadbackTests(unittest.TestCase):
    def test_metadata_only_and_unknown_is_not_a_failed_collector(self):
        report=assess(snapshot(),health_code=200,denied_code=401)
        self.assertEqual(report["health"],"ok")
        self.assertEqual(report["unauthenticated_registry"],"denied")
        self.assertEqual([x["id"] for x in report["providers"]],list(PROVIDER_IDS))
        encoded=json.dumps(report)
        self.assertNotIn("token-secret-account",encoded)
        self.assertNotIn("secret-example",encoded)
        self.assertTrue(all(x["status"]=="unknown" for x in report["providers"]))

    def test_anonymous_200_never_counts_as_safe(self):
        report=assess(snapshot(),health_code=200,denied_code=200)
        self.assertEqual(report["unauthenticated_registry"],"unverified")

    def test_strict_id_allowlist(self):
        for obj in ({"schema":1,"read_only":True,"providers":[]},
                    {"schema":1,"read_only":False,"providers":snapshot()["providers"]},
                    {"schema":1,"read_only":True,"providers":snapshot()["providers"][:-1]},
                    {"schema":1,"read_only":True,"providers":[*snapshot()["providers"],
                        {"id":"other","status":"ok","windows":[]}]}):
            with self.subTest(snapshot=obj),self.assertRaises(ValueError):
                assess(obj,health_code=200,denied_code=401)

    def test_local_requests_no_auth_and_fixed_uris(self):
        def transport(request,timeout):
            self.assertEqual(timeout,3)
            self.assertEqual(request.full_url,"http://127.0.0.1:9133/healthz")
            self.assertEqual(request.get_header("Host"),"hermes.mikemoore.top")
            self.assertIsNone(request.get_header("Authorization"))
            self.assertIsNone(request.get_header("Cookie"))
            return Response()
        self.assertEqual(local_http("/healthz",transport=transport),200)
        for path in ("/other", "/api/providers/registry?x=1",
                     "https://api.cloudflare.com"):
            with self.assertRaises(ValueError):
                local_http(path,transport=transport)

    def test_cli_no_sensitive_stdout_and_exit_codes(self):
        import io
        from contextlib import redirect_stdout
        with patch("scripts.h15_provider_readback.registry",
                   return_value=snapshot()),patch(
                   "scripts.h15_provider_readback.local_http",
                   side_effect=[200,401]):
            out=io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(main(),0)
            self.assertEqual(json.loads(out.getvalue())["providers"][0]["id"],
                             "cloudflare_workers_ai")
        with patch("scripts.h15_provider_readback.registry",
                   return_value=snapshot()),patch(
                   "scripts.h15_provider_readback.local_http",
                   side_effect=[200,200]):
            out=io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(main(),1)

if __name__ == "__main__":
    unittest.main()
