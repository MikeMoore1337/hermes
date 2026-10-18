"""Issue #295: truthful quotas and owner-only provider registry, no network."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from control_center.auth import AuthConfig, OAuthService, ORIGIN
from control_center.codex_usage import normalize as codex_normalize, save_snapshot as codex_save
from control_center.desktop_commander import normalize as dc_normalize, save_snapshot as dc_save
from control_center.provider_registry import registry
from control_center.server import make_handler

NOW = datetime(2026, 10, 18, 23, 40, tzinfo=timezone.utc)


class ProviderRegistryContract(unittest.TestCase):
    def test_cloudflare_limit_but_usage_strictly_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = registry(codex_path=Path(tmp)/"codex.json",
                            desktop_path=Path(tmp)/"dc.json",cloudflare_path=Path(tmp)/"cf.json",now=NOW)
        self.assertEqual(data["schema"], 1)
        self.assertTrue(data["read_only"])
        self.assertEqual([x["id"] for x in data["providers"]], [
            "cloudflare_workers_ai","codex","desktop_commander","github_api"])
        cf = data["providers"][0]
        self.assertEqual(cf["status"], "unknown")
        self.assertEqual(cf["notes"], "account_usage_unavailable")
        self.assertEqual(cf["windows"][0]["quota_limit"], 10000)
        self.assertEqual(cf["windows"][0]["unit"], "neurons")
        self.assertEqual(cf["windows"][0]["reset_at_utc"], "2026-10-19T00:00:00Z")
        for key in ("used", "remaining", "used_percent", "remaining_percent"):
            self.assertIsNone(cf["windows"][0][key])
        self.assertEqual(cf["windows"][0]["source_kind"], "unknown")
        self.assertEqual(data["providers"][1]["status"], "not_connected")
        self.assertEqual(data["providers"][2]["status"], "not_connected")
        self.assertEqual(data["providers"][3]["status"], "unknown")

    def test_timezone_canonical_and_no_fake_reset_after_midnight(self):
        offset_now = datetime(2026, 10, 19, 1, 10, tzinfo=timezone(timedelta(hours=3)))
        with tempfile.TemporaryDirectory() as tmp:
            data=registry(codex_path=Path(tmp)/"none",desktop_path=Path(tmp)/"missing",
                          cloudflare_path=Path(tmp)/"cf.json",now=offset_now)
        self.assertEqual(data["providers"][0]["windows"][0]["reset_at_utc"],
                         "2026-10-19T00:00:00Z")
        with self.assertRaises(ValueError):
            registry(now=datetime(2026,10,18,12))

    def test_codex_official_windows_are_independent_and_not_absolute(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=Path(tmp)/"codex.json"
            snap=codex_normalize({
                "ordinaryUsageAllowed":True,
                "rateLimitsByLimitId":{"codex":{
                    "primary":{"usedPercent":33.5,"windowDurationMins":300,
                               "resetsAt":int((NOW+timedelta(hours=1)).timestamp())},
                    "secondary":{"usedPercent":80,"windowDurationMins":10080,
                                 "resetsAt":int((NOW+timedelta(days=4)).timestamp())}}}},
                now=NOW)
            codex_save(snap,c)
            result=registry(codex_path=c,desktop_path=Path(tmp)/"dc",cloudflare_path=Path(tmp)/"cf.json",now=NOW)
            entry=result["providers"][1]
            self.assertEqual(entry["status"],"low")
            self.assertEqual(entry["source_kind"],"official_api")
            self.assertEqual(len(entry["windows"]),2)
            self.assertEqual([w["label"] for w in entry["windows"]],["300 мин","10080 мин"])
            self.assertEqual([w["used_percent"] for w in entry["windows"]],[33.5,80])
            self.assertEqual([w["remaining_percent"] for w in entry["windows"]],[66.5,20])
            self.assertTrue(all(w["quota_limit"] is None for w in entry["windows"]))

    def test_desktop_commander_connected_devices_do_not_override_exhausted(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"dc.json"
            snap=dc_normalize({"remote_calls_left_pct":0},
                "Device: vps1777112993\n Status: online\n",now=NOW)
            dc_save(snap,p)
            result=registry(desktop_path=p,codex_path=Path(tmp)/"codex",cloudflare_path=Path(tmp)/"cf.json",now=NOW)
            item=result["providers"][2]
            self.assertEqual(item["status"],"exhausted")
            self.assertEqual(item["notes"],"remote_calls_blocked")
            self.assertEqual(item["windows"][0]["used_percent"],100)
            self.assertEqual(item["windows"][0]["remaining_percent"],0)

    def test_provider_reports_no_numeric_quota_not_low(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            payload={"status":"monitored","quota_remaining_percent":None,
                     "observed_at":NOW.isoformat(),"remote_execution":"unverified"}
            with patch("control_center.provider_registry.read_desktop_snapshot",
                       return_value=payload):
                items=registry(codex_path=Path(tmp)/"codex.json",
                               desktop_path=Path(tmp)/"dc.json",cloudflare_path=Path(tmp)/"cf.json",now=NOW)["providers"]
            self.assertEqual(items[2]["status"],"unknown")
            self.assertEqual(items[2]["windows"],[])
            self.assertEqual(items[2]["source_kind"],"unknown")

    def test_error_snapshot_is_not_a_quota_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=Path(tmp)/"codex.json";d=Path(tmp)/"dc.json"
            c.write_text('{"secret":"sensitive quota"}',encoding="utf-8")
            d.write_text("{invalid}",encoding="utf-8")
            result=registry(codex_path=c,desktop_path=d,cloudflare_path=Path(tmp)/"cf.json",now=NOW)
            for x in result["providers"][1:3]:
                self.assertEqual(x["status"],"unknown")
                self.assertEqual(x["windows"],[])
                self.assertNotIn("sensitive",str(x))

    def test_stale_snapshot_not_represented_as_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=Path(tmp)/"codex.json"
            snap=codex_normalize({"ordinaryUsageAllowed":True,
                                  "rateLimits":{"primary":{
                                      "usedPercent":60,"windowDurationMins":300}}},
                                  now=NOW-timedelta(hours=2))
            codex_save(snap,c)
            result=registry(codex_path=c,desktop_path=Path(tmp)/"dc",now=NOW)
            self.assertEqual(result["providers"][1]["status"],"stale")
            self.assertEqual(result["providers"][1]["windows"],[])


class RegistryAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        root=Path(self.tmp.name)
        self.code=root/"codex.json"
        self.dc=root/"dc.json"
        self.srv=ThreadingHTTPServer(("127.0.0.1",0),make_handler(
            root/"missing-overview.json",codex_path=self.code,
            desktop_commander_path=self.dc))
        self.thread=Thread(target=self.srv.serve_forever,daemon=True)
        self.thread.start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=4)
        self.tmp.cleanup()

    def request(self,path):
        req=Request(f"http://127.0.0.1:{self.srv.server_port}{path}",
                    headers={"Host":"hermes.mikemoore.top"})
        try: response=urlopen(req,timeout=2)
        except HTTPError as error: response=error
        with response:return response.status,response.headers,response.read()

    def test_allowlisted_get_only_and_static_assets(self):
        status,headers,raw=self.request("/api/providers/registry")
        self.assertEqual(status,200)
        self.assertEqual(headers["Cache-Control"],"no-store")
        self.assertTrue(json.loads(raw)["read_only"])
        self.assertEqual(self.request("/api/providers/registry?token=secret")[0],404)
        for name in ("/provider-quota.js","/provider-quota.css"):
            status,_,raw=self.request(name)
            self.assertEqual(status,200)
            self.assertGreater(len(raw),200)

    def test_github_oauth_anonymous_denied(self):
        from control_center.auth import AuthConfig
        config=AuthConfig("github",ORIGIN,"Ov23abcdefghijk",
                          "test-client-secret-long-enough",42142321,
                          b"test signing secret longer than 32 characters")
        oauth=OAuthService(config)
        server=ThreadingHTTPServer(("127.0.0.1",0),make_handler(
            Path(self.tmp.name)/"missing-overview.json",
            codex_path=self.code,desktop_commander_path=self.dc,
            auth_config=config,oauth_service=oauth,
            cloudflare_billing_path=Path(self.tmp.name)/"cf.json"))
        thread=Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            req=Request(f"http://127.0.0.1:{server.server_port}/api/providers/registry",
                        headers={"Host":"hermes.mikemoore.top"})
            with self.assertRaises(HTTPError) as context:
                urlopen(req,timeout=2)
            self.assertEqual(context.exception.code,401)
        finally:
            server.shutdown();server.server_close();thread.join(timeout=4)


if __name__=="__main__":
    unittest.main()
