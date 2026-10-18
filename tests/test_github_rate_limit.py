"""Synthetic GitHub token-scoped official API limits - zero network calls."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from urllib.error import HTTPError

from control_center import github_rate_limit as gh
from control_center.provider_registry import registry

NOW=datetime(2026,10,18,17,tzinfo=timezone.utc)


class Answer:
    status=200
    def __init__(self,body):self.body=body
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def read(self,n):return self.body[:n]


class GitHubRateLimitTests(unittest.TestCase):
    def test_independent_bucket_and_zero_limit(self):
        data={"resources":{
            "core":{"limit":5000,"used":4000,"remaining":1000,
                    "reset":int((NOW+timedelta(hours=1)).timestamp())},
            "search":{"limit":30,"used":30,"remaining":0,
                      "reset":int((NOW+timedelta(minutes=1)).timestamp())},
            "graphql":{"limit":0,"used":0,"remaining":0,
                       "reset":int((NOW+timedelta(hours=1)).timestamp())},
            "private_resource":{"limit":1000000,"used":100000,"remaining":900000,
                                "reset":int((NOW+timedelta(hours=1)).timestamp())}}}
        result=gh.parse(json.dumps(data).encode(),now=NOW)
        self.assertEqual(result["status"],"ok")
        self.assertEqual([i["resource"] for i in result["resources"]],[
            "core","search","graphql"])
        self.assertEqual([i["status"] for i in result["resources"]],[
            "low","exhausted","unknown"])
        with TemporaryDirectory() as d:
            p=Path(d)/"gh.json"
            gh.save(result,p)
            projected=registry(codex_path=Path(d)/"codex",
                               desktop_path=Path(d)/"dc",
                               cloudflare_path=Path(d)/"cf",
                               github_path=p,now=NOW)["providers"][3]
            self.assertEqual(projected["status"],"low")
            self.assertEqual(projected["source_kind"],"official_api")
            self.assertEqual(len(projected["windows"]),3)
            self.assertEqual(projected["windows"][0]["quota_limit"],5000)
            self.assertEqual(projected["windows"][1]["remaining"],0)
            self.assertEqual(projected["windows"][2]["used_percent"],None)
            self.assertEqual(projected["notes"],"per_token_rate_limit_collected")

    def test_http_errors_only_fixed_status_no_raw_body(self):
        with TemporaryDirectory() as d:
            token=Path(d)/"key"
            token.write_text("x"*45)
            token.chmod(0o600)
            def deny(status):
                def request(req,timeout):
                    self.assertEqual(req.full_url,"https://api.github.com/rate_limit")
                    self.assertEqual(req.get_method(),"GET")
                    self.assertEqual(timeout,7)
                    raise HTTPError(req.full_url,status,"sensitive text",{},None)
                return request
            for status,expected in [(401,"auth_required"),(403,"auth_required"),
                                    (429,"throttled"),(500,"unavailable")]:
                with self.subTest(status=status):
                    data=gh.read(token,now=NOW,transport=deny(status))
                    self.assertEqual(data["status"],expected)
                    self.assertEqual(data["resources"],[])
                    self.assertNotIn("sensitive",str(data))

    def test_reject_unsafe_rate_limit_values(self):
        sample={"resources":{"core":{"limit":100,"used":40,"remaining":60,
                         "reset":int((NOW+timedelta(hours=1)).timestamp())}}}
        for pair in [("remaining",-1),("remaining",101),("used",True),
                     ("limit",-1),("reset","999")]:
            with self.subTest(field=pair):
                data=json.loads(json.dumps(sample))
                data["resources"]["core"][pair[0]]=pair[1]
                with self.assertRaises(gh.GitHubQuotaError):
                    gh.parse(json.dumps(data).encode(),now=NOW)

    def test_read_only_token_configured_not_connected_without_snapshot(self):
        with TemporaryDirectory() as d:
            report=registry(codex_path=Path(d)/"codex",
                            desktop_path=Path(d)/"dc",cloudflare_path=Path(d)/"cf",
                            github_path=Path(d)/"missing",now=NOW)["providers"][3]
            self.assertEqual(report["status"],"unknown")
            self.assertEqual(report["windows"],[])
            key=Path(d)/"token";key.write_text("x"*40);key.chmod(0o644)
            with self.assertRaises(gh.GitHubQuotaError):
                gh.read(key,now=NOW)

    def test_malformed_stale_snapshot_fails_closed(self):
        with TemporaryDirectory() as d:
            path=Path(d)/"gh.json"
            old=gh.parse(json.dumps({"resources":{"core":{
              "limit":60,"used":30,"remaining":30,
              "reset":int((NOW+timedelta(hours=1)).timestamp())}}}).encode(),
              now=NOW-timedelta(days=1))
            gh.save(old,path)
            self.assertEqual(gh.snapshot(path,now=NOW)["status"],"unknown")
            path.write_text("{bad}")
            self.assertEqual(gh.snapshot(path,now=NOW)["status"],"unknown")


if __name__=="__main__":
    unittest.main()
