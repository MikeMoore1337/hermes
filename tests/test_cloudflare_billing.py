"""Offline contracts for Cloudflare's delayed Billable Usage API. No network."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock
from urllib.error import HTTPError

from control_center import cloudflare_billing as cf
from control_center.provider_registry import registry

NOW = datetime(2026,10,18,13,0,tzinfo=timezone.utc)
ACCOUNT = "a" * 32


def record(day: str, *, quantity=1200, unit="Neurons",
           service="Workers AI", family="Workers AI"):
    date = datetime.fromisoformat(day).replace(tzinfo=timezone.utc)
    return {"ServiceName":service,"ServiceFamilyName":family,
            "ConsumedQuantity":quantity,"ConsumedUnit":unit,
            "ChargePeriodStart":date.isoformat().replace("+00:00","Z"),
            "ChargePeriodEnd":(date+timedelta(days=1)).isoformat().replace("+00:00","Z")}


class Response:
    status=200
    def __init__(self,body): self._body=body
    def read(self,n):return self._body[:n]
    def __enter__(self):return self
    def __exit__(self,*_):return False


class BillingTests(unittest.TestCase):
    def test_official_completed_day_only_current_quota_never_deducted(self):
        rows=[record("2026-10-17",quantity=3100),
              record("2026-10-18",quantity=5000),
              record("2026-10-16",quantity=400,unit="Tokens",service="R2"),
              record("2026-10-16",quantity=850)]
        # An unrecognized Workers AI unit invalidates the entire observation,
        # not merely that row, even if another Neuron record is present.
        rows.pop(2)
        out=cf.parse(json.dumps({"success":True,"result":rows}).encode(),now=NOW)
        self.assertEqual(out["status"],"ok")
        self.assertEqual(out["days"],[{"day":"2026-10-16","neurons":850},
                                      {"day":"2026-10-17","neurons":3100}])
        self.assertEqual(out["last_complete_day"],"2026-10-17")
        with TemporaryDirectory() as tmp:
            path=Path(tmp)/"billing.json"
            cf.save(out,path)
            view=registry(codex_path=Path(tmp)/"c.json",
                          desktop_path=Path(tmp)/"d.json",
                          cloudflare_path=path,now=NOW)["providers"][0]
            self.assertEqual(view["billing_history"],out["days"])
            self.assertEqual(view["status"],"unknown")
            self.assertEqual(view["notes"],"official_delayed_historical_usage")
            self.assertIsNone(view["windows"][0]["remaining"])
            self.assertIsNone(view["windows"][0]["used_percent"])

    def test_non_neuron_unit_is_unknown_not_estimate(self):
        for payload in [
            {"success":True,"result":[record("2026-10-17",unit="Tokens")]},
            {"success":True,"result":[record("2026-10-17",unit="Requests")]},
            {"success":True,"result":[]},
            {"success":False,"result":[record("2026-10-17")]},
            {"success":True,"result":[record("2026-10-17",quantity=-1)]},
        ]:
            with self.subTest(payload=payload):
                try: out=cf.parse(json.dumps(payload).encode(),now=NOW)
                except cf.BillingError: continue
                self.assertEqual(out["status"],"unknown")

    def test_billing_scopes_and_outages_are_fixed_statuses(self):
        with TemporaryDirectory() as tmp:
            secret=Path(tmp)/"token"
            secret.write_text("x"*40)
            secret.chmod(0o600)
            def failing(code):
                def _request(request,timeout):
                    self.assertEqual(request.get_method(),"GET")
                    self.assertIn("/billable-usage?",request.full_url)
                    self.assertNotIn("ai/run",request.full_url)
                    self.assertEqual(timeout,7)
                    raise HTTPError(request.full_url,code,"NO_RAW_PAYLOAD",{},None)
                return _request
            for code,status in [(401,"auth_required"),(403,"auth_required"),
                                (429,"throttled"),(500,"unavailable"),
                                (503,"unavailable")]:
                with self.subTest(code=code):
                    result=cf.read(secret,ACCOUNT,now=NOW,transport=failing(code))
                    self.assertEqual(result["status"],status)
                    self.assertNotIn("NO_RAW_PAYLOAD",str(result))
                    self.assertEqual(result["days"],[])

    def test_malformed_token_or_empty_token_never_network(self):
        with TemporaryDirectory() as tmp:
            p=Path(tmp)/"token"
            for value in ("", "short","x"*40):
                p.write_text(value)
                p.chmod(0o644)
                with self.subTest(value=value), self.assertRaises(cf.BillingError):
                    cf.read(p,ACCOUNT,now=NOW,transport=Mock())
            with self.assertRaises(cf.BillingError):
                cf.read(p,"-o ProxyCommand",now=NOW,transport=Mock())

    def test_ro_provider_body_no_leaked_account(self):
        with TemporaryDirectory() as tmp:
            key=Path(tmp)/"secret"
            key.write_text("x"*40)
            key.chmod(0o600)
            response=json.dumps({"success":True,"result":[record("2026-10-17")]})
            seen=[]
            def runner(request,timeout):
                seen.append(request.full_url)
                return Response(response.encode())
            record_=cf.read(key,ACCOUNT,now=NOW,transport=runner)
            self.assertEqual(record_["status"],"ok")
            self.assertNotIn(ACCOUNT,json.dumps(record_))
            self.assertEqual(len(seen),1)
            self.assertTrue(seen[0].startswith("https://api.cloudflare.com/client/v4/accounts/"))

    def test_billing_denial_does_not_claim_ai_model_auth_failure(self):
        with TemporaryDirectory() as tmp:
            path=Path(tmp)/"billing.json"
            cf.save(cf.error("auth_required",NOW),path)
            result=registry(cloudflare_path=path,codex_path=Path(tmp)/"codex",
                            desktop_path=Path(tmp)/"dc",github_path=Path(tmp)/"gh",
                            now=NOW)["providers"][0]
            self.assertEqual(result["status"],"unknown")
            self.assertEqual(result["billing_status"],"auth_required")
            self.assertEqual(result["notes"],"billing_auth_required")
            self.assertIsNone(result["windows"][0]["remaining_percent"])

    def test_invalid_saved_snapshot_cannot_fake_neurons(self):
        with TemporaryDirectory() as tmp:
            p=Path(tmp)/"billing.json"
            p.write_text(json.dumps({"schema":1,"source":"cloudflare-billable-usage-api",
                "status":"ok","observed_at":cf.iso(NOW),"days":[
                    {"day":"2026-10-18","neurons":10000}],
                "last_complete_day":"2026-10-18"}))
            self.assertEqual(cf.snapshot(p,now=NOW)["status"],"unknown")
            p.write_text("{invalid")
            self.assertEqual(cf.snapshot(p,now=NOW)["status"],"unknown")


if __name__=="__main__":
    unittest.main()
