"""Offline #295 quota threshold alerts. No cloud requests or Telegram sends."""
from __future__ import annotations

from datetime import UTC,datetime,timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ops_watch import collector,quota_alerts
from ops_watch.core import InputError,analyze,changes
from ops_watch.incident_preview import render
from ops_watch.advisor_adapter import CODE_MAPPING

NOW=datetime(2026,10,18,12,tzinfo=UTC)
HEALTH={"last_successful_discovery_at":NOW.isoformat(),
        "consecutive_discovery_failures":0,"consecutive_drain_failures":0,
        "pending_jobs":0,"oldest_pending_age_seconds":0}
GUARD={"loaded":True,"enabled":True,"active":True}


def envelope(DC,GH):
    data=collector.normalized(HEALTH,NOW,timer_enabled=True,
        timer_active=True,agent_guard=GUARD)
    data["quota_signals"]={"desktop_commander":DC,"github_api":GH}
    return data


class QuotaAlerts(unittest.TestCase):
    def test_thresholds_and_independent_services(self):
        for status,expected in [
            ("healthy",set()),("warn80",{"quota_desktop_80"}),
            ("warn95",{"quota_desktop_95"}),
            ("exhausted",{"quota_desktop_exhausted"}),
            ("auth_required",{"quota_desktop_auth"}),
            ("stale",{"quota_desktop_stale"}),
            ("unknown",set()),("not_connected",set())]:
            with self.subTest(status=status):
                found=analyze(envelope(status,"not_connected"),now=NOW)
                self.assertEqual({f["code"] for f in found},expected)
        out=analyze(envelope("warn80","exhausted"),now=NOW)
        self.assertEqual({f["code"] for f in out},
                         {"quota_desktop_80","quota_github_exhausted"})
        self.assertTrue(all(f["code"] in CODE_MAPPING for f in out))
        self.assertTrue(all(f["code"] in render(changes([],out),out)[i]["code"] for i,f in enumerate(out)) or
                        {item["code"] for item in render(changes([],out),out)}
                        == {f["code"] for f in out})

    def test_forged_or_missing_quota_provider_fails_closed(self):
        bad=(
            {"desktop_commander":"warn80"},
            {"desktop_commander":"infinite","github_api":"healthy"},
            {"desktop_commander":80,"github_api":"healthy"},
            {"desktop_commander":"healthy","github_api":"healthy","unknown":"ok"})
        for entry in bad:
            with self.subTest(value=entry),self.assertRaises(InputError):
                data=envelope("unknown","not_connected")
                data["quota_signals"]=entry
                analyze(data,now=NOW)

    def test_pure_adapter_does_not_merge_quota_windows(self):
        raw={"providers":[
            {"id":"desktop_commander","status":"exhausted","windows":[{
                "used_percent":100,"label":"remote calls"}]},
            {"id":"github_api","status":"low","windows":[
                {"used_percent":30,"label":"core"},
                {"used_percent":95,"label":"search"}]}]}
        with patch.object(quota_alerts,"registry",return_value=raw):
            result=quota_alerts.observe(now=NOW,paths={"codex":Path("/x"),
                "desktop":Path("/x"),"cloudflare":Path("/x"),"github":Path("/x")})
        self.assertEqual(result,{"desktop_commander":"exhausted",
                                 "github_api":"warn95"})

    def test_disabled_detector_never_reads_global_cloud_data(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d);folder.chmod(0o700)
            src=folder/"news.json";src.write_text(json.dumps({"health":HEALTH}))
            with patch.object(collector,"_state",return_value=True),\
                 patch.object(collector,"_codex_telemetry",return_value=None),\
                 patch.object(collector,"quota_observe") as probe:
                result=collector.once(src,folder,NOW,agent_guard=GUARD)
            self.assertEqual(result["changes"]["raised"],[])
            probe.assert_not_called()

    def test_alert_deduplicates_and_unavailable_does_not_claim_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d);folder.chmod(0o700)
            src=folder/"news.json";src.write_text(json.dumps({"health":HEALTH}))
            params={"codex":folder/"c","desktop":folder/"dc",
                    "cloudflare":folder/"cf","github":folder/"gh"}
            with patch.object(collector,"_state",return_value=True),\
                 patch.object(collector,"_codex_telemetry",return_value=None),\
                 patch.object(collector,"quota_observe",side_effect=[
                 {"desktop_commander":"warn95","github_api":"not_connected"},
                 {"desktop_commander":"warn95","github_api":"not_connected"},
                 {"desktop_commander":"unknown","github_api":"not_connected"},
                 {"desktop_commander":"healthy","github_api":"not_connected"}]):
                a=collector.once(src,folder,NOW,agent_guard=GUARD,quota_paths=params)
                b=collector.once(src,folder,NOW+timedelta(minutes=1),
                                 agent_guard=GUARD,quota_paths=params)
                c=collector.once(src,folder,NOW+timedelta(minutes=2),
                                 agent_guard=GUARD,quota_paths=params)
                d=collector.once(src,folder,NOW+timedelta(minutes=3),
                                 agent_guard=GUARD,quota_paths=params)
            self.assertEqual(a["changes"]["raised"],["ops:quota_desktop_95"])
            self.assertEqual(a["queued_incident_events"],1)
            self.assertEqual(b["changes"]["raised"],[])
            self.assertEqual(c["changes"]["resolved"],[])
            self.assertEqual(d["changes"]["resolved"],["ops:quota_desktop_95"])


if __name__=="__main__":
    unittest.main()
