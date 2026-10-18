"""H-02: private alert sender timer disabled/inactive -> persistent incident.

No live unit disables, no Telegram calls and no production database mutations.
"""
from __future__ import annotations

import json
import sqlite3
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from ops_watch import collector
from ops_watch.core import InputError, analyze
from ops_watch.incident_preview import render

NOW = datetime(2026,10,15,7,20,tzinfo=UTC)
GOOD = {"loaded":True,"enabled":True,"active":True}
NEWS = {
    "last_successful_discovery_at": NOW.isoformat(),
    "consecutive_discovery_failures":0,"consecutive_drain_failures":0,
    "pending_jobs":0,"oldest_pending_age_seconds":0,
}

class SenderTimerMonitoringTests(unittest.TestCase):
    def test_active_sender_is_not_a_false_incident(self):
        snap=collector.normalized(
            NEWS,NOW,timer_enabled=True,timer_active=True,
            agent_guard=GOOD,alerts_timer=GOOD,
        )
        self.assertEqual(analyze(snap,now=NOW),[])

    def test_sender_timer_is_missing_disabled_or_inactive(self):
        for state,expected in (
            ({"loaded":False,"enabled":False,"active":False},
             {"alert_sender_missing"}),
            ({"loaded":True,"enabled":False,"active":True},
             {"alert_sender_disabled"}),
            ({"loaded":True,"enabled":True,"active":False},
             {"alert_sender_inactive"}),
            ({"loaded":True,"enabled":False,"active":False},
             {"alert_sender_disabled","alert_sender_inactive"}),
        ):
            with self.subTest(expected=expected):
                snap=collector.normalized(
                    NEWS,NOW,timer_enabled=True,timer_active=True,
                    agent_guard=GOOD,alerts_timer=state,
                )
                findings=analyze(snap,now=NOW)
                self.assertEqual({x["code"] for x in findings},expected)
                self.assertTrue(all(x["severity"]=="critical" for x in findings))
                delta={"raised":[x["fingerprint"] for x in findings],"resolved":[]}
                preview=render(delta,findings)
                self.assertEqual({x["code"] for x in preview},expected)
                self.assertTrue(all(x["phase"]=="new" for x in preview))
                self.assertNotIn("token",str(preview).lower())

    def test_untrustworthy_sender_state_is_rejected_not_assumed_healthy(self):
        for bad in (
            {"loaded":True,"enabled":True,"active":"active"},
            {"loaded":True,"enabled":True},
            {"loaded":True,"enabled":1,"active":True},
        ):
            snap=collector.normalized(NEWS,NOW,timer_enabled=True,
                timer_active=True,agent_guard=GOOD,alerts_timer=bad)
            with self.assertRaises(InputError):
                analyze(snap,now=NOW)

    def test_exact_systemctl_read_only_and_strict_output(self):
        valid="LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n"
        with patch.object(collector.subprocess,"run",return_value=subprocess.CompletedProcess([],0,valid,"")) as call:
            self.assertEqual(collector._ops_alert_timer_status(),GOOD)
        self.assertEqual(call.call_args.args[0],[
            "systemctl","show","hermes-ops-alerts.timer","-p","LoadState",
            "-p","ActiveState","-p","UnitFileState","--no-pager",
        ])
        for text in (
            "LoadState=loaded\nActiveState=active\n",
            "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\nSecret=YES\n",
            "LoadState=loaded\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n",
        ):
            with self.subTest(text=text):
                with patch.object(collector.subprocess,"run",return_value=subprocess.CompletedProcess([],0,text,"")):
                    with self.assertRaisesRegex(InputError,"alert_sender_status_unavailable"):
                        collector._ops_alert_timer_status()

    def test_disabled_delivery_is_queued_and_recovery_is_deduplicated(self):
        with tempfile.TemporaryDirectory(prefix="hermes-alert-selfcheck-") as tmp:
            directory=Path(tmp)
            directory.chmod(0o700)
            source=directory/"sanitized-health.json"
            source.write_text(json.dumps({"health":NEWS}),encoding="utf-8")
            disabled={"loaded":True,"enabled":False,"active":True}
            with patch.object(collector,"_state",return_value=True):
                raised=collector.once(
                    source,directory,NOW,agent_guard=GOOD,alerts_timer=disabled)
                again=collector.once(
                    source,directory,NOW,agent_guard=GOOD,alerts_timer=disabled)
                resolved=collector.once(
                    source,directory,NOW,agent_guard=GOOD,alerts_timer=GOOD)
                healthy=collector.once(
                    source,directory,NOW,agent_guard=GOOD,alerts_timer=GOOD)
            self.assertEqual(raised["changes"]["raised"],["ops:alert_sender_disabled"])
            self.assertEqual(raised["queued_incident_events"],1)
            self.assertEqual(again["queued_incident_events"],1)
            self.assertEqual(resolved["changes"]["resolved"],["ops:alert_sender_disabled"])
            self.assertEqual(resolved["queued_incident_events"],2)
            self.assertEqual(healthy["queued_incident_events"],2)
            with sqlite3.connect((directory/"incidents.sqlite3").as_uri()+"?mode=ro",uri=True) as database:
                rows=database.execute(
                    "SELECT phase,title FROM events ORDER BY id"
                ).fetchall()
            self.assertEqual([row[0] for row in rows],["new","resolved"])
            self.assertIn("Восстановлено",rows[1][1])

    def test_main_wires_real_timer_probe_once_and_never_restarts_it(self):
        with patch.object(collector,"_ops_alert_timer_status",return_value=GOOD) as status:
            with patch.object(collector,"_ops_alert_service_status",
                              return_value={"failed":False}) as service:
                with patch.object(collector,"once",return_value={
                    "status":"ok","changes":{"raised":[],"resolved":[]},
                    "active_codes":[],"queued_incident_events":0,
                }) as collector_run:
                    self.assertEqual(collector.main(),0)
        status.assert_called_once()
        service.assert_called_once()
        collector_run.assert_called_once_with(alerts_timer=GOOD,
                                               alerts_service={"failed":False},
                                               infrastructure_dir=collector.INFRASTRUCTURE_ROOT,
                                               quota_paths={"codex": collector.Q_CODEX,
                                                            "desktop": collector.Q_DESKTOP,
                                                            "cloudflare": collector.Q_CF,
                                                            "github": collector.Q_GITHUB})


if __name__=="__main__":
    unittest.main()
