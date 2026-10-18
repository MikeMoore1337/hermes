"""Hermes #276 persistent read-only agent and networkless Ops Watch contracts."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from device_fabric.presence import DeviceRegistry
from ops_watch.core import analyze
from ops_watch.collector import once
from ops_watch.device_fabric_alerts import observe, certificate_status

NOW = datetime(2026, 10, 18, 16, 30, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]


def prepare(root: Path, *, enabled_minutes: int = 30):
    db = root / "devices.sqlite3"
    reg = DeviceRegistry(db)
    reg.initialize()
    for name in ("windows-pc", "linux-vps"):
        code = reg.request_pair(name, name)
        reg.approve_pair(code)
    gate = root / "ops-watch-presence.json"
    gate.write_text(json.dumps({
        "schema": 1, "devices": ["windows-pc", "linux-vps"],
        "enabled_at": (NOW - timedelta(minutes=enabled_minutes)).isoformat(),
    }))
    gate.chmod(0o600)
    return db, gate


def touch(db: Path, ident: str, *, at: datetime, connected: int):
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE devices SET connected=?, last_seen=? WHERE device_id=?",
                     (connected, at.isoformat(), ident))


def snapshot(fabric):
    return {
        "schema": "hermes-ops-snapshot-v1", "observed_at": NOW.isoformat(),
        "news": {
            "timer_enabled": True, "timer_active": True,
            "last_successful_discovery_at": NOW.isoformat(),
            "consecutive_discovery_failures": 0,
            "consecutive_drain_failures": 0, "pending_jobs": 0,
            "oldest_pending_age_seconds": 0, "recent_provider_rate_limits": 0,
        },
        "device_fabric": fabric,
    }


class PresencePersistenceTests(unittest.TestCase):
    def test_explicit_opt_in_required_and_no_registry_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            self.assertEqual(observe(p / "absent.db", p / "absent.json", now=NOW),
                {"windows-pc": {"status": "not_configured"},
                 "linux-vps": {"status": "not_configured"}})
            self.assertFalse((p / "absent.db").exists())

    def test_two_distinct_grace_windows_and_linux(self):
        with tempfile.TemporaryDirectory() as tmp:
            db, gate = prepare(Path(tmp), enabled_minutes=30)
            touch(db, "windows-pc", at=NOW - timedelta(minutes=15), connected=0)
            touch(db, "linux-vps", at=NOW - timedelta(minutes=15), connected=0)
            report = observe(db, gate, now=NOW)
            self.assertEqual(report["linux-vps"]["status"], "offline")
            self.assertEqual(report["windows-pc"]["status"], "warming")
            self.assertEqual({x["code"] for x in analyze(snapshot(report), now=NOW)},
                             {"device_linux_vps_unavailable"})
            touch(db, "windows-pc", at=NOW - timedelta(minutes=21), connected=0)
            report = observe(db, gate, now=NOW)
            self.assertEqual({x["code"] for x in analyze(snapshot(report), now=NOW)},
                {"device_linux_vps_unavailable", "device_windows_pc_unavailable"})
            touch(db, "linux-vps", at=NOW - timedelta(seconds=9), connected=1)
            touch(db, "windows-pc", at=NOW - timedelta(seconds=5), connected=1)
            self.assertEqual({x["status"] for x in observe(db, gate, now=NOW).values()},
                             {"online"})
            self.assertEqual(analyze(snapshot(observe(db, gate, now=NOW)), now=NOW), [])

    def test_recent_offline_and_not_yet_seen_are_warming(self):
        with tempfile.TemporaryDirectory() as tmp:
            db, gate = prepare(Path(tmp), enabled_minutes=1)
            touch(db, "linux-vps", at=NOW - timedelta(seconds=20), connected=0)
            self.assertEqual({x["status"] for x in observe(db, gate, now=NOW).values()},
                             {"warming"})

    def test_stale_connected_not_considered_online_and_revoked_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            db, gate = prepare(Path(tmp))
            touch(db, "linux-vps", at=NOW - timedelta(minutes=11), connected=1)
            report = observe(db, gate, now=NOW)
            self.assertEqual(report["linux-vps"]["status"], "offline")
            with sqlite3.connect(db) as conn:
                conn.execute("UPDATE devices SET revoked=1 WHERE device_id='linux-vps'")
            self.assertEqual(observe(db, gate, now=NOW)["linux-vps"]["status"], "unknown")

    def test_broken_opt_in_symlink_and_future_timestamp_never_fake_online(self):
        with tempfile.TemporaryDirectory() as tmp:
            db, gate = prepare(Path(tmp))
            gate.write_text('{"token":"DO_NOT_LOG"}')
            self.assertEqual({x["status"] for x in observe(db, gate, now=NOW).values()},
                             {"unknown"})
            self.assertNotIn("DO_NOT_LOG", str(observe(db, gate, now=NOW)))
            gate.unlink()
            gate.symlink_to(db)
            self.assertEqual({x["status"] for x in observe(db, gate, now=NOW).values()},
                             {"not_configured"})

    def test_untrusted_presence_shapes_rejected(self):
        s = snapshot({"linux-vps": {"status": "online"},
                      "windows-pc": {"status": "online"}})
        self.assertEqual(analyze(s, now=NOW), [])
        for bad in (
            {"linux-vps": {"status": "success"}, "windows-pc": {"status": "online"}},
            {"linux-vps": {"status": "offline"}},
            {"linux-vps": {"status": "online", "token": "secret"},
             "windows-pc": {"status": "online"}},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                analyze(snapshot(bad), now=NOW)

    def test_ops_watch_persists_outage_until_positive_heartbeat(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "ops"
            target.mkdir(mode=0o700)
            db, gate = prepare(root)
            touch(db, "linux-vps", at=NOW - timedelta(minutes=12), connected=0)
            touch(db, "windows-pc", at=NOW - timedelta(seconds=3), connected=1)
            mock_news = snapshot({})["news"]
            with patch("ops_watch.collector._state", return_value=True), \
                 patch("ops_watch.collector._agent_network_guard_status",
                       return_value={"loaded": True, "active": True, "enabled": True}), \
                 patch("ops_watch.collector._read_state", return_value=mock_news), \
                 patch("ops_watch.collector._codex_telemetry", return_value=None), \
                 patch("ops_watch.collector.observed_status", return_value=None):
                kw = dict(device_fabric_db=db, device_fabric_opt_in=gate)
                first = once(root / "health", target, NOW, **kw)
                self.assertIn("ops:device_linux_vps_unavailable", first["changes"]["raised"])
                gate.write_text("broken")
                second = once(root / "health", target, NOW + timedelta(minutes=1), **kw)
                self.assertIn("device_linux_vps_unavailable", second["active_codes"])
                self.assertEqual(second["changes"]["resolved"], [])
                gate.write_text(json.dumps({
                    "schema": 1, "devices": ["windows-pc", "linux-vps"],
                    "enabled_at": (NOW - timedelta(minutes=30)).isoformat(),
                }))
                touch(db, "linux-vps", at=NOW + timedelta(minutes=2), connected=1)
                touch(db, "windows-pc", at=NOW + timedelta(minutes=2), connected=1)
                third = once(root / "health", target, NOW + timedelta(minutes=2), **kw)
                self.assertIn("ops:device_linux_vps_unavailable", third["changes"]["resolved"])

    def test_tls_expiry_warns_before_silent_permanent_disconnect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, gate = prepare(root)
            cert = root / "cert.pem"
            cert.write_text("public dummy certificate", encoding="ascii")
            samples = (
                ("notAfter=Oct 20 14:30:00 2026 GMT\\n", "expiring", "device_tls_expiring"),
                ("notAfter=Oct 17 14:30:00 2026 GMT\\n", "expired", "device_tls_expired"),
                ("notAfter=Nov 20 14:30:00 2026 GMT\\n", "healthy", None),
            )
            for enddate, expected, code in samples:
                with self.subTest(enddate=enddate), patch(
                    "ops_watch.device_fabric_alerts.subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, enddate, "")
                ) as call:
                    level = certificate_status(cert, gate, now=NOW)
                    self.assertEqual(level, expected)
                    s = snapshot({"windows-pc": {"status": "online"},
                                  "linux-vps": {"status": "online"}})
                    s["device_fabric_tls"] = level
                    findings = {item["code"] for item in analyze(s, now=NOW)}
                    self.assertEqual(findings, {code} if code else set())
                    self.assertEqual(call.call_args.kwargs["timeout"], 3)
            gate.write_text('{"untrusted":true}')
            self.assertEqual(certificate_status(cert, gate, now=NOW), "unknown")

    def test_linux_hardening_and_no_unapproved_enable(self):
        script = ROOT / "deploy/h15-device-fabric-yfc-autostart.sh"
        unit = (ROOT / "deploy/hermes-device-agent-yfc.service.in").read_text()
        if shutil.which("bash"):
            subprocess.run(["bash", "-n", str(script)], check=True)
        source = script.read_text()
        self.assertIn('prepare|enable|status|rollback', source)
        self.assertIn("AUTOSTART=NOT_ENABLED", source)
        self.assertIn("systemctl enable --now", source)
        self.assertIn("STATE_AND_ENROLLMENT=PRESERVED", source)
        self.assertNotIn("PermitRootLogin", source)
        for fragment in ("User=hermes-presence-agent", "--watch",
                         "Restart=always", "RestartSec=30s", "ProtectHome=true",
                         "NoNewPrivileges=true", "ExecStart=",
                         "hermes-presence-tunnel"):
            self.assertIn(fragment, unit)
        self.assertNotIn("User=root", unit)
        self.assertNotIn("0.0.0.0", unit)

    def test_windows_localservice_boot_task_not_system_or_user_logon(self):
        code = (ROOT / "deploy/h15-device-fabric-windows-autostart.ps1").read_text()
        for fragment in ("-AtStartup", "'NT AUTHORITY\\LOCAL SERVICE'",
                         "-LogonType ServiceAccount", "-RunLevel Limited",
                         "-MultipleInstances IgnoreNew", "-RestartInterval",
                         "-RestartCount 999", "--watch", "StrictMode",
                         "AUTOSTART=NOT_ENABLED", "STATE_AND_ENROLLMENT=PRESERVED"):
            self.assertIn(fragment, code)
        self.assertNotIn("-LogonType S4U", code)
        self.assertNotIn("-UserId 'SYSTEM'", code)
        self.assertNotIn("New-NetFirewallRule", code)


if __name__ == "__main__":
    unittest.main()
