"""Offline H-15 daily Cloudflare advisory schedule and no-extra-query tests."""
from __future__ import annotations

import contextlib
import datetime as dt
from io import StringIO
import os
from pathlib import Path
import stat
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import h15_cloudflare_analytics_collect as collect
from scripts import h15_cloudflare_analytics_gate as gate


ROOT = Path(__file__).resolve().parents[1]
BASE = "hermes-cloudflare-analytics-advisory"
SERVICE = ROOT / "deploy" / (BASE + ".service")
TIMER = ROOT / "deploy" / (BASE + ".timer")
SETUP = ROOT / "deploy/h15-cloudflare-analytics-setup.sh"
NOW = dt.datetime(2026, 10, 18, 20, tzinfo=dt.timezone.utc)


class DailyAnalyticsTests(unittest.TestCase):
    def test_separate_once_per_day_timer_and_capless_service(self):
        timer = TIMER.read_text(encoding="utf-8")
        service = SERVICE.read_text(encoding="utf-8")
        installer = SETUP.read_text(encoding="utf-8")
        self.assertIn("OnCalendar=*-*-* 06:15:00 UTC", timer)
        self.assertIn("RandomizedDelaySec=15min", timer)
        self.assertIn("Persistent=true", timer)
        self.assertNotIn("OnUnitInactiveSec", timer)
        self.assertNotIn("OnBootSec", timer)
        for directive in (
            "Type=oneshot", "User=root", "Group=hermes-control",
            "CapabilityBoundingSet=", "NoNewPrivileges=true",
            "ProtectSystem=strict", "StateDirectoryMode=0750",
            "ReadWritePaths=/var/lib/hermes-provider-quota",
            "TimeoutStartSec=25",
        ):
            self.assertIn(directive, service)
        for value in (
            "control_center.cloudflare_analytics_runner",
            "/etc/hermes/cloudflare-analytics-read.token",
            "/etc/hermes/cloudflare-analytics-read.env",
        ):
            self.assertIn(value, service)
        self.assertNotIn("cloudflare-billing-read", service)
        self.assertNotIn("EnvironmentFile=", service)
        self.assertNotIn("ExecStartPre=", service)
        self.assertNotIn("curl ", installer)
        self.assertNotIn("eval ", installer)
        self.assertIn("same_installed_units", installer)
        self.assertIn("CLOUDFLARE_ADVISORY_NOT_STARTED=true", installer)
        self.assertIn("systemctl enable --now", installer)
        self.assertIn("systemctl disable --now", installer)
        result = subprocess.run(["bash", "-n", str(SETUP)], timeout=3,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_owner_gate_needs_real_previous_utc_day(self):
        previous={"status":"historical_estimate","days":[{"day":"2026-10-17"}]}
        with patch.object(gate.history,"read",return_value=previous):
            self.assertTrue(gate.observed(now=NOW))
            self.assertFalse(gate.observed(now=NOW+dt.timedelta(days=1)))
        with patch.object(gate.history,"read",return_value={
                "status":"unknown","days":[{"day":"2026-10-17"}]}):
            self.assertFalse(gate.observed(now=NOW))

    def test_gate_never_uses_inference_or_echoes_secrets(self):
        with patch.object(gate.os,"geteuid",return_value=0), \
             patch.object(gate,"credentials_ready",return_value=True), \
             patch.object(gate,"observed",return_value=True), \
             contextlib.redirect_stdout(StringIO()) as output:
            self.assertEqual(gate.main(["--gate","observed"]),0)
        self.assertIn("FRESH_ARCHIVE",output.getvalue())
        self.assertIn('"quota_remaining": "UNKNOWN"',output.getvalue())
        self.assertNotIn("Bearer",output.getvalue())
        with patch.object(gate.os,"geteuid",return_value=1000), \
             patch.object(gate,"credentials_ready") as creds, \
             contextlib.redirect_stdout(StringIO()):
            self.assertEqual(gate.main(["--gate","credentials"]),2)
            creds.assert_not_called()

    def test_duplicate_completed_day_never_sends_another_query(self):
        with TemporaryDirectory() as temp:
            root=Path(temp)
            archive=root/"readback.json"
            original=Path.stat
            def trusted_dir(p, *args, **kwargs):
                info=original(p,*args,**kwargs)
                if p==root:
                    return SimpleNamespace(st_uid=0,st_gid=os.getegid(),
                                           st_mode=stat.S_IFDIR|0o750)
                return info
            with patch.object(collect.os,"geteuid",return_value=0), \
                 patch.object(collect.grp,"getgrnam",
                     return_value=SimpleNamespace(gr_gid=os.getegid())), \
                 patch.object(collect.history,"OUTPUT",archive), \
                 patch.object(collect.history,"read",return_value={
                   "status":"historical_estimate",
                   "days":[{"day":(dt.datetime.now(dt.timezone.utc).date()-
                                   dt.timedelta(days=1)).isoformat()}]}), \
                 patch.object(Path,"stat",trusted_dir), \
                 patch.object(collect.probe,"inspect_confidence") as remote, \
                 patch.object(collect.probe,"load_credentials") as auth, \
                 contextlib.redirect_stdout(StringIO()) as output:
                self.assertEqual(collect.main(),0)
                remote.assert_not_called()
                auth.assert_not_called()
            self.assertIn("already_collected",output.getvalue())
            self.assertIn("QUOTA_REMAINING=UNKNOWN",output.getvalue())

    def test_empty_cloudflare_day_is_success_but_never_fabricates_zeros(self):
        # A successful GraphQL response containing [] is not evidence of
        # zero Neurons, nor a reason to destroy older measurements.
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            archive = directory / "advisory.json"
            archive.write_text("existing archive must not change", encoding="utf-8")
            archive.chmod(0o640)
            original = Path.stat

            def trusted_stat(path, *args, **kwargs):
                metadata = original(path, *args, **kwargs)
                if path == directory:
                    return SimpleNamespace(st_uid=0, st_gid=os.getegid(),
                                           st_mode=stat.S_IFDIR | 0o750)
                if path == archive:
                    return SimpleNamespace(st_uid=0, st_gid=os.getegid(),
                                           st_mode=stat.S_IFREG | 0o640,
                                           st_nlink=1)
                return metadata

            previous = (dt.datetime.now(dt.timezone.utc).date() -
                        dt.timedelta(days=1)).isoformat()
            with patch.object(collect.os, "geteuid", return_value=0), \
                 patch.object(collect.grp, "getgrnam",
                              return_value=SimpleNamespace(gr_gid=os.getegid())), \
                 patch.object(collect.history, "OUTPUT", archive), \
                 patch.object(collect.history, "read", return_value={
                     "status": "historical_estimate",
                     "days": [{"day": "2026-10-17"}]}), \
                 patch.object(Path, "stat", trusted_stat), \
                 patch.object(collect.probe, "load_credentials",
                              return_value=("fake-token", "fake-account")), \
                 patch.object(collect.probe, "inspect_confidence",
                              return_value=("no_confirmed_samples", None)) as source, \
                 patch.object(collect.history, "append") as write, \
                 contextlib.redirect_stdout(StringIO()) as out:
                self.assertEqual(collect.main(), 0)
                source.assert_called_once()
                write.assert_not_called()
            self.assertEqual(archive.read_text(encoding="utf-8"),
                             "existing archive must not change")
            self.assertIn("CLOUDFLARE_ADVISORY_ARCHIVE=no_confirmed_samples",
                          out.getvalue())
            self.assertIn("OBSERVATION_DAY=" + previous, out.getvalue())
            self.assertIn("HISTORY_UPDATED=false", out.getvalue())
            self.assertIn("QUOTA_REMAINING=UNKNOWN", out.getvalue())
            self.assertIn("BILLABLE_USAGE=NOT_VERIFIED", out.getvalue())
            self.assertNotIn("estimate_neurons", out.getvalue())

    def test_real_source_errors_still_return_failure(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            archive = directory / "advisory.json"
            original = Path.stat

            def trusted_stat(path, *args, **kwargs):
                metadata = original(path, *args, **kwargs)
                if path == directory:
                    return SimpleNamespace(st_uid=0, st_gid=os.getegid(),
                                           st_mode=stat.S_IFDIR | 0o750)
                return metadata

            for source_status in (
                    "unavailable", "throttled", "auth_required",
                    "unsupported_or_denied", "unknown"):
                with self.subTest(source_status=source_status), \
                     patch.object(collect.os, "geteuid", return_value=0), \
                     patch.object(collect.grp, "getgrnam",
                                  return_value=SimpleNamespace(gr_gid=os.getegid())), \
                     patch.object(collect.history, "OUTPUT", archive), \
                     patch.object(collect.history, "read", return_value={
                         "status": "unknown", "days": []}), \
                     patch.object(Path, "stat", trusted_stat), \
                     patch.object(collect.probe, "load_credentials",
                                  return_value=("fake-token", "fake-account")), \
                     patch.object(collect.probe, "inspect_confidence",
                                  return_value=(source_status, None)), \
                     patch.object(collect.history, "append") as write, \
                     contextlib.redirect_stdout(StringIO()) as out:
                    self.assertEqual(collect.main(), 1)
                    write.assert_not_called()
                    self.assertIn("CLOUDFLARE_ADVISORY_ARCHIVE=" + source_status,
                                  out.getvalue())
                    self.assertNotIn("HISTORY_UPDATED=false", out.getvalue())

    def test_unsafe_state_rejected_before_credentials_or_graphql(self):
        with patch.object(collect.os,"geteuid",return_value=0), \
             patch.object(collect.grp,"getgrnam",
                 return_value=SimpleNamespace(gr_gid=os.getegid())), \
             patch.object(collect.probe,"inspect_confidence") as remote, \
             patch.object(collect.probe,"load_credentials") as auth, \
             patch.object(collect.history,"OUTPUT",Path("/missing-state-root-false/do-not-query.json")), \
             contextlib.redirect_stdout(StringIO()) as output:
            self.assertEqual(collect.main(),2)
            remote.assert_not_called()
            auth.assert_not_called()
        self.assertIn("STATE_UNAVAILABLE",output.getvalue())


if __name__ == "__main__":
    unittest.main()
