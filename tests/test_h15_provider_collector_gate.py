"""Offline tests of #295 owner opt-in source gates and shell syntax.

No live HTTP, no GitHub/Cloudflare account access, no model inference, no
systemd mutation and no production credentials.
"""
from __future__ import annotations

import contextlib
from io import StringIO
import json
import os
from pathlib import Path
import stat
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import h15_provider_collector_gate as gate


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "deploy" / "h15-provider-source-setup.sh"


class CollectorSourceGateTests(unittest.TestCase):
    def test_shell_syntax_and_separate_explicit_actions(self):
        result = subprocess.run(
            ["bash", "-n", str(INSTALLER)],
            capture_output=True, text=True, check=False, timeout=3,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        raw = INSTALLER.read_text(encoding="utf-8")
        for action in ("status", "install", "smoke", "enable", "disable"):
            self.assertIn(action, raw)
        self.assertIn("COLLECTOR_NOT_STARTED=true", raw)
        self.assertIn("systemctl enable --now", raw)
        self.assertIn("same_installed_units", raw)
        self.assertNotIn("curl ", raw)
        self.assertNotIn("eval ", raw)

    def test_github_missing_unsafe_or_symlink_never_ready(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "github-token"
            routes = {"github": p}
            self.assertFalse(gate.credentials_ready("github", paths=routes,
                                                   user_id=os.getuid()))
            p.write_text("f" * 40, encoding="ascii")
            p.chmod(0o644)
            self.assertFalse(gate.credentials_ready("github", paths=routes,
                                                   user_id=os.getuid()))
            p.chmod(0o600)
            self.assertTrue(gate.credentials_ready("github", paths=routes,
                                                  user_id=os.getuid()))
            self.assertFalse(gate.credentials_ready("github", paths=routes,
                                                   user_id=os.getuid() + 1))
            other = Path(d) / "hardlink"
            os.link(p, other)
            self.assertFalse(gate.credentials_ready("github", paths=routes,
                                                   user_id=os.getuid()))
            other.unlink()
            p.unlink()
            p.symlink_to(Path(d) / "missing-secret")
            self.assertFalse(gate.credentials_ready("github", paths=routes,
                                                   user_id=os.getuid()))

    def test_cloudflare_must_have_exact_root_only_account_env(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "cf-token"
            env = Path(d) / "billing.env"
            p.write_text("f" * 40)
            p.chmod(0o600)
            routes = {"cloudflare": p}
            def ready():
                return gate.credentials_ready(
                    "cloudflare", paths=routes, account_env=env,
                    user_id=os.getuid(),
                )
            self.assertFalse(ready())
            env.write_text("CLOUDFLARE_BILLING_ACCOUNT_ID=" + "a" * 32 + "\n")
            env.chmod(0o600)
            self.assertTrue(ready())
            env.write_text(
                "CLOUDFLARE_BILLING_ACCOUNT_ID=" + "a" * 32
                + "\nLD_PRELOAD=/tmp/untrusted\n"
            )
            self.assertFalse(ready())
            env.write_text("CLOUDFLARE_BILLING_ACCOUNT_ID=" + "z" * 32 + "\n")
            self.assertFalse(ready())
            env.write_text("CLOUDFLARE_BILLING_ACCOUNT_ID=" + "a" * 32 + "\n")
            env.chmod(0o640)
            self.assertFalse(ready())
            env.chmod(0o600)
            self.assertTrue(ready())

    def test_preflight_status_never_discloses_token_or_path(self):
        stdout = StringIO()
        with patch.object(gate.os, "geteuid", return_value=0), \
                patch.object(gate, "credentials_ready", return_value=True), \
                patch.object(gate, "observed", return_value=True), \
                contextlib.redirect_stdout(stdout):
            status = gate.main(["--provider", "github", "--gate", "observed"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stdout.getvalue()), {
            "provider": "github", "credentials": "READY_METADATA_ONLY",
            "source": "FRESH_OBSERVED",
        })
        for phrase in ("/etc/hermes", "Bearer", "token=", "a" * 32):
            self.assertNotIn(phrase, stdout.getvalue())

    def test_gate_fails_closed_on_missing_credentials_or_snapshot(self):
        for ready, seen, expected in [(False, False, 2),
                                      (True, False, 2), (True, True, 0)]:
            with self.subTest(ready=ready, seen=seen):
                stdout = StringIO()
                with patch.object(gate.os, "geteuid", return_value=0), \
                        patch.object(gate, "credentials_ready", return_value=ready), \
                        patch.object(gate, "observed", return_value=seen), \
                        contextlib.redirect_stdout(stdout):
                    result = gate.main(["--provider", "cloudflare",
                                        "--gate", "observed"])
                self.assertEqual(result, expected)
                if not ready or not seen:
                    self.assertEqual(
                        json.loads(stdout.getvalue())["source"], "NOT_VERIFIED",
                    )

    def test_nonroot_refuses_any_credentials_probe(self):
        with patch.object(gate.os, "geteuid", return_value=1001), \
                patch.object(gate, "credentials_ready") as probe, \
                contextlib.redirect_stdout(StringIO()):
            self.assertEqual(gate.main(["--provider", "github"]), 2)
            probe.assert_not_called()

    def test_snapshot_requirement_is_real_official_data(self):
        with patch("control_center.github_rate_limit.snapshot") as probe:
            probe.return_value = {"status": "unknown", "resources": []}
            self.assertFalse(gate.observed("github", path=Path("/nonexistent")))
            probe.return_value = {"status": "ok", "resources": [{"resource": "core"}]}
            self.assertTrue(gate.observed("github", path=Path("/nonexistent")))
        with patch("control_center.cloudflare_billing.snapshot") as probe:
            probe.return_value = {"status": "unknown", "days": []}
            self.assertFalse(gate.observed("cloudflare", path=Path("/nonexistent")))
            probe.return_value = {"status": "ok", "days": [{"day": "2026-10-17"}]}
            self.assertTrue(gate.observed("cloudflare", path=Path("/nonexistent")))


if __name__ == "__main__":
    unittest.main()
