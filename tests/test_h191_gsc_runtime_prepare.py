"""H-24/#191 preactivation installer contracts: offline only, no root mutations."""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "deploy" / "h191-gsc-runtime-prepare.sh"
SERVICE = ROOT / "deploy" / "hermes-gsc-readonly.service"
TIMER = ROOT / "deploy" / "hermes-gsc-readonly.timer"
REQUIREMENTS = ROOT / "deploy" / "requirements-gsc-readonly.txt"


class GscPrepareContractTests(unittest.TestCase):
    def test_bash_script_parses(self):
        result = subprocess.run(
            ["bash", "-n", str(INSTALLER)], capture_output=True, text=True,
            timeout=5, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_plan_is_read_only_and_explicit(self):
        result = subprocess.run(
            ["bash", str(INSTALLER), "--plan"], capture_output=True,
            text=True, timeout=5, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("H191_PLAN=OWNER_HOST_PREPARATION_ONLY", result.stdout)
        self.assertIn("NO_SECRET_CONTENT", result.stdout)
        self.assertIn("NO_GOOGLE_API", result.stdout)
        self.assertIn("NO_TIMER_ENABLE", result.stdout)

    def test_unrecognized_operations_fail_before_host_mutation(self):
        for action in ("--start", "--enable", "--live", "--rollback", ""):
            cmd = ["bash", str(INSTALLER)]
            if action:
                cmd.append(action)
            with self.subTest(action=action):
                result = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=5, check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("action_must_be_plan_or_prepare", result.stderr)

    def test_enforces_exact_released_source_and_local_host(self):
        script = INSTALLER.read_text(encoding="utf-8")
        for required in (
            "vps1777112993",
            "last-success.sha",
            ".deployment-receipt.txt",
            "release_sha_invalid",
            "untrusted_installer_location",
            "active_source_drift",
            "root_required",
            "identity_extra_groups",
            "directory_permissions_mismatch",
        ):
            with self.subTest(required=required):
                self.assertIn(required, script)

    def test_preparation_only_no_service_or_oauth_activation(self):
        script = INSTALLER.read_text(encoding="utf-8")
        for forbidden in (
            "systemctl start ",
            "systemctl enable ",
            "systemctl restart ",
            "systemctl stop ",
            "--credentials /etc/hermes-gsc",
            "--output /var/lib/hermes-gsc",
            "curl ",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, script)
        self.assertIn("systemctl daemon-reload", script)
        self.assertIn("unit_unexpectedly_activated", script)
        self.assertIn("--dry-run", script)
        self.assertIn("credentials_accessed", script)

    def test_dormant_unit_has_independent_network_denial(self):
        unit = SERVICE.read_text(encoding="utf-8")
        for required in (
            "User=hermes-gsc",
            "Group=hermes-gsc",
            "PrivateNetwork=yes",
            "IPAddressDeny=any",
            "RestrictAddressFamilies=AF_UNIX",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "ProtectSystem=strict",
            "NoNewPrivileges=yes",
            "ReadOnlyPaths=/etc/hermes-gsc",
            "ReadWritePaths=/var/lib/hermes-gsc",
        ):
            with self.subTest(required=required):
                self.assertIn(required, unit)
        self.assertNotIn("IPAddressAllow=", unit)
        self.assertNotIn("AF_INET", unit)

    def test_service_does_not_invoke_shell_or_write_provider(self):
        unit = SERVICE.read_text(encoding="utf-8")
        self.assertIn("WorkingDirectory=/opt/hermes-agent-owner", unit)
        self.assertIn(
            "ExecStart=/opt/hermes-gsc/venv/bin/python -m scripts.hermes_gsc_collect "
            "--credentials /etc/hermes-gsc/service-account.json "
            "--output /var/lib/hermes-gsc/latest.json",
            unit,
        )
        self.assertNotIn("/bin/bash", unit)
        self.assertNotIn("/bin/sh", unit)
        timer = TIMER.read_text(encoding="utf-8")
        self.assertIn("Unit=hermes-gsc-readonly.service", timer)
        self.assertNotIn("OnBootSec=", timer)

    def test_pinned_direct_dependencies_and_no_unbounded_setup(self):
        reqs = [
            line.strip() for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        self.assertEqual(reqs, ["google-auth==2.62.0", "requests==2.32.5"])
        installer = INSTALLER.read_text(encoding="utf-8")
        for required in (
            "--only-binary=:all:",
            "--no-cache-dir",
            "--retries 0",
            "https://pypi.org/simple",
            "dependency_version_mismatch",
            "dependency_conflict",
            "H191_NETWORK_POLICY=PREACTIVATION_DENY_ALL_NOT_LIVE_TESTED",
        ):
            with self.subTest(required=required):
                self.assertIn(required, installer)
        self.assertNotRegex(installer, r"\b(?:apt|apt-get|docker)\s+(?:install|run|exec|restart)\b")

    def test_no_credential_write_or_private_data_logging(self):
        script = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("existing_credentials_require_separate_metadata_review", script)
        self.assertIn("H191_GOOGLE_OAUTH=NOT_RUN", script)
        self.assertIn("H191_TIMER=NOT_ENABLED", script)
        self.assertNotRegex(
            script,
            r"(?:cat|cp|mv|install|printf|tee)\s+[^\n]*service-account\.json",
        )


if __name__ == "__main__":
    unittest.main()
