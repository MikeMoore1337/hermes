"""Offline safety contract for manually approved Hermes production delivery.

This test is deliberately static: the live VPS isolated systemd checks are validated
separately, and no network, SSH, secrets or production calls occur in CI.
"""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MainDeployContractTests(unittest.TestCase):
    def test_shell_syntax(self):
        bash = shutil.which('bash')
        if not bash:
            self.skipTest('bash unavailable')
        for name in ('hermes-main-deploy.sh', 'provision-main-deploy.sh'):
            with self.subTest(script=name):
                subprocess.run([bash, '-n', str(ROOT / 'deploy' / name)], check=True)

    def test_nonroot_offline_validation(self):
        script = (ROOT / "deploy/hermes-main-deploy.sh").read_text(encoding="utf-8")
        for fragment in (
            '[[ "$EUID" == 0 ]]',
            'sha256sum -c -',
            'git get-tar-commit-id',
            'tarfile.open(',
            '".." in p.parts',
            'chmod -R a+rX,go-w "$work/src"',
            'DynamicUser=yes',
            'PrivateNetwork=yes',
            'ProtectSystem=strict',
            'NoNewPrivileges=yes',
            'runtime_max_sec=240',
            'runtime_max_sec=540',
            '-p "RuntimeMaxSec=$runtime_max_sec"',
            'if [[ "${1:-}" == "--full-unit-suite" ]]',
            'MemoryMax=1G',
            'TasksMax=128',
            'OFFLINE_UNIT_SUITE_FAILED_OR_TIMED_OUT',
            'isolated_python scripts/validate_repo.py',
            'isolated_python scripts/check_policy_index.py',
            'isolated_python scripts/check_markdown_links.py',
            'isolated_python --full-unit-suite -m unittest discover -s tests -q',
            'PRODUCTION_DEPLOYED=',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, script)
        # Only the full suite receives 540s; preflight remains bounded at 240s.
        self.assertEqual(script.count('runtime_max_sec=240'), 1)
        self.assertEqual(script.count('runtime_max_sec=540'), 1)
        self.assertNotIn('runtime_max_sec=360', script)
        self.assertEqual(script.count('--full-unit-suite'), 2)
        self.assertNotIn('runtime_max_sec=0', script)
        self.assertNotIn('RuntimeMaxSec=0', script)
        self.assertNotIn('RuntimeMaxSec=infinity', script)
        self.assertNotIn('timeout 180s python3 -m unittest', script)
        self.assertNotIn('RuntimeMaxSec=infinity', script)
        self.assertNotIn('PrivateNetwork=no', script)
        self.assertNotIn('eval ', script)
        self.assertNotIn('systemctl enable', script)
        self.assertNotIn('hermes-agent-sandbox.service start', script)

    def test_openat2_full_suite_is_static_nonroot_without_disabling_sandbox(self):
        script = (ROOT / "deploy/hermes-main-deploy.sh").read_text(encoding="utf-8")
        # DynamicUser implicitly installs RestrictSUIDSGID which blocks
        # openat2 with ENOSYS on systemd. Keep DynamicUser for fast checks;
        # the full kernel-backed suite runs as unprivileged uid/gid 65534.
        self.assertIn("local sandbox_identity=(-p DynamicUser=yes)", script)
        self.assertIn('if [[ "${1:-}" == "--full-unit-suite" ]]; then', script)
        self.assertIn('id -u nobody 2>/dev/null)', script)
        self.assertIn('id -g nobody 2>/dev/null)', script)
        self.assertIn("sandbox_identity=(-p DynamicUser=no -p User=65534 -p Group=65534", script)
        self.assertIn("-p RestrictSUIDSGID=no -p CapabilityBoundingSet=)", script)
        self.assertIn('"${sandbox_identity[@]}" -p "WorkingDirectory=$work/src"', script)
        for protection in (
            "PrivateNetwork=yes", "NoNewPrivileges=yes", "ProtectSystem=strict",
            "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes",
            "MemoryMax=1G", "TasksMax=128",
        ):
            self.assertIn(protection, script)
        self.assertIn("OFFLINE_UNIT_SUITE_FAILED_OR_TIMED_OUT", script)
        self.assertNotIn("SystemCallFilter=~openat2", script)
        self.assertNotIn("skipUnless(os.environ", script)
        self.assertNotIn("RunAs=root", script)

    def test_unittest_status_allows_only_clean_ok_or_ok_with_skips(self):
        script = (ROOT / "deploy/hermes-main-deploy.sh").read_text(encoding="utf-8")
        expression = r"^OK( \(skipped=[0-9]+\))?$"
        self.assertIn("grep -Eq '" + expression + "' \"$work/tests.log\"", script)
        for line, allowed in (
            ("OK", True), ("OK (skipped=8)", True),
            ("FAILED (failures=1)", False), ("OK (expected failures=1)", False),
            ("OK (skipped=abc)", False), ("", False),
        ):
            with self.subTest(report=line):
                proc = subprocess.run(["grep", "-Eq", expression], input=line + "\n",
                                      text=True, capture_output=True)
                self.assertEqual(proc.returncode == 0, allowed)
    def test_ci_gate_and_host_identity(self):
        workflow = (ROOT / ".github/workflows/production-deploy.yml").read_text(encoding="utf-8")
        for fragment in (
            'workflow_dispatch:',
            "if: github.event_name == 'workflow_dispatch'",
            'Manual dispatch refused: required SHA-scoped checks not green',
            '[.workflow_runs[] | select(.name=="Hermes repository checks")]',
            '[.workflow_runs[] | select(.name=="Hermes Control Center UI")]',
            '"$quality" == success && "$ui" == success',
            'TARGET_SHA:',
            'git archive --format=tar.gz',
            'StrictHostKeyChecking=yes',
            # Secure keepalive avoids premature SSH idle disconnect while the
            # sandboxed server full test suite is intentionally stdout-quiet.
            'ServerAliveInterval=15',
            'ServerAliveCountMax=6',
            'HERMES_DEPLOY_KNOWN_HOSTS',
            'cancel-in-progress: false',
            'timeout-minutes: 20',
            'contents: read',
            'actions: read',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, workflow)
        self.assertNotIn('StrictHostKeyChecking=no', workflow)
        self.assertNotIn('workflow_run:', workflow)
        self.assertNotIn('github.event.workflow_run', workflow)
        self.assertNotIn('known_hosts=/dev/null', workflow)
        self.assertNotIn('ssh-keyscan', workflow)
        self.assertNotIn('ServerAliveInterval=0', workflow)
        self.assertNotIn('ServerAliveCountMax=0', workflow)


if __name__ == "__main__":
    unittest.main()
