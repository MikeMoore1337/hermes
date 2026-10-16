"""Offline safety contract for automatic Hermes main-to-production delivery.

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
            'isolated_python scripts/validate_repo.py',
            'isolated_python scripts/check_policy_index.py',
            'isolated_python scripts/check_markdown_links.py',
            'isolated_python -m unittest discover -s tests -q',
            'PRODUCTION_DEPLOYED=',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, script)
        self.assertNotIn('timeout 180s python3 -m unittest', script)
        self.assertNotIn('eval ', script)
        self.assertNotIn('systemctl enable', script)
        self.assertNotIn('hermes-agent-sandbox.service start', script)

    def test_ci_gate_and_host_identity(self):
        workflow = (ROOT / ".github/workflows/production-deploy.yml").read_text(encoding="utf-8")
        for fragment in (
            'workflow_run:',
            'workflow_dispatch:',
            "github.event.workflow_run.conclusion == 'success'",
            "github.event.workflow_run.event == 'push'",
            'TARGET_SHA:',
            'ui_required=',
            'git archive --format=tar.gz',
            'StrictHostKeyChecking=yes',
            'HERMES_DEPLOY_KNOWN_HOSTS',
            'cancel-in-progress: false',
            'contents: read',
            'actions: read',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, workflow)
        self.assertNotIn('StrictHostKeyChecking=no', workflow)
        self.assertNotIn('known_hosts=/dev/null', workflow)
        self.assertNotIn('ssh-keyscan', workflow)


if __name__ == "__main__":
    unittest.main()
