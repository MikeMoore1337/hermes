"""H-01 #33: static regression guard for the *disabled example* OS sandbox.

This does not run the image, attest a production unit, authorize any tools, or
grant resident Agent approval. It catches unsafe source drift before review.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "deploy" / "run-agent-sandbox.sh"
EXAMPLE = ROOT / "deploy" / "hermes-agent-sandbox.service.example"


class ResidentExampleOfflineGuardTests(unittest.TestCase):
    def test_launcher_stays_pinned_networkless_and_unprivileged(self):
        script = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("require_patched_agent_image", script)
        self.assertNotIn("sha256:32d095e84190ae", script)
        for required in (
            "--pull=never", "--network none", "--read-only",
            "--cap-drop ALL", "--security-opt no-new-privileges",
            "--pids-limit 96", "--cpus 0.5", "--memory 640m",
            "--user", "exec docker run --rm",
        ):
            with self.subTest(required=required):
                self.assertIn(required, script)
        for forbidden in (
            "--privileged", "--network host", "--network=host", "--pid=host",
            "--pid host", "--device ", "--env-file", "--publish", "--add-host",
            "/var/run/docker.sock", "CLOUDFLARE_API_TOKEN",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, script)
        self.assertIn('--mount type=bind,src="$STATE",dst=/opt/data', script)
        self.assertNotIn("network_mode: host", script)
        self.assertIn('if [ ! -d "$STATE" ] || [ -L "$STATE" ]; then', script)
        self.assertIn('--entrypoint /opt/hermes/bin/hermes', script)

    def test_example_unit_cannot_start_automatically_after_failure(self):
        text = EXAMPLE.read_text(encoding="utf-8")
        self.assertIn("Example only; do not install/enable", text)
        self.assertRegex(text, r"(?m)^Restart=no$")
        self.assertRegex(text, r"(?m)^NoNewPrivileges=yes$")
        self.assertRegex(text, r"(?m)^ProtectSystem=strict$")
        self.assertRegex(text, r"(?m)^PrivateTmp=yes$")
        self.assertRegex(text, r"(?m)^RuntimeMaxSec=1800$")
        self.assertRegex(
            text, r"(?m)^ExecStart=/opt/hermes-agent-owner/deploy/run-agent-sandbox.sh$"
        )
        self.assertNotRegex(text, r"(?m)^Environment(File)?=.*(?:TOKEN|KEY|SECRET)")
        self.assertNotRegex(text, r"(?m)^Restart=(?:always|on-failure)$")


if __name__ == "__main__":
    unittest.main()
