"""Negative contract tests for the disabled H-01 local sandbox candidate."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SandboxContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.launch = (ROOT / "deploy/run-agent-sandbox.sh").read_text(encoding="utf-8")
        cls.prepare = (ROOT / "deploy/prepare-agent-home.sh").read_text(encoding="utf-8")
        cls.service = (ROOT / "deploy/hermes-agent-sandbox.service.example").read_text(
            encoding="utf-8"
        )

    def test_no_network_or_host_privileges(self) -> None:
        for expected in (
            "--network none", "--read-only", "--cap-drop ALL",
            "--security-opt no-new-privileges", "--pids-limit 96",
            "--user", "--memory 640m", "--memory-swap 896m",
            "--cpus 0.5", "--pull=never",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.launch)

    def test_immutable_image_no_automatic_pull(self) -> None:
        self.assertIn("nousresearch/hermes-agent@sha256:", self.launch)
        self.assertNotIn("hermes-agent:latest", self.launch)
        self.assertNotIn("docker pull", self.launch)

    def test_only_agent_private_data_mount_is_present(self) -> None:
        self.assertIn("STATE='/var/lib/hermes-agent'", self.launch)
        self.assertIn('src="$STATE",dst=/opt/data', self.launch)
        for forbidden in (
            "docker.sock", "/var/lib/hermes/state.json",
            "second-brain-vault", "--privileged", "network host",
            "--publish", "--mount type=volume", "--env-file",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.launch)

    def test_scripts_validate_owned_directory_and_host_capacity(self) -> None:
        self.assertIn("host_capacity.py", self.launch)
        self.assertIn("--reserve-mib 640 --margin-mib 256", self.launch)
        self.assertIn('stat -c %a "$STATE"', self.launch)
        self.assertIn('docker container inspect "$NAME"', self.launch)
        self.assertIn("nologin", self.prepare)
        self.assertIn("0700", self.prepare)

    def test_service_must_not_run_indefinitely_or_auto_restart(self) -> None:
        self.assertIn("Restart=no", self.service)
        self.assertIn("RuntimeMaxSec=1800", self.service)
        self.assertIn("StartLimitBurst=2", self.service)
        self.assertIn("host_capacity.py", self.service)
        self.assertNotIn("Restart=always", self.service)

    def test_launch_is_not_replacing_news_worker(self) -> None:
        self.assertNotIn("hermes-worker-drain", self.launch)
        self.assertNotIn("hermes-discovery.timer", self.launch)
        self.assertNotIn("/var/lib/hermes/", self.launch)


if __name__ == "__main__":
    unittest.main()
