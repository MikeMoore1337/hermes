"""Минимальные офлайн-проверки ограничений smoke, без Docker и VPS."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SmokeContractTests(unittest.TestCase):
    """Не допускает случайного подключения сети и расширения привилегий."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.script = (ROOT / "deploy" / "smoke.sh").read_text(encoding="utf-8")

    def test_explicit_immutable_amd64_docker_digest(self) -> None:
        self.assertIn("nousresearch/hermes-agent@sha256:32d095e84190ae", self.script)
        self.assertIn("--platform linux/amd64", self.script)

    def test_process_level_isolation(self) -> None:
        for fragment in (
            "--network none", "--read-only", "--user 10000:10000",
            "--cap-drop ALL", "--security-opt no-new-privileges",
            "--pids-limit 64", "--memory 128m", "--cpus 0.25",
            "--rm", "--pull=never", "--tmpfs /opt/data:", "--tmpfs /tmp:",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.script)

    def test_no_host_mounts_or_full_agent_execution(self) -> None:
        for prohibited in ("--privileged", "network host", "-v /", "--mount", "gateway run",
                           "hermes setup", "docker pull ", "sudo "):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, self.script)


if __name__ == "__main__":
    unittest.main()
