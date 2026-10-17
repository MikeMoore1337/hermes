"""H-01: negative image selection tests; never contact a Docker daemon."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy" / "require-patched-agent-image.sh"
DOCKERFILE = ROOT / "docker" / "v0222-native-tool-policy-test" / "Dockerfile"
DIGEST = "sha256:" + "a" * 64


class V0222ImageGateTests(unittest.TestCase):
    def test_build_is_pinned_to_official_v0222_and_applies_tool_patch(self) -> None:
        data = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn(
            "nousresearch/hermes-agent@sha256:"
            "a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05", data
        )
        self.assertIn("hermes.native.tool.policy=\"bounded-v0222\"", data)
        self.assertIn("git apply --unidiff-zero --check", data)
        self.assertIn('hermes.derivative.resident-agent-allowed="false"', data)

    def test_both_launchers_fail_closed_without_operator_selected_image(self) -> None:
        for name in ("run-agent-sandbox.sh", "smoke-cloudflare-agent.sh"):
            script = (ROOT / "deploy" / name).read_text(encoding="utf-8")
            with self.subTest(script=name):
                self.assertIn('source "$ROOT/deploy/require-patched-agent-image.sh"', script)
                self.assertIn("require_patched_agent_image", script)
                self.assertNotIn("sha256:32d095e84190ae", script)
        gate = HELPER.read_text(encoding="utf-8")
        self.assertIn("HERMES_AGENT_RUNTIME_IMAGE", gate)
        self.assertIn("sha256:[0-9a-f]{64}", gate)
        self.assertIn("hermes.base.commit", gate)
        self.assertIn("hermes.native.tool.policy", gate)

    @unittest.skipIf(os.name == "nt" or not shutil.which("bash"), "Linux bash required")
    def test_gate_rejects_missing_tag_unpatched_and_mismatched_images(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            fake_docker = directory / "docker"
            fake_docker.write_text(
                '#!/bin/sh\n'
                'case "$*" in\n'
                '  *"{{.Id}}"*) printf "%s\\n" "$MOCK_IMAGE_ID" ;;\n'
                '  *"hermes.base.commit"*) printf "%s\\n" "$MOCK_REVISION" ;;\n'
                '  *"hermes.native.tool.policy"*) printf "%s\\n" "$MOCK_POLICY" ;;\n'
                '  *) exit 42 ;;\n'
                'esac\n',
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)
            base = dict(os.environ)
            base["PATH"] = str(directory) + os.pathsep + base.get("PATH", "")
            base.update(
                MOCK_IMAGE_ID=DIGEST,
                MOCK_REVISION="d923a5eb487a17c0a68801bba9ef0f56c81040a8",
                MOCK_POLICY="bounded-v0222",
            )

            def run(**env_changes: str) -> subprocess.CompletedProcess[str]:
                env = dict(base)
                env.update(env_changes)
                return subprocess.run(
                    ["bash", "-c", 'source "$1"; require_patched_agent_image', "bash", str(HELPER)],
                    env=env, capture_output=True, text=True, check=False, timeout=5,
                )

            self.assertNotEqual(run(HERMES_AGENT_RUNTIME_IMAGE="").returncode, 0)
            self.assertNotEqual(run(HERMES_AGENT_RUNTIME_IMAGE="hermes:latest").returncode, 0)
            self.assertNotEqual(run(HERMES_AGENT_RUNTIME_IMAGE="sha256:bad").returncode, 0)
            self.assertNotEqual(
                run(HERMES_AGENT_RUNTIME_IMAGE=DIGEST, MOCK_IMAGE_ID="sha256:" + "b" * 64).returncode,
                0,
            )
            self.assertNotEqual(
                run(HERMES_AGENT_RUNTIME_IMAGE=DIGEST, MOCK_REVISION="old-upstream").returncode,
                0,
            )
            self.assertNotEqual(
                run(HERMES_AGENT_RUNTIME_IMAGE=DIGEST, MOCK_POLICY="").returncode, 0
            )
            self.assertEqual(run(HERMES_AGENT_RUNTIME_IMAGE=DIGEST).returncode, 0)


if __name__ == "__main__":
    unittest.main()
