"""H-15: no-public, zero-device OAuth-only runner contract.

These tests never run Docker, shell tools or an owner OAuth session.
Actual disposable container OAuth tests run separately in the full H-15 CI.
"""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / "deploy/h15/run-zero-device-oauth-pilot.sh"
STAGE = ROOT / "deploy/h15/stage-relay.sh"
TEST = ROOT / "scripts/h15_brc_zero_device_oauth_pilot.mjs"
WORKFLOW = ROOT / ".github/workflows/h15-remote-commander-candidate.yml"


class ZeroDeviceOAuthPilotTests(unittest.TestCase):
    def test_exact_shell_and_node_syntax(self):
        shell = subprocess.run(["bash", "-n", str(PILOT)], capture_output=True, text=True)
        self.assertEqual(shell.returncode, 0, shell.stderr)
        node = subprocess.run(["node", "--check", str(TEST)], capture_output=True, text=True)
        self.assertEqual(node.returncode, 0, node.stderr)

    def test_bad_args_fail_before_network_or_docker(self):
        for args in ([], ["run"], ["run", "latest"], ["start", "latest"],
                     ["preflight", "sha256:bad"]):
            with self.subTest(args=args):
                result = subprocess.run(["bash", str(PILOT), *args],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("H15_OAUTH_PILOT_REFUSED=", result.stderr)
                self.assertNotIn("H15_OAUTH_PILOT_OAUTH_TEST=PASS", result.stdout)

    def test_all_exit_paths_guard_rollback_of_own_stage(self):
        text = PILOT.read_text()
        for expected in (
            'STAGE="$HERE/stage-relay.sh"',
            'OAUTH_TEST="$HERE/../../scripts/h15_brc_zero_device_oauth_pilot.mjs"',
            '[[ "$MODE" == preflight || "$MODE" == run ]]',
            'owned_stage_absent',
            'bash "$STAGE" preflight "$IMAGE_ID"',
            'bash "$STAGE" start "$IMAGE_ID"',
            'bash "$STAGE" rollback',
            'trap cleanup EXIT',
            'timeout --kill-after=5s 120s',
            'docker exec -i "$NAME" node --input-type=module -',
            'closed_public_mcp',
            '[[ "$result" == "503 0" ]]',
            'H15_OAUTH_PILOT_RELEASE_APPROVED=NO',
        ):
            self.assertIn(expected, text)
        for forbidden in (
            "--network host", "--publish", "docker pull", "docker build",
            "--privileged", "docker system prune", "systemctl restart",
            "docker exec \"$NAME\" sh", "/var/run/docker.sock",
        ):
            self.assertNotIn(forbidden, text)
        stage = STAGE.read_text()
        self.assertIn("--network none", stage)
        self.assertIn("--restart no", stage)
        self.assertIn("--cap-drop ALL", stage)
        self.assertIn("FOREIGN_CONTAINER_NOT_OWNED", stage)
        self.assertIn("OWNER_REMOTE_COMMANDS=NOT_ENABLED", stage)

    def test_oauth_script_makes_no_device_or_file_command_calls(self):
        text = TEST.read_text()
        for expected in (
            "'initialize'", "AUTHORIZATION_CODE_REPLAY_DENIED",
            "OLD_REFRESH_TOKEN_REPLAY_DENIED", "INVALID_BEARER_DENIED",
            "WRONG_PKCE_VERIFIER_DENIED",
            "REVOCATION_ENDPOINT_ADVERTISED", "SEPARATE_OAUTH_CLIENT_REGISTERED",
            "FOREIGN_CLIENT_CANNOT_REVOKE_ACCESS", "REVOKED_ACCESS_TOKEN_DENIED",
            "REVOKED_REFRESH_TOKEN_DENIED",
            "ZERO_DEVICES_AFTER_OAUTH", "S256", "resource: prm.resource",
            "H15_OAUTH_ONLY_END_TO_END=PASS",
        ):
            self.assertIn(expected, text)
        for forbidden in (
            "start_process", "interact_with_process",
            "write_file", "read_file", "send_file_transfer",
            "tools/call", "child_process", "node:fs",
            "socket.connect", "execSync(", "eval(",
        ):
            # Source has comments about the forbidden route; check only
            # executable statements rather than banning documentation.
            executable = "\n".join(
                line for line in text.splitlines()
                if not line.lstrip().startswith("//")
            )
            self.assertNotIn(forbidden, executable)
        self.assertIn("['127.0.0.1', 'localhost'].includes(url.hostname)", text)
        self.assertIn("url.hostname = '127.0.0.1'", text)
        self.assertIn("fetch(url, { redirect: 'manual'", text)

    def test_real_disposable_image_ci_executes_oauth_only_no_bind_mount(self):
        text = WORKFLOW.read_text()
        start = text.index("      - name: Build real hardened BRC relay OCI image")
        end = text.index("      - name: Verify dedicated owner UID/GID image runtime", start)
        step = text[start:end]
        self.assertIn('docker exec -i "$container" node --input-type=module -', step)
        self.assertIn('scripts/h15_brc_zero_device_oauth_pilot.mjs', step)
        self.assertIn("H15_CI_ZERO_DEVICE_OAUTH_PKCE=PASS", step)
        self.assertIn("--network none", step)
        self.assertIn("--read-only", step)
        self.assertIn("--cap-drop ALL", step)
        self.assertIn('OCI_PRODUCTION_DEPLOY=NOT_EXECUTED', step)


if __name__ == "__main__":
    unittest.main()
