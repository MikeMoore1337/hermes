"""H-15 offline VPS staging invariants (#371); no Docker required for unit tests."""
import subprocess
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/h15/stage-relay.sh"


class OfflineStageTests(unittest.TestCase):
    def test_bash_syntax_is_valid(self):
        result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_requires_exact_preloaded_sha_not_registry_tags(self):
        content = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(r"^sha256:[a-f0-9]{64}$", content)
        self.assertIn("IMAGE_NOT_LOADED_LOCALLY", content)
        self.assertIn("WRONG_UPSTREAM_SOURCE", content)
        self.assertIn("IMAGE_BAKED_SECRETS", content)
        self.assertIn("IMAGE_NOT_NONROOT", content)
        self.assertIn("VPS_MEMORY_TOO_LOW", content)

    def test_hermetic_stage_has_no_egress_ports_host_mounts_or_privileges(self):
        source = SCRIPT.read_text(encoding="utf-8")
        first = source.index('docker run -d --name "$NAME"')
        last = source.index('    smoke\n', first)
        run = source[first:last]
        for flag in [
            "--network none", "--read-only", "--user 65534:65534",
            "--cap-drop ALL", "--security-opt no-new-privileges",
            "--memory 512m", "--cpus 0.50", "--pids-limit 80",
            "--restart no", "--tmpfs /state:", "--tmpfs /tmp:",
            "PUBLIC_URL=http://localhost:3000", "HOST=127.0.0.1",
        ]:
            self.assertIn(flag, run)
        for forbidden in ("--network host", "--privileged", "--publish", "-p 3000",
                          "-v /", "--volume", "--restart always", "--device",
                          "/var/run/docker.sock", "/var/lib/hermes-device-fabric"):
            self.assertNotIn(forbidden, run)

    def test_cleanup_is_scoped_only_to_our_own_container(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("FOREIGN_CONTAINER_NOT_OWNED", source)
        self.assertIn('[[ "$committed" != yes ]]', source)
        self.assertIn("trap cleanup_new_stage EXIT", source)
        self.assertIn('docker rm -f "$NAME"', source)
        self.assertNotIn("docker system prune", source)
        self.assertNotIn("docker volume prune", source)
        self.assertNotIn("systemctl stop", source)
        self.assertNotIn("systemctl disable", source)

    def test_reject_unapproved_image_argument_without_running_docker(self):
        # Run as nonroot if available? Syntax rejects tag only after user check,
        # so assert no invocation succeeds; both refusal paths acceptable.
        proc = subprocess.run(["bash", str(SCRIPT), "preflight", "latest"],
                              text=True, capture_output=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("H15_STAGE_REFUSED=", proc.stderr)
        self.assertNotIn("H15_STAGE_PREFLIGHT=PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
