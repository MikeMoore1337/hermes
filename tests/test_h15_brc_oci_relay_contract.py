"""Fail-closed containerization invariants for Hermes Remote MCP relay."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "deploy/h15/Dockerfile.brc-relay"
WORKFLOW = ROOT / ".github/workflows/h15-remote-commander-candidate.yml"
SMOKE = ROOT / "scripts/h15_brc_oci_relay_smoke.mjs"


class RemoteRelayContainerContractTests(unittest.TestCase):
    def test_runtime_is_nonroot_and_local_only(self):
        doc = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("USER 65534:65534", doc)
        self.assertIn("HOST=127.0.0.1", doc)
        self.assertIn("BRC_DB=/state/relay.sqlite", doc)
        self.assertIn('CMD ["node", "packages/relay/dist/cli.js"]', doc)
        self.assertIn("COPY --from=builder --chown=65534:65534", doc)
        self.assertIn("pnpm install --frozen-lockfile && pnpm build", doc)
        self.assertNotIn("BRC_ADMIN_PASSWORD=", doc)
        self.assertNotIn("BRC_SESSION_SECRET=", doc)

    def test_ephemeral_ci_has_no_public_network_or_host_privileges(self):
        job = WORKFLOW.read_text(encoding="utf-8")
        start = job.index("- name: Build real hardened BRC relay OCI image")
        body = job[start:job.index("- name: Build verified offline patch bundle", start)]
        for required in (
            "--network none", "--read-only", "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--user 65534:65534", "--memory 768m",
            "--pids-limit 100", "--tmpfs /state:", "docker port",
            "OCI_PUBLIC_PORTS=NONE",
            "OCI_PRODUCTION_DEPLOY=NOT_EXECUTED",
            "h15_brc_oci_relay_smoke.mjs",
        ):
            self.assertIn(required, body)
        self.assertNotIn("--privileged", body)
        self.assertNotIn("--network host", body)

    def test_actual_image_smoke_has_auth_and_readonly_canary(self):
        script = SMOKE.read_text(encoding="utf-8")
        for expected in (
            "HERMES_BRC_NONROOT_OCI_RELAY_E2E=PASS",
            "OCI_SOURCE_READONLY=PASS",
            "OCI_MCP_AUTH_REQUIRED",
            "OCI_EMPTY_UNPAIRED_RELAY",
            "OCI_NO_HOST_SSH_PRIVATE_KEY",
            "OCI_BROWSER_ORIGIN_REQUIRED",
        ):
            self.assertIn(expected, script)


if __name__ == "__main__":
    unittest.main()
