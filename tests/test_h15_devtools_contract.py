"""No-network source-contract checks for H-15 devtools candidate (#445).

These tests deliberately do not claim a Docker build or running-agent E2E.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "deploy" / "h15" / "devtools" / "Dockerfile"
DOC = ROOT / "deploy" / "h15" / "devtools" / "README.md"


class H15DevtoolsContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = DOCKERFILE.read_text(encoding="utf-8")
        cls.runbook = DOC.read_text(encoding="utf-8")

    def test_base_must_be_explicit_not_latest(self):
        self.assertRegex(self.source, r"(?m)^ARG BRC_BASE_IMAGE$")
        self.assertRegex(self.source, r"(?m)^FROM \$\{BRC_BASE_IMAGE\}$")
        self.assertNotRegex(self.source, r"(?m)^FROM\s+(?:node|debian|alpine):")
        self.assertIn("sha256:", self.runbook)
        self.assertIn("64", self.runbook)

    def test_static_snapshot_only(self):
        self.assertEqual(self.source.count("20261020T000000Z"), 2)
        self.assertIn("snapshot.debian.org/archive/debian/", self.source)
        self.assertIn("snapshot.debian.org/archive/debian-security/", self.source)
        self.assertIn('test "$ID" = debian', self.source)
        self.assertIn('test "$VERSION_CODENAME" = bookworm', self.source)
        self.assertNotIn("apt-get upgrade", self.source)
        self.assertNotIn("curl ", self.source)

    def test_minimal_dev_tools_only(self):
        self.assertIn("git python3 python3-pip python3-venv ca-certificates", self.source)
        self.assertIn("--no-install-recommends", self.source)
        self.assertNotIn("npm install", self.source)
        self.assertNotIn("pip install", self.source)
        self.assertNotIn("sudo", self.source)

    def test_no_new_runtime_grants(self):
        active = "\n".join(line for line in self.source.splitlines() if not line.lstrip().startswith("#"))
        self.assertEqual(len(re.findall(r"(?m)^USER\s", active)), 2)
        self.assertRegex(active, r"(?m)^USER 65534:65534$")
        for command in ("ENTRYPOINT", "CMD", "EXPOSE", "VOLUME", "HEALTHCHECK", "ADD", "COPY"):
            self.assertNotRegex(active, rf"(?m)^{command}\b")
        self.assertIn("NO-RUNTIME-ACTIVATION", self.runbook)
        self.assertIn("/workspace", self.runbook)

    def test_readme_requires_identity_and_rollback(self):
        for term in ("docker image inspect", "sha256:", "roll back", "No production", "offline", "BRC_BASE_IMAGE"):
            self.assertIn(term, self.runbook)


if __name__ == "__main__":
    unittest.main()
