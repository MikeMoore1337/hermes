"""H-15: pinned Debian perl security update only inside the evaluation OCI runtime."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "deploy/h15/Dockerfile.brc-relay"
WORKFLOW = ROOT / ".github/workflows/h15-remote-commander-candidate.yml"
FIXED = "5.36.0-7+deb12u4"


class RuntimePerlSecurityTests(unittest.TestCase):
    def test_exact_debian_security_package_in_runtime_only(self):
        dockerfile = DOCKERFILE.read_text()
        builder, runtime = dockerfile.split("\nFROM node:24-bookworm-slim@", 1)
        self.assertNotIn("apt-get", builder)
        self.assertIn(" AS runtime", runtime)
        self.assertIn("perl-base=" + FIXED, runtime)
        self.assertIn("apt-get install --yes --no-install-recommends", runtime)
        self.assertIn("apt-get update", runtime)
        self.assertIn("dpkg-query -W '-f=${Version}' perl-base", runtime)
        self.assertIn("rm -rf /var/lib/apt/lists/*", runtime)
        self.assertIn("USER 65534:65534", runtime)
        self.assertNotIn("upgrade -y", runtime)
        self.assertNotIn("dist-upgrade", runtime)
        self.assertNotIn("apt-get autoremove", runtime)
        self.assertIn("a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5", runtime)

    def test_exact_image_proof_in_full_h15_ci(self):
        workflow = WORKFLOW.read_text()
        before = workflow.index("      - name: Build real hardened BRC relay OCI image")
        after = workflow.index("      - name: Verify dedicated owner UID/GID image runtime", before)
        section = workflow[before:after]
        self.assertIn("H15_RUNTIME_PERL_BASE_FIXED_VERSION=PASS", section)
        self.assertIn('--entrypoint dpkg-query', section)
        self.assertIn('--network none', section)
        self.assertIn('--read-only', section)
        self.assertIn('--cap-drop ALL', section)
        self.assertIn('--user 65534:65534', section)
        self.assertIn('test "$package" = "' + FIXED + '"', section)
        for forbidden in ("--privileged", "--network host", "/var/run/docker.sock"):
            self.assertNotIn(forbidden, section)


if __name__ == "__main__":
    unittest.main()
