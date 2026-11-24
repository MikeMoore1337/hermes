"""H-15: pinned Debian security-fixed APT and Perl in the OCI runtime."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "deploy/h15/Dockerfile.brc-relay"
WORKFLOW = ROOT / ".github/workflows/h15-remote-commander-candidate.yml"
FIXED = "5.36.0-7+deb12u4"
BASE = "873f586f3794f52281bd039bf02c048a0be08fde619338f9941bad1eb6b34530"


class RuntimePerlSecurityTests(unittest.TestCase):
    def test_exact_debian_security_packages_in_pinned_runtime(self):
        dockerfile = DOCKERFILE.read_text()
        builder, runtime = dockerfile.split("\nFROM node:24-bookworm-slim@", 1)
        self.assertNotIn("apt-get", builder)
        self.assertIn(" AS runtime", runtime)
        self.assertEqual(dockerfile.count("node:24-bookworm-slim@sha256:" + BASE), 2)
        self.assertIn("dpkg-query -W '-f=${Version}' perl-base", runtime)
        self.assertIn("= '" + FIXED + "'", runtime)
        for package in ("apt", "libapt-pkg6.0"):
            self.assertIn("dpkg-query -W '-f=${Version}' " + package, runtime)
        self.assertEqual(runtime.count("= '2.6.2'"), 2)
        self.assertNotIn("apt-get", runtime)
        self.assertIn("USER 65534:65534", runtime)
        self.assertNotIn("upgrade -y", runtime)
        self.assertNotIn("dist-upgrade", runtime)
        self.assertNotIn("apt-get autoremove", runtime)
        self.assertIn(BASE, runtime)

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
        self.assertIn('for name in apt libapt-pkg6.0', section)
        self.assertIn('test "$package" = "2.6.2"', section)
        self.assertIn('H15_RUNTIME_APT_FIXED_VERSION=PASS', section)
        for forbidden in ("--privileged", "--network host", "/var/run/docker.sock"):
            self.assertNotIn(forbidden, section)


if __name__ == "__main__":
    unittest.main()
