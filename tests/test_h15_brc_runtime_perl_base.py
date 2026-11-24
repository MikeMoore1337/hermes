"""H-15: pinned Debian security-fixed APT and Perl in the OCI runtime."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "deploy/h15/Dockerfile.brc-relay"
WORKFLOW = ROOT / ".github/workflows/h15-remote-commander-candidate.yml"
FIXED = "5.40.1-6+deb13u1"
BASE = "4d00acb4bcc42c454c4eb801526f7ad7f772ea3bd4fd168c5cc2e384abcbb9d4"


class RuntimePerlSecurityTests(unittest.TestCase):
    def test_exact_debian_security_packages_in_pinned_runtime(self):
        dockerfile = DOCKERFILE.read_text()
        builder, runtime = dockerfile.split("\nFROM node:24-trixie-slim@", 1)
        self.assertNotIn("apt-get", builder)
        self.assertIn(" AS runtime", runtime)
        self.assertEqual(dockerfile.count("node:24-trixie-slim@sha256:" + BASE), 2)
        self.assertIn("dpkg-query -W '-f=${Version}' perl-base", runtime)
        self.assertIn("= '" + FIXED + "'", runtime)
        for package in ("apt", "libapt-pkg7.0"):
            self.assertIn("dpkg-query -W '-f=${Version}' " + package, runtime)
        self.assertEqual(runtime.count("= '3.0.4'"), 2)
        self.assertIn("dpkg-query -W '-f=${Version}' libpam0g", runtime)
        self.assertIn("= '1.7.0-5'", runtime)
        self.assertIn("dpkg-query -W '-f=${Version}' zlib1g", runtime)
        self.assertIn("= '1:1.3.dfsg+really1.3.1-1+deb13u1'", runtime)
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
        self.assertIn('for name in apt libapt-pkg7.0', section)
        self.assertIn('test "$package" = "3.0.4"', section)
        self.assertIn('H15_RUNTIME_APT_FIXED_VERSION=PASS', section)
        self.assertIn('libpam0g=1.7.0-5', section)
        self.assertIn('zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1', section)
        self.assertIn('H15_RUNTIME_PAM_ZLIB_FIXED_VERSIONS=PASS', section)
        for forbidden in ("--privileged", "--network host", "/var/run/docker.sock"):
            self.assertNotIn(forbidden, section)


if __name__ == "__main__":
    unittest.main()
