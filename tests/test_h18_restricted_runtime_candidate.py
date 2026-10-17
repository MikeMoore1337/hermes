"""H-18 #199: local restricted derivative opt-in, no Docker/network/LLM."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import prepare_v0222_pyjwt_candidate as candidate


class RestrictedCandidateTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "repo"
        self.out = self.root / "staging"
        self.repo.mkdir()
        self.out.mkdir()
        self.wheel = self.root / candidate.WHEEL
        self.wheel.write_bytes(b"synthetic local PyJWT wheel")
        self.patch = self.root / candidate.PATCH
        self.patch.write_bytes(b"synthetic native guard patch")
        self.pyjwt_dockerfile = self.repo / "pyjwt.Dockerfile"
        self.restricted_dockerfile = self.repo / "restricted.Dockerfile"
        origin = b"FROM " + candidate.IMAGE.encode() + b"\n# sha256 " + hashlib.sha256(self.wheel.read_bytes()).hexdigest().encode()
        self.pyjwt_dockerfile.write_bytes(origin + b"\n# default")
        self.restricted_dockerfile.write_bytes(origin + b"\n# restricted")
        for key, value in {
            "ROOT": self.repo,
            "WHEEL_SHA256": hashlib.sha256(self.wheel.read_bytes()).hexdigest(),
            "PATCHFILE": self.patch,
            "PATCH_SHA256": hashlib.sha256(self.patch.read_bytes()).hexdigest(),
            "DOCKERFILE": self.pyjwt_dockerfile,
            "RESTRICTED_DOCKERFILE": self.restricted_dockerfile,
        }.items():
            patcher = mock.patch.object(candidate, key, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_default_recipe_is_backward_compatible(self):
        result = candidate.prepare(self.wheel, self.out / "default")
        self.assertEqual(result["candidate_recipe"], "pyjwt")
        self.assertEqual((self.out / "default" / "Dockerfile").read_bytes(),
                         self.pyjwt_dockerfile.read_bytes())
        self.assertFalse(result["resident_agent_allowed"])

    def test_explicit_restricted_stage_only(self):
        result = candidate.prepare(self.wheel, self.out / "restricted", recipe="restricted")
        self.assertEqual(result["files_staged"], 3)
        self.assertEqual(result["candidate_recipe"], "restricted")
        self.assertEqual((self.out / "restricted" / "Dockerfile").read_bytes(),
                         self.restricted_dockerfile.read_bytes())
        self.assertEqual({p.name for p in (self.out / "restricted").iterdir()},
                         {"Dockerfile", candidate.WHEEL, candidate.PATCH})
        self.assertFalse(result["build_executed"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_unknown_recipe_fails_closed_before_io(self):
        with self.assertRaisesRegex(candidate.ContextDenied, "unknown_candidate_recipe"):
            candidate.prepare(self.wheel, self.out / "unexpected", recipe="../../unsafe")
        self.assertFalse((self.out / "unexpected").exists())

    def test_restricted_recipe_missing_denied_without_fallback(self):
        self.restricted_dockerfile.unlink()
        with self.assertRaisesRegex(candidate.ContextDenied, "missing_or_invalid_input"):
            candidate.prepare(self.wheel, self.out / "fail", recipe="restricted")
        self.assertFalse((self.out / "fail").exists())

    def test_restricted_dockerfile_no_network_downloads(self):
        real = Path(__file__).resolve().parents[1] / "docker/v0222-restricted-runtime-candidate/Dockerfile"
        text = real.read_text(encoding="utf-8")
        self.assertIn("FROM " + candidate.IMAGE, text)
        self.assertIn("apt-get -s purge openssh-client linux-libc-dev", text)
        self.assertIn("apt-get --yes --no-download purge", text)
        self.assertIn("diff -u /tmp/h18-approved-removals /tmp/h18-observed-removals", text)
        self.assertIn("PyJWT[crypto]==2.15.1", text)
        self.assertNotIn("apt-get update", text)
        self.assertNotIn("apt-get autoremove", text)
        self.assertNotIn("--autoremove", text)
        self.assertNotIn("curl ", text)
        self.assertNotIn("wget ", text)


if __name__ == "__main__":
    unittest.main()
