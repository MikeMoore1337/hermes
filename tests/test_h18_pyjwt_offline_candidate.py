"""H-18 fixed PyJWT 2.14 derivative staging: synthetic, NO Docker/LLM."""
from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import prepare_v0222_pyjwt_candidate as candidate


class CandidatePreflightTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.root = self.tmp / "repo"
        self.out = self.tmp / "outside"
        self.root.mkdir()
        self.out.mkdir()
        self.patch = self.root / candidate.PATCH
        self.dockerfile = self.root / "Dockerfile"
        self.wheel = self.tmp / candidate.WHEEL
        self.wheel.write_bytes(b"synthetic wheel bytes")
        self.patch.write_bytes(b"--- synthetic security patch ---")
        self.dockerfile.write_bytes(b"FROM " + candidate.IMAGE.encode() +
                                    b"\n# immutable sha256=" + hashlib.sha256(self.wheel.read_bytes()).hexdigest().encode())
        self.settings = [
            mock.patch.object(candidate, "ROOT", self.root),
            mock.patch.object(candidate, "PATCHFILE", self.patch),
            mock.patch.object(candidate, "DOCKERFILE", self.dockerfile),
            mock.patch.object(candidate, "WHEEL_SHA256",
                              hashlib.sha256(self.wheel.read_bytes()).hexdigest()),
            mock.patch.object(candidate, "PATCH_SHA256",
                              hashlib.sha256(self.patch.read_bytes()).hexdigest()),
        ]
        for setting in self.settings:
            setting.start()
            self.addCleanup(setting.stop)

    def test_copy_exact_three_artifacts_no_build(self):
        path = self.out / "new-stage"
        result = candidate.prepare(self.wheel, path)
        self.assertEqual(result["files_staged"], 3)
        self.assertEqual(result["status"], "OFFLINE_CONTEXT_PREPARED_NO_GO")
        self.assertFalse(result["build_executed"])
        self.assertFalse(result["resident_agent_allowed"])
        self.assertEqual({p.name for p in path.iterdir()},
                         {"Dockerfile", candidate.PATCH, candidate.WHEEL})
        self.assertEqual((path / candidate.WHEEL).read_bytes(), self.wheel.read_bytes())

    def test_broken_wheel_is_denied_before_stage(self):
        with mock.patch.object(candidate, "WHEEL_SHA256", "0" * 64):
            with self.assertRaisesRegex(candidate.ContextDenied, "input_sha256_mismatch"):
                candidate.prepare(self.wheel, self.out / "stage")

    def test_wrong_patch_is_denied_before_stage(self):
        with mock.patch.object(candidate, "PATCH_SHA256", "a" * 64):
            with self.assertRaisesRegex(candidate.ContextDenied, "input_sha256_mismatch"):
                candidate.prepare(self.wheel, self.out / "stage")

    def test_wrong_base_denied(self):
        self.dockerfile.write_bytes(b"FROM docker.io/not-allowed:latest")
        with self.assertRaisesRegex(candidate.ContextDenied, "unrecognized_immutable_build_recipe"):
            candidate.prepare(self.wheel, self.out / "stage")

    def test_output_inside_repository_denied(self):
        with self.assertRaisesRegex(candidate.ContextDenied, "unsafe_output_directory"):
            candidate.prepare(self.wheel, self.root / "stage")

    def test_output_existing_denied_and_unmodified(self):
        path = self.out / "existing"
        path.mkdir()
        (path / "sentinel").write_text("untouched")
        with self.assertRaisesRegex(candidate.ContextDenied, "output_must_not_exist"):
            candidate.prepare(self.wheel, path)
        self.assertEqual((path / "sentinel").read_text(), "untouched")

    def test_wrong_wheel_name_denied(self):
        other = self.tmp / "trojan.whl"
        other.write_bytes(self.wheel.read_bytes())
        with self.assertRaisesRegex(candidate.ContextDenied, "unexpected_wheel_filename"):
            candidate.prepare(other, self.out / "stage")

    def test_missing_parent_denied(self):
        with self.assertRaisesRegex(candidate.ContextDenied, "output_must_not_exist"):
            candidate.prepare(self.wheel, self.tmp / "absent" / "stage")

    def test_no_wheel_bytes_in_repo(self):
        stage = self.out / "context"
        candidate.prepare(self.wheel, stage)
        self.assertFalse((self.root / candidate.WHEEL).exists())

    def test_default_does_not_touch_paths(self):
        output = io.StringIO()
        with redirect_stdout(output):
            rc = candidate.main([])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "NOT_EXECUTED")

    def test_cli_sanitizes_error_and_denies_go(self):
        output = io.StringIO()
        with redirect_stdout(output):
            rc = candidate.main(["--execute", "--wheel", str(self.root / "PRIVATE_TOKEN_PATH"),
                                 "--output-dir", str(self.out / "context")])
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "INCONCLUSIVE")
        self.assertNotIn("PRIVATE_TOKEN_PATH", output.getvalue())
        self.assertFalse(json.loads(output.getvalue())["resident_agent_allowed"])

    def test_cli_valid_staging_returns_exit_2(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = candidate.main(["--execute", "--wheel", str(self.wheel),
                                 "--output-dir", str(self.out / "stage")])
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(out.getvalue())["status"], "OFFLINE_CONTEXT_PREPARED_NO_GO")


if __name__ == "__main__":
    unittest.main()
