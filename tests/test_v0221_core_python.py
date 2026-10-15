"""Core Python sample is byte-exact, bounded and never an agent GO."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import verify_v0221_core_python as audit

META = json.dumps([audit.IMAGE]).encode() + b"|amd64"


def rows(manifest):
    return [
        {"path": path, "git_blob_sha1": blob, "size": size}
        for path, (blob, size) in sorted(manifest.items())
    ]


def packet(files):
    return json.dumps({
        "schema": "hermes-v0221-image-python-tree-v1",
        "files": files,
    }, separators=(",", ":")).encode()


class CoreSourceParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = audit.load_manifest()

    def test_manifest_is_pinned_to_exact_official_source(self):
        self.assertEqual(len(self.manifest), 1410)
        self.assertEqual({root: sum(name.startswith(root + "/")
                                   for name in self.manifest)
                          for root in audit.ROOTS}, audit.COUNTS)
        self.assertIn("agent/tool_guardrails.py", self.manifest)
        self.assertIn("gateway/__init__.py", self.manifest)

    def test_dry_run_never_touches_docker_or_filesystem(self):
        with patch.object(audit, "observe") as observer:
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(audit.main([]), 0)
        observer.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["status"], "NOT_EXECUTED")

    def test_container_is_pinned_nonroot_offline_and_without_mounts(self):
        first, second = audit.commands()
        self.assertEqual(first[:3], ["docker", "image", "inspect"])
        self.assertEqual(second.count(audit.IMAGE), 1)
        for required in ("--pull=never", "--network", "none", "--read-only",
                         "--cap-drop", "ALL", "--user", "65534:65534",
                         "--memory", "256m", "--pids-limit", "25"):
            self.assertIn(required, second)
        for forbidden in ("--privileged", "--volume", "--mount", "--env-file",
                          "-v", "pull", "push", "login"):
            self.assertNotIn(forbidden, second)
        self.assertIn("file.is_symlink()", audit.INSPECTOR)
        self.assertIn('hashlib.sha1(', audit.INSPECTOR)

    def test_all_matching_python_blobs_remain_unattested_and_no_go(self):
        result = audit.compare(self.manifest, packet(rows(self.manifest)))
        self.assertEqual(result["status"], "CORE_PYTHON_BLOBS_MATCH_UNATTESTED")
        self.assertEqual(result["expected_files"], 1410)
        self.assertTrue(result["sampled_scope_matches"])
        self.assertFalse(result["full_source_to_image_parity_verified"])
        self.assertFalse(result["supplier_attestation_verified"])
        self.assertFalse(result["complete_sbom_verified"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_one_changed_content_detected_without_exposing_body(self):
        files = rows(self.manifest)
        files[0]["git_blob_sha1"] = "0" * 40
        result = audit.compare(self.manifest, packet(files))
        self.assertEqual(result["different_count"], 1)
        self.assertFalse(result["sampled_scope_matches"])
        self.assertEqual(result["status"], "CORE_PYTHON_BLOBS_MISMATCH")

    def test_missing_or_extra_python_file_fails_comparison(self):
        files = rows(self.manifest)
        missing = audit.compare(self.manifest, packet(files[:-1]))
        self.assertEqual(missing["missing_count"], 1)
        self.assertFalse(missing["sampled_scope_matches"])
        files.append({"path": "agent/extra_unattested.py",
                      "git_blob_sha1": "0" * 40, "size": 0})
        extra = audit.compare(self.manifest, packet(files))
        self.assertEqual(extra["extra_count"], 1)
        self.assertFalse(extra["sampled_scope_matches"])

    def test_path_escape_duplicate_and_malformed_json_fail_closed(self):
        files = rows(self.manifest)
        for modified in (
            [*files, files[0]],
            [*files, {"path": "../secret.py", "git_blob_sha1": "0"*40, "size": 0}],
            [*files, {"path": "agent/secret.py", "git_blob_sha1": "notahash", "size": 0}],
        ):
            with self.subTest(length=len(modified)):
                with self.assertRaises(audit.ParityDenied):
                    audit.compare(self.manifest, packet(modified))
        with self.assertRaises(audit.ParityDenied):
            audit.compare(self.manifest,
                          b'{"schema":"x","schema":"y","files":[]}')

    def test_wrong_digest_or_arch_denied_before_container(self):
        for data in (b"[]|amd64", b"[]|arm64",
                     json.dumps([audit.IMAGE]).encode() + b"|arm64"):
            with self.subTest(data=data):
                with self.assertRaises(audit.ParityDenied):
                    audit.image_identity(data)

    def test_image_mismatch_never_starts_container(self):
        runner = Mock(return_value=Mock(returncode=0, stdout=b"[]|amd64"))
        with self.assertRaises(audit.ParityDenied):
            audit.observe(runner=runner)
        runner.assert_called_once()

    def test_exact_two_docker_commands_and_no_raw_stderr(self):
        calls = []
        def runner(cmd, **kw):
            calls.append(cmd)
            return Mock(returncode=0, stdout=META if len(calls) == 1
                        else packet(rows(self.manifest)), stderr=b"PRIVATE_TOKEN")
        result = audit.observe(runner=runner)
        self.assertEqual(calls, list(audit.commands()))
        self.assertNotIn("PRIVATE_TOKEN", str(result))

    def test_manifest_wrong_source_commit_rejected_before_docker(self):
        doc = json.loads(audit.MANIFEST.read_text(encoding="utf-8"))
        doc["source_commit"] = "0" * 40
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "source-manifest.json"
            path.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaisesRegex(audit.ParityDenied, "manifest_identity_invalid"):
                audit.load_manifest(path)

    def test_cli_keeps_exit_code_two_even_when_bytes_match(self):
        passing = audit.compare(self.manifest, packet(rows(self.manifest)))
        with patch.object(audit, "observe", return_value=passing):
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(audit.main(["--execute"]), 2)
        self.assertFalse(json.loads(output.getvalue())["resident_agent_allowed"])


if __name__ == "__main__":
    unittest.main()
