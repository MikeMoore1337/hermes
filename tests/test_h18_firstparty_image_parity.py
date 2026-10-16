"""Offline synthetic image-to-upstream byte parity regression tests."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import audit_v0222_firstparty_image_parity as audit


class FirstPartyParityTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        self.image = self.root / "image"
        self.source = self.root / "git"
        self.image.mkdir()
        self.source.mkdir()
        self.tracked = []
        for i, part in enumerate(audit.ROOTS):
            name = part + "/component.py"
            self.tracked.append(name)
            for folder in (self.image, self.source):
                path = folder / name
                path.parent.mkdir(parents=True)
                path.write_bytes(f"# EXAMPLE {i}\n".encode())
        self.vendor = {}
        for key, prefix in audit.VENDOR_PREFIXES.items():
            name = prefix + "lib/synthetic.py"
            p = self.image / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"# synthetic vendor\n")
            self.vendor[key] = name

    def report(self):
        return audit.compare_trees(self.image, self.source, self.tracked)

    def test_bounded_parity_never_allows_resident(self):
        result = self.report()
        self.assertEqual(result["status"], "FIRST_PARTY_SUBSET_PARITY_NO_GO")
        self.assertEqual(result["first_party_matching"], 8)
        self.assertEqual(result["image_python_files_scanned"], 11)
        self.assertEqual(result["embedded_runtime_python_files_unattested"], 3)
        self.assertTrue(all(v == 1 for v in result["embedded_vendor_python_file_counts"].values()))
        for key in ("resident_agent_allowed", "all_cve_fixed", "compiled_native_files_verified",
                    "source_to_build_to_image_attestation_verified"):
            self.assertFalse(result[key])

    def test_modified_installed_file_reported_no_source_leak(self):
        (self.image / "agent/component.py").write_bytes(b"PRIVATE_MARKER\n")
        result = self.report()
        self.assertEqual(result["status"], "FIRST_PARTY_SOURCE_DRIFT")
        self.assertEqual(result["first_party_differing"], 1)
        self.assertNotIn("PRIVATE_MARKER", json.dumps(result))

    def test_missing_image_file_rejected(self):
        (self.image / "agent/component.py").unlink()
        with self.assertRaisesRegex(audit.ParityDenied, "unexpected_or_missing"):
            self.report()

    def test_unexpected_extra_source_rejected(self):
        (self.image / "tools/unknown.py").write_bytes(b"")
        with self.assertRaisesRegex(audit.ParityDenied, "unexpected_or_missing"):
            self.report()

    def test_new_vendor_version_not_implicitly_allowed(self):
        extra = self.image / "tools/python-3.14.8-unknown/lib/abc.py"
        extra.parent.mkdir(parents=True)
        extra.write_bytes(b"")
        with self.assertRaisesRegex(audit.ParityDenied, "unexpected_or_missing"):
            self.report()

    def test_three_vendor_runtime_sources_explicitly_unattested(self):
        result = self.report()
        self.assertEqual(set(result["embedded_vendor_python_file_counts"]), set(self.vendor))
        self.assertFalse(result["embedded_python_runtime_provenance_verified"])

    def test_vendor_mutation_not_misreported_as_first_party_match(self):
        before = self.report()["vendor_source_fingerprint_unattested"]
        (self.image / self.vendor["node-26.7.0"]).write_bytes(b"UPDATED_VENDOR")
        after = self.report()
        self.assertNotEqual(before, after["vendor_source_fingerprint_unattested"])
        self.assertEqual(after["first_party_matching"], 8)

    def test_empty_and_duplicate_tracking_sets_rejected(self):
        for names in ([], [*self.tracked, self.tracked[0]]):
            with self.subTest(names=len(names)):
                with self.assertRaisesRegex(audit.ParityDenied, "unbounded_or_duplicate"):
                    audit.compare_trees(self.image, self.source, names)

    def test_git_escape_attempt_rejected(self):
        with self.assertRaisesRegex(audit.ParityDenied, "unsafe_tracked_git_paths"):
            audit.compare_trees(self.image, self.source, [*self.tracked, "agent/../evil.py"])

    def test_symlinked_python_denied_when_available(self):
        path = self.image / "agent/extra.py"
        try:
            path.symlink_to(self.image / "agent/component.py")
        except (NotImplementedError, OSError):
            self.skipTest("No filesystem symlink privilege")
        with self.assertRaisesRegex(audit.ParityDenied, "symlinked_python_file"):
            self.report()

    def test_absent_root_denied(self):
        (self.image / "gateway/component.py").unlink()
        (self.image / "gateway").rmdir()
        with self.assertRaisesRegex(audit.ParityDenied, "missing_image_scope"):
            self.report()

    def test_large_source_file_denied(self):
        (self.source / self.tracked[0]).write_bytes(b"x" * (audit.MAX_FILE_BYTES + 1))
        with self.assertRaisesRegex(audit.ParityDenied, "missing_or_oversized_file"):
            self.report()

    def test_default_cli_does_not_read_snapshot(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(audit.main([]), 0)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "NOT_EXECUTED")

    def test_invalid_cli_fails_closed_without_path(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = audit.main(["--execute", "--image-tree", str(self.root / "PRIVATE"),
                               "--source-tree", str(self.source)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())["status"], "INCONCLUSIVE")
        self.assertNotIn(str(self.root), out.getvalue())

    def test_successful_synthetic_match_still_returns_exit_2(self):
        out = io.StringIO()
        with mock.patch.object(audit, "_verified_git_filenames", return_value=self.tracked):
            with redirect_stdout(out):
                code = audit.main(["--execute", "--image-tree", str(self.image),
                                   "--source-tree", str(self.source)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())["status"], "FIRST_PARTY_SUBSET_PARITY_NO_GO")


if __name__ == "__main__":
    unittest.main()
