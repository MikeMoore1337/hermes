"""Offline syntax scan proof and fail-closed tests; no real image in CI."""
from __future__ import annotations

from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock
import copy
import io
import json
import tempfile
import unittest

from scripts import audit_v0222_installed_jwt_callsites as audit


class ImageJWTSourceTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        for folder in audit.ROOTS:
            (self.root / folder).mkdir()
        for name in audit.EXPECTED_BLOBS:
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"# SYNTHETIC PINNED\n")
        sha = audit._git_blob(b"# SYNTHETIC PINNED\n")
        self.expected = {name: sha for name in audit.EXPECTED_BLOBS}

    def sample(self, filename="plugins/fixture.py", code='import jwt\njwt.decode("fake", key, algorithms=["RS256"])\n'):
        p = self.root / filename
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(code, encoding="utf-8")
        with mock.patch.object(audit, "EXPECTED_BLOBS", self.expected):
            return audit.analyze(self.root)

    def test_observed_callsite_never_grants_admission(self):
        report = self.sample()
        self.assertEqual(report["status"], "P0_REVIEW_REQUIRED")
        self.assertEqual(report["tag_blob_checks"], 5)
        self.assertTrue(report["tag_blob_parity_checked"])
        self.assertEqual(report["jwt_decode_callsites_found"], 1)
        self.assertEqual(report["callsites"][0]["review_reason"],
                         "LITERAL_ALGORITHMS_REQUIRE_KEY_REVIEW")
        self.assertFalse(report["resident_agent_allowed"])
        self.assertFalse(report["source_to_image_provenance_verified"]
                         if "source_to_image_provenance_verified" in report
                         else report["total_installed_source_provenance_verified"])
        self.assertFalse(report["third_party_site_packages_covered"])

    def test_import_as_and_from_import_are_found(self):
        code = ('import jwt as signed\nfrom jwt import decode as imported\n'
                'signed.decode("x", key, algorithms=["RS256"])\n'
                'imported("x", key, algorithms=["RS256"])\n')
        r = self.sample(code=code)
        self.assertEqual(r["jwt_decode_callsites_found"], 2)

    def test_mixed_algorithms_detected_but_no_go(self):
        r = self.sample(code='import jwt\njwt.decode("x", key, algorithms=["HS256","RS256"])\n')
        self.assertTrue(r["callsites"][0]["mixed_algorithms_literal"])
        self.assertEqual(r["callsites"][0]["review_reason"], "MIXED_HS_ASYMMETRIC_LITERAL")
        self.assertFalse(r["resident_agent_allowed"])

    def test_unsigned_unverified_decode_detected(self):
        r = self.sample(code='import jwt\njwt.decode("x", options={"verify_signature": False})\n')
        self.assertEqual(r["callsites"][0]["review_reason"], "UNVERIFIED_DECODE")
        self.assertTrue(r["callsites"][0]["verified_signature_disabled_literal"])

    def test_positional_algorithm_allowlist_and_options_are_audited(self):
        # Old AST review ignored the third and fourth PyJWT.decode arguments.
        mixed = self.sample(code='import jwt\njwt.decode("x", key, ["HS256", "RS256"])\n')
        self.assertTrue(mixed["callsites"][0]["mixed_algorithms_literal"])
        self.assertEqual(
            mixed["callsites"][0]["review_reason"], "MIXED_HS_ASYMMETRIC_LITERAL"
        )
        unsigned = self.sample(
            code='import jwt\njwt.decode("x", key, ["RS256"], {"verify_signature": False})\n'
        )
        self.assertTrue(unsigned["callsites"][0]["verified_signature_disabled_literal"])
        self.assertEqual(unsigned["callsites"][0]["review_reason"], "UNVERIFIED_DECODE")
        self.assertFalse(unsigned["resident_agent_allowed"])

    def test_dynamic_kwargs_are_conservatively_flagged(self):
        r = self.sample(code='import jwt\njwt.decode("x", key, **decode_kwargs)\n')
        self.assertEqual(r["callsites"][0]["review_reason"], "DYNAMIC_KWARGS")
        self.assertFalse(r["dynamic_dispatch_fully_analyzed"])

    def test_dynamic_algorithms_not_trusted(self):
        r = self.sample(code='import jwt\njwt.decode("x", key, algorithms=algorithms)\n')
        self.assertEqual(r["callsites"][0]["review_reason"], "DYNAMIC_OR_MISSING_ALGORITHMS")

    def test_git_blob_drift_is_denied(self):
        (self.root / "pyproject.toml").write_bytes(b"ALTERED\n")
        with mock.patch.object(audit, "EXPECTED_BLOBS", self.expected):
            with self.assertRaisesRegex(audit.EvidenceInvalid, "installed_source_differs_from_exact_tag"):
                audit.analyze(self.root)

    def test_unparseable_source_is_inconclusive(self):
        with self.assertRaisesRegex(audit.EvidenceInvalid, "unparseable_installed_source"):
            self.sample(code="def broken(: pass\n")

    def test_synthetic_code_content_not_quoted_in_report(self):
        r = self.sample(code='import jwt\n# PRIVATE_VALUE_SAMPLE\njwt.decode("private-token", key, algorithms=["RS256"])\n')
        self.assertNotIn("PRIVATE_VALUE_SAMPLE", json.dumps(r))
        self.assertNotIn("private-token", json.dumps(r))

    def test_empty_python_module_is_permitted(self):
        r = self.sample(code="")
        self.assertEqual(r["jwt_decode_callsites_found"], 0)
        self.assertEqual(r["status"], "P0_REVIEW_REQUIRED")

    def test_wrong_scope_and_missing_roots_rejected(self):
        (self.root / "pm").rmdir()
        with mock.patch.object(audit, "EXPECTED_BLOBS", self.expected):
            with self.assertRaisesRegex(audit.EvidenceInvalid, "missing_or_symlinked_scope"):
                audit.analyze(self.root)

    def test_size_denied(self):
        with mock.patch.object(audit, "EXPECTED_BLOBS", self.expected):
            (self.root / "pm" / "huge.py").write_bytes(b"x" * (audit.MAX_FILE+1))
            with self.assertRaisesRegex(audit.EvidenceInvalid, "source_size_denied"):
                audit.analyze(self.root)

    def test_cli_default_not_executed(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(audit.main([]), 0)
        self.assertEqual(json.loads(out.getvalue())["status"], "NOT_EXECUTED")

    def test_cli_missing_snapshot_fail_closed(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(audit.main(["--execute", "--source-dir", str(self.root / "missing")]), 2)
        r = json.loads(out.getvalue())
        self.assertEqual(r["status"], "INCONCLUSIVE")
        self.assertFalse(r["resident_agent_allowed"])
        self.assertNotIn(str(self.root), out.getvalue())


if __name__ == "__main__":
    unittest.main()
