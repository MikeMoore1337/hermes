"""No dependencies and no external or upstream code execution during tests."""
from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import audit_v0222_python_surface as scope


class SurfaceTests(unittest.TestCase):
    def test_three_direct_jwt_calls_and_two_wrappers(self):
        fixture = {
            "auth/client.py": b'''
import jwt as tokenjwt
from jwt import decode as decode_helper

def verified(token, key):
    one = tokenjwt.decode(token, key, algorithms=["RS256"])
    two = decode_helper(token, key, algorithms=["RS256", "HS256"])
    three = tokenjwt.decode(token, options={"verify_signature": False})
    return one, two, three
''',
            "auth/wrapper.py": b'''
def caller(token, provider):
    verify_jwt(token, provider, algorithms=["RS256"])
    verify_jwt(token, provider, algorithms=["ES256"])
''',
        }
        result = scope.scan_source_blobs(fixture)
        self.assertEqual(result["python_files_examined"], 2)
        self.assertEqual(len(result["jwt_decode_sites"]), 3)
        self.assertEqual(result["jwt_verify_wrapper_calls"], 2)
        self.assertEqual(sum(c["literal_mixed_hs_asymmetric_algorithms"]
                             for c in result["jwt_decode_sites"]), 1)
        self.assertEqual(sum(c["signature_verification_disabled_literal"]
                             for c in result["jwt_decode_sites"]), 1)
        self.assertFalse(result["all_possible_dynamic_calls_proven_absent"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_dynamic_kwargs_and_import_aliases_never_prove_safe(self):
        blobs = {"runtime/jwt_auth.py": b'''
import jwt
def verify(token, key, config):
    return jwt.decode(token, key, **config)
'''}
        out = scope.scan_source_blobs(blobs)
        self.assertEqual(len(out["jwt_decode_sites"]), 1)
        call = out["jwt_decode_sites"][0]
        self.assertTrue(call["has_expanded_kwargs"])
        self.assertFalse(call["algorithms_static_literal"])
        self.assertFalse(out["signed_source_image_provenance_verified"])

    def test_zero_byte_valid_tracked_py_and_deterministic_digest(self):
        a = {"src/__init__.py": b"", "src/code.py": b"import json\n"}
        b = dict(reversed(list(a.items())))
        r1 = scope.scan_source_blobs(a)
        r2 = scope.scan_source_blobs(b)
        self.assertEqual(r1["python_files_examined"], 2)
        self.assertEqual(r1["file_content_digest_sha256"], r2["file_content_digest_sha256"])
        self.assertEqual(r1["python_bytes_examined"], len(a["src/code.py"]))

    def test_xml_parsing_is_flagged_as_path_candidate_not_exploit(self):
        out = scope.scan_source_blobs({
            "app/xml_in.py": b"from xml.etree import ElementTree\n",
            "app/lxml_in.py": b"import lxml.etree\n",
            "tests/ignore.py": b"import lxml.etree\n",
            "module/tests/test_code.py": b"from xml.etree import ElementTree\n",
            "app/ssh.py": b"SSH_TARGET = 'ssh'\n",
        })
        self.assertEqual(out["production_xml_import_files"], ["app/lxml_in.py", "app/xml_in.py"])
        self.assertEqual(out["production_ssh_text_reference_file_count"], 1)
        self.assertFalse(out["resident_agent_allowed"])

    def test_dirty_or_wrong_commit_refused_before_any_parsing(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            with patch.object(scope, "_git", side_effect=[
                b"wrong\n",
            ]):
                with self.assertRaisesRegex(scope.SourceAuditDenied, "wrong_upstream_commit"):
                    scope._verified_git_filenames(path)
            with patch.object(scope, "_git", side_effect=[
                scope.UPSTREAM_COMMIT.encode()+b"\n", b" M pyproject.toml\n",
            ]):
                with self.assertRaisesRegex(scope.SourceAuditDenied, "dirty_upstream_source"):
                    scope._verified_git_filenames(path)

    def test_invalid_git_filename_and_incomplete_inventory_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            calls = [scope.UPSTREAM_COMMIT.encode()+b"\n", b"", b"evil/../secret.py\0"]
            with patch.object(scope, "_git", side_effect=calls):
                with self.assertRaisesRegex(scope.SourceAuditDenied, "unsafe_git_file_path"):
                    scope._verified_git_filenames(path)
            # Even if filenames look valid, a 2-file directory is not full v0.22.2.
            calls = [scope.UPSTREAM_COMMIT.encode()+b"\n", b"", b"a.py\0b.py\0"]
            with patch.object(scope, "_git", side_effect=calls):
                with self.assertRaisesRegex(scope.SourceAuditDenied,
                                            "incomplete_git_python_inventory"):
                    scope._verified_git_filenames(path)

    def test_oversized_sources_and_bad_data_refused(self):
        with self.assertRaisesRegex(scope.SourceAuditDenied, "invalid_source_file"):
            scope.scan_source_blobs({"large.py": b"x" * (scope.MAX_PY_BYTES + 1)})
        with self.assertRaisesRegex(scope.SourceAuditDenied, "invalid_source_file"):
            scope.scan_source_blobs({"not-python.txt": b"import jwt"})
        with self.assertRaisesRegex(scope.SourceAuditDenied, "invalid_source_file"):
            scope.scan_source_blobs({"data.py": "not bytes"})

    def test_bad_python_candidate_is_not_silently_parsed(self):
        out = scope.scan_source_blobs({"runtime.py": b"import jwt\nif ???\n"})
        self.assertEqual(out["candidate_python_parse_errors"], 1)
        self.assertEqual(out["jwt_decode_sites"], [])
        self.assertFalse(out["resident_agent_allowed"])

    def test_no_execute_default_or_missing_source_reports_no_go(self):
        with patch("sys.stdout", new_callable=io.StringIO) as buf:
            self.assertEqual(scope.main([]), 0)
            self.assertEqual(json.loads(buf.getvalue())["status"], "NOT_EXECUTED")
        with patch("sys.stdout", new_callable=io.StringIO) as buf:
            self.assertEqual(scope.main(["--execute"]), 2)
            self.assertEqual(json.loads(buf.getvalue())["status"], "INCONCLUSIVE")
        with patch("sys.stdout", new_callable=io.StringIO) as buf:
            self.assertEqual(scope.main(["--execute", "--source-tree", "/not-present"]), 2)
            self.assertFalse(json.loads(buf.getvalue())["resident_agent_allowed"])
            self.assertNotIn("/not-present", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
