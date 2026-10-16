"""Deterministic offline H-18 critical PyJWT prerequisites review tests."""
from __future__ import annotations

import ast
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import audit_v0222_critical_jwt as audit

CHRONOS = '''
def verify_nas_fire_token():
    key = jwks_client.get_signing_key_from_jwt(token)
    decode_kwargs = dict(algorithms=["RS256", "ES256"], audience=expected_audience)
    claims = jwt.decode(token, key, **decode_kwargs)
    return claims
'''
NOUS = '''
def _claims_for(self, access_token):
    return verify_jwt(access_token, self._get_jwks_client(), algorithms=["RS256"])
'''
SELF_HOSTED = '''
_ALLOWED_ID_TOKEN_ALGS = ("RS256", "ES256", "RS384")
def _verify_id_token(self, id_token):
    return verify_jwt(id_token, self._get_jwks_client(),
        algorithms=list(_ALLOWED_ID_TOKEN_ALGS))
'''
SHARED = '''
def verify_jwt(token, jwks_client, *, algorithms, audience, issuer, label):
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    try:
        return jwt.decode(token, signing_key.key, algorithms=algorithms)
    except Exception:
        unverified = jwt.decode(token, options={"verify_signature": False})
        raise
'''
PYPROJECT = '"PyJWT[crypto]==2.13.0; python_version >= 3.14"'

SOURCES = {
    "plugins/cron_providers/chronos/verify.py": CHRONOS,
    "plugins/dashboard_auth/_shared.py": SHARED,
    "plugins/dashboard_auth/nous/__init__.py": NOUS,
    "plugins/dashboard_auth/self_hosted/__init__.py": SELF_HOSTED,
    "pyproject.toml": PYPROJECT,
}


class CriticalJwtAuditTest(unittest.TestCase):
    def test_safe_asymmetric_only_calls_return_p0_not_release_go(self):
        result = audit.inspect_sources(SOURCES)
        self.assertEqual(result["status"], "P0_REVIEW_REQUIRED")
        self.assertEqual(result["pyjwt_dependency_version"], "2.13.0")
        self.assertEqual(result["pyjwt_fixed_version"], "2.14.0")
        self.assertEqual(set(result["reviewed_jwt_paths"]), {"chronos", "nous", "self_hosted"})
        for route in result["reviewed_jwt_paths"].values():
            self.assertFalse(route["mixed_hmac_asymmetric"])
        for field in (
            "jwt_all_callsites_exhaustively_reviewed",
            "critical_cve_applicability_confirmed",
            "source_to_image_provenance_verified",
            "image_contains_same_git_source_verified",
            "resident_agent_allowed",
        ):
            self.assertFalse(result[field], field)

    def test_mixed_hmac_asymmetric_is_detected_not_suppressed(self):
        sources = {**SOURCES, "plugins/dashboard_auth/nous/__init__.py":
                   NOUS.replace('["RS256"]', '["RS256", "HS256"]')}
        result = audit.inspect_sources(sources)
        self.assertTrue(result["reviewed_jwt_paths"]["nous"]["mixed_hmac_asymmetric"])
        self.assertTrue(result["pyjwt_risky_configuration_observed_in_reviewed_paths"])
        self.assertFalse(result["resident_agent_allowed"])

    def test_empty_unknown_or_dynamic_algorithms_fail_closed(self):
        for original, replacement in (
            ('["RS256"]', '["RS256", "NONSTANDARD"]'),
            ('["RS256"]', "config_algorithms"),
            ('["RS256"]', "[]"),
            ('["RS256"]', '["RS256", "RS256"]'),
        ):
            with self.subTest(replacement=replacement):
                sources = {**SOURCES, "plugins/dashboard_auth/nous/__init__.py":
                           NOUS.replace(original, replacement)}
                with self.assertRaises(audit.AuditDenied):
                    audit.inspect_sources(sources)

    def test_missing_or_extra_source_rejected(self):
        for sources in (
            {k: v for k, v in SOURCES.items() if k != "pyproject.toml"},
            {**SOURCES, "extra.py": "pass"},
        ):
            with self.assertRaisesRegex(audit.AuditDenied, "incomplete_source_snapshot"):
                audit.inspect_sources(sources)

    def test_source_structure_and_jwks_verification_required(self):
        cases = (
            ("plugins/cron_providers/chronos/verify.py",
             CHRONOS.replace("get_signing_key_from_jwt", "get_random_key")),
            ("plugins/dashboard_auth/_shared.py",
             SHARED.replace("get_signing_key_from_jwt", "get_unsigned_key")),
            ("plugins/dashboard_auth/_shared.py",
             SHARED.replace("algorithms=algorithms", "algorithms=['HS256']")),
            ("plugins/dashboard_auth/self_hosted/__init__.py",
             SELF_HOSTED.replace("list(_ALLOWED_ID_TOKEN_ALGS)", "list(config)")),
            ("pyproject.toml", PYPROJECT.replace("2.13.0", "2.12.0")),
        )
        for name, val in cases:
            with self.subTest(path=name):
                with self.assertRaises(audit.AuditDenied):
                    audit.inspect_sources({**SOURCES, name: val})

    def test_git_blob_sha_exact_roundtrip(self):
        raw = b"hello\n"
        self.assertEqual(audit.git_blob_id(raw),
                         __import__("hashlib").sha1(b"blob 6\0hello\n").hexdigest())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.py"
            path.write_bytes(raw)
            self.assertEqual(audit._read_exact(Path(folder), "test.py",
                             audit.git_blob_id(raw)), "hello\n")
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(audit.AuditDenied, "upstream_blob_mismatch"):
                audit._read_exact(Path(folder), "test.py", audit.git_blob_id(raw))

    def test_empty_broken_or_symlink_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaises(audit.AuditDenied):
                audit._read_exact(root, "missing.py", "a" * 40)
            regular = root / "inside.py"
            regular.write_text("x", encoding="utf-8")
            alias = root / "alias.py"
            try:
                alias.symlink_to(regular)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaisesRegex(audit.AuditDenied, "symlink_denied"):
                    audit._read_exact(root, "alias.py", audit.git_blob_id(b"x"))
            regular.write_bytes(b"X" * (audit.MAX_BYTES + 1))
            with self.assertRaisesRegex(audit.AuditDenied, "missing_or_oversized_source"):
                audit._read_exact(root, "inside.py", audit.git_blob_id(b"x"))

    def test_default_dry_run_and_explicit_missing_evidence(self):
        with patch("sys.stdout", new_callable=io.StringIO) as buf:
            self.assertEqual(audit.main([]), 0)
            self.assertEqual(json.loads(buf.getvalue())["status"], "NOT_EXECUTED")
        with patch("sys.stdout", new_callable=io.StringIO) as buf:
            self.assertEqual(audit.main(["--execute"]), 2)
            self.assertEqual(json.loads(buf.getvalue())["status"], "INCONCLUSIVE")
        with patch("sys.stdout", new_callable=io.StringIO) as buf:
            self.assertEqual(audit.main(["--execute", "--source-dir", "/missing"]), 2)
            report = json.loads(buf.getvalue())
            self.assertFalse(report["resident_agent_allowed"])
            self.assertNotIn("/missing", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
