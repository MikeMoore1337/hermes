"""Synthetic offline private-CA candidate tests; no owner identity or network."""
from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.h15_presence_tls_preflight import PreflightError, check


def openssl(*parts: str) -> None:
    subprocess.run(["openssl", *parts], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=8)


class PresenceTlsPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        root = Path(self._dir.name)
        self.ca, self.ca_key = root / "ca.pem", root / "ca.key"
        self.leaf, self.key = root / "leaf.pem", root / "leaf.key"
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
                "-keyout", str(self.ca_key), "-out", str(self.ca),
                "-subj", "/CN=Synthetic H15 Private CA", "-addext", "basicConstraints=critical,CA:true",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        csr = root / "leaf.csr"
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(self.key),
                "-out", str(csr), "-subj", "/CN=localhost")
        ext = root / "leaf.ext"
        ext.write_text("subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:false\n"
                       "extendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n")
        openssl("x509", "-req", "-in", str(csr), "-CA", str(self.ca), "-CAkey",
                str(self.ca_key), "-CAcreateserial", "-out", str(self.leaf),
                "-days", "4", "-extfile", str(ext))
        os.chmod(self.key, 0o600)

    def test_valid_leaf_bound_to_approved_ca_and_localhost(self) -> None:
        self.assertEqual(check(self.ca, self.leaf, self.key), "CANDIDATE_CERTIFICATE_PREFLIGHT=PASS")

    def test_wrong_hostname_is_rejected(self) -> None:
        with self.assertRaisesRegex(PreflightError, "VERIFICATION_FAILED"):
            check(self.ca, self.leaf, self.key, hostname="other.example")

    def test_wrong_ca_is_rejected(self) -> None:
        with self.assertRaisesRegex(PreflightError, "VERIFICATION_FAILED"):
            check(self.leaf, self.ca, self.key)

    def test_cn_fallback_without_san_is_rejected(self) -> None:
        root = self.leaf.parent
        csr = root / "leaf.csr"
        bare = root / "cn-only.pem"
        openssl("x509", "-req", "-in", str(csr), "-CA", str(self.ca), "-CAkey",
                str(self.ca_key), "-CAcreateserial", "-out", str(bare), "-days", "4")
        with self.assertRaisesRegex(PreflightError, "SAN_MISSING"):
            check(self.ca, bare, self.key)

    def test_serverauth_eku_missing_is_rejected(self) -> None:
        # OpenSSL verify -purpose sslserver accepts leaf certificates with
        # absent EKU. Require an explicit serverAuth OID in addition.
        root = self.leaf.parent
        extension = root / "no-serverauth.ext"
        extension.write_text("subjectAltName=DNS:localhost\\n"
                             "basicConstraints=critical,CA:false\\n")
        leaf = root / "no-serverauth.pem"
        openssl("x509", "-req", "-in", str(root / "leaf.csr"),
                "-CA", str(self.ca), "-CAkey", str(self.ca_key),
                "-CAcreateserial", "-out", str(leaf), "-days", "4",
                "-extfile", str(extension))
        with self.assertRaisesRegex(PreflightError, "SERVER_AUTH_EKU_REQUIRED"):
            check(self.ca, leaf, self.key)

    def test_different_private_key_is_rejected(self) -> None:
        other = self.key.parent / "other.key"
        openssl("genpkey", "-algorithm", "RSA", "-out", str(other),
                "-pkeyopt", "rsa_keygen_bits:2048")
        os.chmod(other, 0o600)
        with self.assertRaisesRegex(PreflightError, "KEY_MISMATCH"):
            check(self.ca, self.leaf, other)

    def test_private_key_group_or_world_permission_is_rejected(self) -> None:
        os.chmod(self.key, 0o644)
        with self.assertRaisesRegex(PreflightError, "PERMISSIONS_UNSAFE"):
            check(self.ca, self.leaf, self.key)

    def test_symlink_rejected(self) -> None:
        linked = self.leaf.parent / "link.pem"
        linked.symlink_to(self.leaf)
        with self.assertRaisesRegex(PreflightError, "NONREGULAR"):
            check(self.ca, linked, self.key)

    def test_cannot_accept_leaf_near_expiry(self) -> None:
        with self.assertRaisesRegex(PreflightError, "EXPIRING_TOO_SOON"):
            check(self.ca, self.leaf, self.key, min_valid_days=10)

    def test_zero_minimum_does_not_override_expired_leaf(self) -> None:
        later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=6)
        with self.assertRaisesRegex(PreflightError, "VERIFICATION_FAILED|EXPIRING_TOO_SOON"):
            check(self.ca, self.leaf, self.key, now=later)


if __name__ == "__main__":
    unittest.main()
