"""Hermes #346: synthetic CA trust overlap, no real owner credentials."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest

from scripts.h346_client_trust_preflight import TrustError, check, _certificates


def openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], capture_output=True, check=True, timeout=15)


class ClientTrustPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.tmp.name)
        cls.new_ca = cls.base / "ca.pem"
        cls.ca_key = cls.base / "ca.key"
        cls.legacy = cls.base / "pilot.pem"
        cls.legacy_key = cls.base / "pilot.key"
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "60", "-keyout", str(cls.ca_key),
                "-out", str(cls.new_ca), "-subj", "/CN=Synthetic Offline CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "14", "-keyout", str(cls.legacy_key),
                "-out", str(cls.legacy), "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost",
                "-addext", "extendedKeyUsage=serverAuth")
        cls.primary, cls.primary_key = cls.signed_leaf("primary")
        cls.fallback, cls.fallback_key = cls.signed_leaf("fallback")
        cls.no_eku, _ = cls.signed_leaf("noeku", include_eku=False)
        cls.bad_host, _ = cls.signed_leaf("wronghost", hostname="wrong.example")
        cls.trust_pin = hashlib.sha256(
            ssl.PEM_cert_to_DER_cert(cls.new_ca.read_text())).hexdigest()

    @classmethod
    def signed_leaf(cls, name: str, *, include_eku: bool = True, hostname: str = "localhost"):
        key = cls.base / f"{name}.key"
        csr = cls.base / f"{name}.csr"
        cert = cls.base / f"{name}.pem"
        ext = cls.base / f"{name}.ext"
        openssl("req", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(csr),
                "-subj", f"/CN={hostname}")
        ext.write_text(
            f"subjectAltName=DNS:{hostname}\n"
            + ("extendedKeyUsage=serverAuth\n" if include_eku else "")
            + "basicConstraints=critical,CA:FALSE\n"
            + "keyUsage=critical,digitalSignature,keyEncipherment\n")
        openssl("x509", "-req", "-in", str(csr), "-CA", str(cls.new_ca),
                "-CAkey", str(cls.ca_key), "-CAcreateserial", "-out",
                str(cert), "-days", "30", "-extfile", str(ext))
        return cert, key

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.tmp_case = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_case.cleanup)
        self.config_path = Path(self.tmp_case.name) / "linux-vps.json"
        self.config = {
            "schema": 1,
            "device_id": "linux-vps",
            "endpoint": "wss://localhost:38179",
            "token": "SYNTHETIC_TOKEN_ONLY_" + "x" * 50,
            "server_ca_pem": self.legacy.read_text(encoding="ascii"),
        }
        self.save()

    def save(self):
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        os.chmod(self.config_path, 0o600)

    def preview(self, **kw):
        args = {
            "expected_device": "linux-vps",
            "expected_ca_sha256": self.trust_pin,
        }
        args.update(kw)
        return check(self.config_path, self.new_ca, self.primary,
                     self.fallback, **args)

    def test_valid_dual_trust_preflight_preserves_private_config(self):
        content = self.config_path.read_bytes()
        result = self.preview()
        self.assertEqual(result.device, "linux-vps")
        self.assertEqual(result.existing_ca_count, 1)
        self.assertFalse(result.already_trusted)
        self.assertLess(result.overlap_bytes, 6144)
        self.assertEqual(self.config_path.read_bytes(), content)

    def test_repeat_preflight_is_idempotent_when_public_ca_present(self):
        self.config["server_ca_pem"] += self.new_ca.read_text(encoding="ascii")
        self.save()
        first = self.preview()
        second = self.preview()
        self.assertTrue(first.already_trusted)
        self.assertEqual(first.overlap_bytes, second.overlap_bytes)
        self.assertEqual(self.config["token"], json.loads(
            self.config_path.read_text())["token"])

    def test_unapproved_ca_sha256_pin_fails_closed(self):
        with self.assertRaisesRegex(TrustError, "OFFLINE_CA_FINGERPRINT_MISMATCH"):
            self.preview(expected_ca_sha256="f" * 64)

    def test_missing_ca_fingerprint_fails_closed(self):
        with self.assertRaisesRegex(TrustError, "CA_PIN_REQUIRED"):
            self.preview(expected_ca_sha256="")

    def test_same_primary_and_fallback_rejected(self):
        with self.assertRaisesRegex(TrustError, "FALLBACK_CERTIFICATE_NOT_INDEPENDENT"):
            check(self.config_path, self.new_ca, self.primary, self.primary,
                  expected_device="linux-vps", expected_ca_sha256=self.trust_pin)

    def test_missing_server_auth_eku_rejected(self):
        with self.assertRaisesRegex(TrustError, "SERVER_AUTH_EKU_REQUIRED"):
            check(self.config_path, self.new_ca, self.no_eku, self.fallback,
                  expected_device="linux-vps", expected_ca_sha256=self.trust_pin)

    def test_wrong_san_rejected(self):
        with self.assertRaisesRegex(TrustError, "PUBLIC_CERTIFICATE_VERIFICATION_FAILED"):
            check(self.config_path, self.new_ca, self.bad_host, self.fallback,
                  expected_device="linux-vps", expected_ca_sha256=self.trust_pin)

    def test_wrong_device_id_rejected(self):
        with self.assertRaisesRegex(TrustError, "DEVICE_ID_MISMATCH"):
            self.preview(expected_device="windows-pc")

    def test_symlinked_ca_rejected(self):
        link = Path(self.tmp_case.name) / "ca-link.pem"
        link.symlink_to(self.new_ca)
        with self.assertRaisesRegex(TrustError, "UNTRUSTED_INPUT_FILE"):
            check(self.config_path, link, self.primary, self.fallback,
                  expected_device="linux-vps", expected_ca_sha256=self.trust_pin)

    def test_symlinked_config_rejected(self):
        link = Path(self.tmp_case.name) / "config-link.json"
        link.symlink_to(self.config_path)
        with self.assertRaisesRegex(TrustError, "UNTRUSTED_INPUT_FILE"):
            check(link, self.new_ca, self.primary, self.fallback,
                  expected_device="linux-vps", expected_ca_sha256=self.trust_pin)

    def test_private_config_world_access_rejected(self):
        os.chmod(self.config_path, 0o644)
        with self.assertRaisesRegex(TrustError, "CLIENT_CONFIG_PERMISSIONS_UNSAFE"):
            self.preview()

    def test_corrupt_existing_trust_pem_rejected_without_writes(self):
        self.config["server_ca_pem"] = (
            "-----BEGIN CERTIFICATE-----\nINVALID@@@@\n"
            "-----END CERTIFICATE-----\n")
        self.save()
        baseline = self.config_path.read_bytes()
        with self.assertRaises(TrustError):
            self.preview()
        self.assertEqual(self.config_path.read_bytes(), baseline)

    def test_config_hardlink_rejected(self):
        link = Path(self.tmp_case.name) / "other.json"
        os.link(self.config_path, link)
        with self.assertRaisesRegex(TrustError, "UNTRUSTED_INPUT_FILE"):
            self.preview()

    def test_overflowing_trust_bundle_rejected(self):
        self.config["server_ca_pem"] = self.legacy.read_text() * 6
        self.save()
        with self.assertRaises(TrustError):
            self.preview()

    def test_untrusted_primary_ca_rejected(self):
        other = Path(self.tmp_case.name) / "old-ca.pem"
        other.write_bytes(self.legacy.read_bytes())
        fingerprint = hashlib.sha256(
            ssl.PEM_cert_to_DER_cert(other.read_text())).hexdigest()
        with self.assertRaisesRegex(TrustError, "CA_BASIC_CONSTRAINTS_REQUIRED"):
            check(self.config_path, other, self.primary, self.fallback,
                  expected_device="linux-vps", expected_ca_sha256=fingerprint)

    def test_expired_legacy_trust_is_preserved_but_does_not_block_new_ca(self):
        # In production the original pilot is already expired. Its trust
        # anchor remains parseable, but cannot authenticate an expired server.
        expired = Path(self.tmp_case.name) / "expired-pilot.pem"
        key = Path(self.tmp_case.name) / "expired-pilot.key"
        csr = Path(self.tmp_case.name) / "expired-pilot.csr"
        old_ca = Path(self.tmp_case.name) / "old-pilot-ca.pem"
        config = Path(self.tmp_case.name) / "old-pilot-ca.cnf"
        db = Path(self.tmp_case.name) / "old-ca-index"
        db.touch()
        (Path(self.tmp_case.name) / "old-ca-serial").write_text("01\n")
        (Path(self.tmp_case.name) / "old-ca-certs").mkdir()
        config.write_text(
            "[ca]\ndefault_ca=local\n[local]\n"
            "database=" + str(db) + "\n"
            "new_certs_dir=" + str(Path(self.tmp_case.name) / "old-ca-certs") + "\n"
            "serial=" + str(Path(self.tmp_case.name) / "old-ca-serial") + "\n"
            "default_md=sha256\npolicy=identity\n"
            "x509_extensions=server\n[identity]\ncommonName=supplied\n"
            "[server]\nsubjectAltName=DNS:localhost\n"
            "basicConstraints=critical,CA:FALSE\n"
            "extendedKeyUsage=serverAuth\n")
        openssl("req", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(csr), "-subj", "/CN=localhost")
        openssl("req", "-x509", "-key", str(key), "-days", "30",
                "-out", str(old_ca), "-subj", "/CN=localhost")
        openssl("ca", "-batch", "-config", str(config),
                "-selfsign", "-cert", str(old_ca), "-keyfile", str(key),
                "-in", str(csr), "-out", str(expired), "-notext",
                "-startdate", "261001000000Z", "-enddate", "261002000000Z")
        self.config["server_ca_pem"] = expired.read_text()
        self.save()
        result = self.preview()
        self.assertEqual(result.existing_ca_count, 1)
        self.assertFalse(result.already_trusted)
        self.assertLess(result.overlap_bytes, 6144)

    def test_fallback_not_signed_by_approved_ca_is_rejected(self):
        with self.assertRaisesRegex(TrustError, "PUBLIC_CERTIFICATE_VERIFICATION_FAILED"):
            check(self.config_path, self.new_ca, self.primary, self.legacy,
                  expected_device="linux-vps", expected_ca_sha256=self.trust_pin)

    def test_existing_windows_id_and_ssh_port_are_checked(self):
        self.config["device_id"] = "windows-pc"
        self.config["endpoint"] = "wss://localhost:38178"
        self.save()
        result = self.preview(expected_device="windows-pc")
        self.assertEqual(result.device, "windows-pc")

    def test_tls_handshake_with_legacy_and_new_ca_overlap(self):
        def connect_with(trust):
            ctx = ssl.create_default_context(cadata=trust)
            ctx.check_hostname = True
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(str(self.primary), str(self.primary_key))
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            server.settimeout(5)
            port = server.getsockname()[1]

            def serve():
                try:
                    con, _ = server.accept()
                    with con:
                        try:
                            with server_ctx.wrap_socket(con, server_side=True):
                                pass
                        except (OSError, ssl.SSLError):
                            pass
                finally:
                    server.close()

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
                    with ctx.wrap_socket(conn, server_hostname="localhost") as tls:
                        return tls.version()
            finally:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())

        with self.assertRaises(ssl.SSLError):
            connect_with(self.legacy.read_text())
        version = connect_with(self.legacy.read_text() + self.new_ca.read_text())
        self.assertIn(version, ("TLSv1.2", "TLSv1.3"))


if __name__ == "__main__":
    unittest.main()
