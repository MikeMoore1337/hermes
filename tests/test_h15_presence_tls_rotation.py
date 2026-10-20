"""Isolated OpenSSL/TLS regression tests for staged WSS leaf rotation (#346)."""
from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest

from scripts.h15_presence_tls_preflight import check, PreflightError
from scripts.h15_presence_tls_rotation import (
    RotationError, RotationPaths, _active_name, _exclusive, _file,
    _pending_name, _probe, _switch, _write, activate, auto, recover, stage,
)


def openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], timeout=12, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class RotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        p = Path(cls.keys.name)
        cls.ca, cls.ca_key = p / "ca.pem", p / "ca.key"
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "50",
                "-keyout", str(cls.ca_key), "-out", str(cls.ca),
                "-subj", "/CN=Synthetic isolated CA", "-addext",
                "basicConstraints=critical,CA:true", "-addext",
                "keyUsage=critical,keyCertSign,cRLSign")
        cls.certificates = []
        for idx in range(3):
            key, cert, csr, ext = [p / f"{idx}.{suffix}" for suffix in ("key", "pem", "csr", "ext")]
            openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                    "-out", str(csr), "-subj", "/CN=localhost")
            ext.write_text("subjectAltName=DNS:localhost\n"
                           "basicConstraints=critical,CA:false\n"
                           "extendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n")
            openssl("x509", "-req", "-in", str(csr), "-CA", str(cls.ca),
                    "-CAkey", str(cls.ca_key), "-CAcreateserial", "-out", str(cert),
                    "-days", "15" if idx == 0 else "35", "-extfile", str(ext))
            os.chmod(key, 0o600)
            cls.certificates.append((cert, key))

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name) / "tls"
        root.mkdir(mode=0o750)
        (root / "generations").mkdir(mode=0o750)
        (root / "ca-public.pem").write_bytes(self.ca.read_bytes())
        os.chmod(root / "ca-public.pem", 0o640)
        self.paths = RotationPaths(root, owner_uid=os.getuid())
        self.gid = os.getgid()

    def staged(self, idx=0):
        leaf, key = self.certificates[idx]
        return stage(self.paths, leaf=leaf, key=key, gid=self.gid)

    def initial(self):
        name = self.staged()
        _switch(self.paths, name)
        (self.paths.root / "pending").unlink()
        return name

    def test_stage_bootstrap_identity_and_permissions(self):
        old = self.initial()
        self.assertEqual(_active_name(self.paths, gid=self.gid), old)
        self.assertTrue((self.paths.active / "cert.pem").is_file())
        self.assertEqual((self.paths.generations / old / "key.pem").stat().st_mode & 0o777, 0o640)

    def test_stage_does_not_change_active(self):
        old = self.initial()
        new = self.staged(1)
        self.assertNotEqual(old, new)
        self.assertEqual(_pending_name(self.paths, gid=self.gid), new)
        self.assertEqual(_active_name(self.paths, gid=self.gid), old)

    def test_second_pending_is_rejected(self):
        self.initial()
        self.staged(1)
        with self.assertRaisesRegex(RotationError, "PENDING_CANDIDATE_ALREADY_EXISTS"):
            self.staged(2)

    def test_successful_activation_probes_exact_leaf(self):
        self.initial()
        new = self.staged(1)
        probes = []
        def probe(**kwargs):
            probes.append(kwargs["leaf"])
            return True
        self.assertEqual(activate(self.paths, new, gid=self.gid,
                                  restart=lambda unit: True, probe=probe), "ROTATION=PASS")
        self.assertEqual(probes, [self.paths.generations / new / "cert.pem"])
        self.assertIsNone(_pending_name(self.paths, gid=self.gid))
        self.assertFalse((self.paths.root / ".rollback-target").exists())

    def test_failed_probe_restores_previous_certificate(self):
        old = self.initial()
        new = self.staged(1)
        probes = []
        def probe(**kwargs):
            probes.append(_active_name(self.paths, gid=self.gid))
            return len(probes) == 2
        with self.assertRaisesRegex(RotationError, "ROTATION_ROLLED_BACK"):
            activate(self.paths, new, gid=self.gid, restart=lambda unit: True, probe=probe)
        self.assertEqual(probes, [new, old])
        self.assertEqual(_active_name(self.paths, gid=self.gid), old)
        self.assertIsNone(_pending_name(self.paths, gid=self.gid))

    def test_unverified_rollback_is_a_failure(self):
        old = self.initial()
        new = self.staged(1)
        with self.assertRaisesRegex(RotationError, "ROLLBACK_HEALTH_UNVERIFIED"):
            activate(self.paths, new, gid=self.gid, restart=lambda unit: False)
        self.assertEqual(_active_name(self.paths, gid=self.gid), old)
        self.assertTrue((self.paths.root / ".rollback-target").exists())

    def test_initial_migration_never_restarts_automatically(self):
        new = self.staged()
        calls = []
        with self.assertRaisesRegex(RotationError, "INITIAL_MIGRATION_REQUIRED"):
            activate(self.paths, new, gid=self.gid, restart=lambda u: calls.append(u))
        self.assertEqual(calls, [])

    def test_early_auto_is_noop(self):
        self.initial()
        calls = []
        self.assertEqual(auto(self.paths, gid=self.gid, restart=lambda u: calls.append(u)),
                         "ROTATION=NOT_DUE")
        self.assertEqual(calls, [])

    def test_auto_near_expiry_rotates_pending(self):
        self.initial()
        new = self.staged(1)
        later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=13)
        self.assertEqual(auto(self.paths, gid=self.gid, now=later,
                              restart=lambda unit: True, probe=lambda **kw: True),
                         "ROTATION=PASS")
        self.assertEqual(_active_name(self.paths, gid=self.gid), new)

    def test_auto_requires_pending_candidate(self):
        self.initial()
        later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=13)
        with self.assertRaisesRegex(RotationError, "NEED_STAGED_PENDING_CANDIDATE"):
            auto(self.paths, gid=self.gid, now=later)

    def test_multiple_prior_generations_do_not_block_later_cycle(self):
        self.initial()
        one = self.staged(1)
        activate(self.paths, one, gid=self.gid, restart=lambda u: True,
                 probe=lambda **kw: True)
        two = self.staged(2)
        self.assertEqual(_pending_name(self.paths, gid=self.gid), two)

    def test_crash_marker_recovers_previous_cert(self):
        old = self.initial()
        new = self.staged(1)
        _write(self.paths.root / ".rollback-target", old.encode("ascii"),
               uid=self.paths.owner_uid, gid=self.gid, mode=0o600)
        _switch(self.paths, new)
        self.assertEqual(recover(self.paths, gid=self.gid, restart=lambda u: True,
                                 probe=lambda **kw: True), "ROTATION=RECOVERED")
        self.assertEqual(_active_name(self.paths, gid=self.gid), old)
        self.assertFalse((self.paths.root / ".rollback-target").exists())

    def test_auto_recovers_crash_before_trying_new_candidate(self):
        old = self.initial()
        new = self.staged(1)
        _write(self.paths.root / ".rollback-target", old.encode("ascii"),
               uid=self.paths.owner_uid, gid=self.gid, mode=0o600)
        _switch(self.paths, new)
        calls = []
        self.assertEqual(auto(self.paths, gid=self.gid,
                              restart=lambda u: calls.append(u) or True,
                              probe=lambda **kw: True), "ROTATION=RECOVERED")
        self.assertEqual(len(calls), 1)
        self.assertEqual(_active_name(self.paths, gid=self.gid), old)

    def test_concurrent_rotation_lock_is_rejected(self):
        with _exclusive(self.paths):
            with self.assertRaisesRegex(RotationError, "ROTATION_ALREADY_RUNNING"):
                with _exclusive(self.paths):
                    pass

    def test_wrong_ca_cannot_stage(self):
        (self.paths.root / "ca-public.pem").write_bytes(self.certificates[0][0].read_bytes())
        with self.assertRaises(PreflightError):
            self.staged()

    def test_mismatched_private_key_cannot_stage(self):
        leaf, _ = self.certificates[0]
        key = self.certificates[1][1]
        with self.assertRaisesRegex(PreflightError, "KEY_MISMATCH"):
            stage(self.paths, leaf=leaf, key=key, gid=self.gid)

    def test_no_san_cannot_stage(self):
        bare = Path(self.tmp.name) / "bare.pem"
        csr = Path(self.keys.name) / "0.csr"
        openssl("x509", "-req", "-in", str(csr), "-CA", str(self.ca),
                "-CAkey", str(self.ca_key), "-CAcreateserial",
                "-out", str(bare), "-days", "15")
        with self.assertRaisesRegex(PreflightError, "SAN_MISSING"):
            stage(self.paths, leaf=bare, key=self.certificates[0][1], gid=self.gid)

    def test_symlinked_ca_is_rejected(self):
        ca = self.paths.ca
        ca.unlink()
        ca.symlink_to(self.ca)
        with self.assertRaises(RotationError):
            self.staged()

    def test_mutable_root_is_rejected(self):
        os.chmod(self.paths.root, 0o770)
        with self.assertRaisesRegex(RotationError, "WRITABLE_BY_OTHERS"):
            self.staged()

    def test_untrusted_active_pointer_is_rejected(self):
        self.initial()
        self.paths.active.unlink()
        self.paths.active.symlink_to("/tmp/untrusted")
        with self.assertRaisesRegex(RotationError, "ACTIVE_POINTER_UNTRUSTED"):
            _active_name(self.paths, gid=self.gid)

    def test_changed_staged_leaf_is_rejected_before_restart(self):
        self.initial()
        name = self.staged(1)
        with open(self.paths.generations / name / "cert.pem", "ab") as f:
            f.write(b"\n")
        calls = []
        with self.assertRaisesRegex(RotationError, "GENERATION_CONTENT_MISMATCH"):
            activate(self.paths, name, gid=self.gid, restart=lambda u: calls.append(u))
        self.assertEqual(calls, [])

    def test_symlinked_staged_key_is_rejected(self):
        self.initial()
        name = self.staged(1)
        key = self.paths.generations / name / "key.pem"
        key.unlink()
        key.symlink_to(self.certificates[0][1])
        with self.assertRaisesRegex(RotationError, "GENERATION_FILE_PERMISSIONS"):
            activate(self.paths, name, gid=self.gid)

    def test_future_attime_rejects_expired_cert(self):
        leaf, key = self.certificates[0]
        later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=20)
        with self.assertRaises(PreflightError):
            check(self.ca, leaf, key, now=later)

    def test_real_loopback_tls_probe_checks_actual_der_not_only_ca(self):
        cert, key = self.certificates[0]
        wrong_cert, _ = self.certificates[1]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(key))
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(4)
        server.settimeout(5)

        def serve():
            try:
                for _ in range(2):
                    conn, _ = server.accept()
                    try:
                        with ctx.wrap_socket(conn, server_side=True):
                            pass
                    except (OSError, ssl.SSLError):
                        pass
            finally:
                server.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        port = server.getsockname()[1]
        self.assertTrue(_probe(ca=self.ca, leaf=cert, port=port))
        self.assertFalse(_probe(ca=self.ca, leaf=wrong_cert, port=port))
        thread.join(timeout=6)
        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
