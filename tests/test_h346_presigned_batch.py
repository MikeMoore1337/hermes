"""Isolated root-only H346 presigned certificate batch selection tests."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import h346_presigned_batch as batch
from scripts.h15_presence_tls_rotation import (
    RotationPaths, _active_name, _generation_name, _switch, stage,
)


def openssl(*args: str) -> bytes:
    p = subprocess.run(["openssl", *args], capture_output=True, timeout=15, check=True)
    return p.stdout


def der_digest(path: Path) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(path.read_text())).hexdigest()


def dates(path: Path) -> tuple[str, str]:
    output = openssl("x509", "-in", str(path), "-noout", "-dates").decode()
    lines = output.splitlines()
    start = dt.datetime.strptime(lines[0][10:], "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=dt.timezone.utc)
    end = dt.datetime.strptime(lines[1][9:], "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=dt.timezone.utc)
    return start.isoformat(), end.isoformat()


class PresignedBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.material = tempfile.TemporaryDirectory()
        base = Path(cls.material.name)
        cls.ca = base / "ca.pem"
        ca_key = base / "ca.key"
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "90", "-keyout", str(ca_key), "-out", str(cls.ca),
                "-subj", "/CN=Disposable CI CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        cls.leaves = []
        for idx, days in enumerate((15, 30)):
            key = base / f"leaf-{idx}.key"
            csr = base / f"leaf-{idx}.csr"
            leaf = base / f"leaf-{idx}.pem"
            ext = base / f"leaf-{idx}.ext"
            openssl("req", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(csr),
                    "-subj", "/CN=localhost")
            ext.write_text("subjectAltName=DNS:localhost\n"
                           "extendedKeyUsage=serverAuth\n"
                           "basicConstraints=critical,CA:FALSE\n"
                           "keyUsage=critical,digitalSignature,keyEncipherment\n")
            openssl("x509", "-req", "-in", str(csr),
                    "-CA", str(cls.ca), "-CAkey", str(ca_key), "-CAcreateserial",
                    "-out", str(leaf), "-days", str(days), "-extfile", str(ext))
            os.chmod(key, 0o600)
            cls.leaves.append((leaf, key))
        cls.ca_pin = der_digest(cls.ca)

    @classmethod
    def tearDownClass(cls):
        cls.material.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "tls"
        self.root.mkdir(mode=0o750)
        self.root.chmod(0o750)
        (self.root / "generations").mkdir(mode=0o750)
        (self.root / "generations").chmod(0o750)
        (self.root / "ca-public.pem").write_bytes(self.ca.read_bytes())
        (self.root / "ca-public.pem").chmod(0o640)
        self.paths = RotationPaths(self.root, owner_uid=os.getuid())
        self.gid = os.getgid()
        primary, primary_key = self.leaves[0]
        self.primary_name = stage(
            self.paths, leaf=primary, key=primary_key, gid=self.gid)
        _switch(self.paths, self.primary_name)
        (self.root / "pending").unlink()
        self.archive = self.root / "presigned-batch"
        self.archive.mkdir(mode=0o700)
        self.archive.chmod(0o700)
        future, future_key = self.leaves[1]
        shutil.copyfile(future, self.archive / "future-01.pem")
        shutil.copyfile(future_key, self.archive / "future-01.key")
        (self.archive / "future-01.pem").chmod(0o600)
        (self.archive / "future-01.key").chmod(0o600)
        manifest = {
            "schema": "hermes-h346-presigned-batch-v1",
            "ca_der_sha256": self.ca_pin,
            "slots": [
                {"slot": slot, "der_sha256": der_digest(cert),
                 "not_before": dates(cert)[0], "not_after": dates(cert)[1]}
                for slot, (cert, _) in zip(
                    ("primary", "future-01"), self.leaves)
            ],
        }
        (self.archive / "manifest.json").write_text(json.dumps(manifest))
        (self.archive / "manifest.json").chmod(0o600)
        p1 = patch.object(batch, "APPROVED_CA_PIN", self.ca_pin)
        p2 = patch.object(batch, "EXPECTED_SLOTS", ("primary", "future-01"))
        p1.start()
        p2.start()
        self.addCleanup(p2.stop)
        self.addCleanup(p1.stop)
        self.due = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=13)

    def run_batch(self, when=None, *, dry=False):
        return batch.process(
            self.paths, gid=self.gid, now=when or self.due, dry_run=dry,
            restart=lambda unit: True,
            probe=lambda **kwargs: True)

    def test_not_due_does_not_stage_or_restart(self):
        self.assertEqual(
            self.run_batch(dt.datetime.now(dt.timezone.utc)),
            "PRESIGNED_BATCH=NOT_DUE")
        self.assertFalse((self.root / "pending").exists())
        self.assertEqual(_active_name(self.paths, gid=self.gid), self.primary_name)

    def test_dry_run_does_not_change_approved_active_leaf(self):
        self.assertEqual(self.run_batch(dry=True),
                         "PRESIGNED_BATCH=WOULD_STAGE_future-01")
        self.assertFalse((self.root / "pending").exists())

    def test_due_stages_and_rotates_only_next_owner_signed_leaf(self):
        self.assertEqual(self.run_batch(), "ROTATION=PASS")
        future_cert, _ = self.leaves[1]
        expected = _generation_name(future_cert.read_bytes())
        self.assertEqual(_active_name(self.paths, gid=self.gid), expected)
        self.assertFalse((self.root / "pending").exists())
        self.assertFalse((self.root / ".rollback-target").exists())

    def test_tampered_manifest_pin_is_rejected(self):
        mf = self.archive / "manifest.json"
        doc = json.loads(mf.read_text())
        doc["ca_der_sha256"] = "f" * 64
        mf.write_text(json.dumps(doc))
        with self.assertRaisesRegex(batch.BatchError, "CA_PIN_MISMATCH"):
            self.run_batch(dry=True)

    def test_untrusted_manifest_symlink_is_rejected(self):
        mf = self.archive / "manifest.json"
        dst = self.archive / "saved.json"
        mf.rename(dst)
        mf.symlink_to(dst.name)
        with self.assertRaisesRegex(batch.BatchError, "BATCH_FILE_UNTRUSTED"):
            self.run_batch(dry=True)

    def test_untrusted_future_private_key_is_rejected(self):
        (self.archive / "future-01.key").chmod(0o644)
        with self.assertRaisesRegex(batch.BatchError, "BATCH_FILE_UNTRUSTED"):
            self.run_batch()

    def test_tampered_signed_leaf_rejected_before_stage(self):
        (self.archive / "future-01.pem").write_text("untrusted leaf")
        with self.assertRaises(batch.BatchError):
            self.run_batch()

    def test_quarantined_failed_generation_is_not_retried(self):
        leaf, key = self.leaves[1]
        name = stage(self.paths, leaf=leaf, key=key, gid=self.gid)
        (self.root / "pending").unlink()
        self.assertTrue((self.paths.generations / name).is_dir())
        with self.assertRaisesRegex(
                batch.BatchError, "FAILED_CANDIDATE_REQUIRES_OWNER_REVIEW"):
            self.run_batch()

    def test_exhausted_last_leaf_requires_new_owner_authorization(self):
        self.assertEqual(self.run_batch(), "ROTATION=PASS")
        near_future_expiry = (
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=28))
        with self.assertRaisesRegex(
                batch.BatchError, "PRESIGNED_BATCH_EXHAUSTED_OWNER_RENEWAL_REQUIRED"):
            self.run_batch(near_future_expiry)


if __name__ == "__main__":
    unittest.main()
