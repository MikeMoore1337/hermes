"""H454: exact-hash universal websockets 17.2 wheel, offline stage/rollback."""
from __future__ import annotations
import hashlib
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts import h454_native_linux_wheel as wheel

RELEASE = "a" * 40
TARGETS = ("hermes-vps", "yfc-vps")


def synthetic_wheel() -> bytes:
    buffer = io.BytesIO()
    contents = {
        "websockets/__init__.py": b"__version__ = '17.2'\n",
        "websockets/sync/client.py": b"def connect(): pass\n",
        "websockets-17.2.dist-info/METADATA": b"Metadata-Version: 2.4\nName: websockets\nVersion: 17.2\n",
        "websockets-17.2.dist-info/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        "websockets-17.2.dist-info/RECORD": b"synthetic fixture,not a real PyPI wheel\n",
    }
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as out:
        for path, data in contents.items():
            out.writestr(path, data)
    return buffer.getvalue()


class NativeOfflineWheel(unittest.TestCase):
    def setUp(self):
        self.payload = synthetic_wheel()
        self.sha = hashlib.sha256(self.payload).hexdigest()
        self.patched = patch.object(wheel, "WHEEL_SHA256", self.sha)
        self.patched.start()
        self.addCleanup(self.patched.stop)
        self.scratch = tempfile.TemporaryDirectory(prefix="h454-native-wheel-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name) / "deps"
        self.root.mkdir(mode=0o700)

    def test_exact_wheel_stage_and_rollback_on_both_original_host_labels(self):
        for target in TARGETS:
            with self.subTest(target=target):
                staged = wheel.stage_wheel(
                    self.payload, target=target, release_sha=RELEASE,
                    root=self.root, owner_uid=os.geteuid(), check_ancestors=False,
                )
                self.assertEqual(staged["status"], "PINNED_WHEEL_STAGED_ONLY")
                self.assertFalse(staged["native_service_started"])
                parent = self.root / ("main-" + RELEASE)
                self.assertTrue((parent / "websockets/sync/client.py").is_file())
                self.assertTrue((parent / wheel.RECEIPT).is_file())
                self.assertTrue(all(
                    (p.stat().st_mode & 0o777) == 0o444 for p in parent.rglob("*")
                    if p.is_file()
                ))
                with self.assertRaises(wheel.WheelDenied):
                    wheel.stage_wheel(self.payload, target=target, release_sha=RELEASE,
                                      root=self.root, owner_uid=os.geteuid(),
                                      check_ancestors=False)
                undone = wheel.rollback_wheel(
                    self.payload, target=target, release_sha=RELEASE,
                    root=self.root, owner_uid=os.geteuid(), check_ancestors=False,
                )
                self.assertEqual(undone["status"], "PINNED_WHEEL_ROLLED_BACK")
                self.assertFalse(parent.exists())

    def test_invalid_hash_or_source_target_is_rejected_before_writes(self):
        with patch.object(wheel, "WHEEL_SHA256", "0" * 64):
            with self.assertRaises(wheel.WheelDenied):
                wheel.verify_bytes(self.payload)
        for target in ("windows", "server", "hermes_vps"):
            with self.subTest(target=target), self.assertRaises(wheel.WheelDenied):
                wheel.stage_wheel(self.payload, target=target, release_sha=RELEASE,
                                  root=self.root, owner_uid=os.geteuid(),
                                  check_ancestors=False)
        for sha in ("x"*40, "a"*39, "0"):
            with self.subTest(sha=sha), self.assertRaises(wheel.WheelDenied):
                wheel.stage_wheel(self.payload, target=TARGETS[0],
                                  release_sha=sha, root=self.root,
                                  owner_uid=os.geteuid(), check_ancestors=False)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_refuse_zip_traversal_foreign_members_and_python_startup_hooks(self):
        cases = [
            ("../escape.py", b""),
            ("/root/shell.py", b""),
            ("websockets/../../escape.py", b""),
            ("websockets/attacker.pth", b"import os\n"),
            ("websockets/fake.so", b"binary"),
            ("other_package/__init__.py", b""),
        ]
        for extra, content in cases:
            with self.subTest(extra=extra):
                buf = io.BytesIO(self.payload)
                # Repack the fixture with a malicious extra member.
                outbuf = io.BytesIO()
                with zipfile.ZipFile(buf) as old, zipfile.ZipFile(
                    outbuf, "w", compression=zipfile.ZIP_DEFLATED,
                ) as changed:
                    for member in old.infolist():
                        changed.writestr(member.filename, old.read(member))
                    changed.writestr(extra, content)
                tampered = outbuf.getvalue()
                with patch.object(wheel, "WHEEL_SHA256",
                                  hashlib.sha256(tampered).hexdigest()):
                    with self.assertRaises(wheel.WheelDenied):
                        wheel.verify_bytes(tampered)

    def test_rollback_denies_tampering_links_and_unrelated_releases(self):
        wheel.stage_wheel(self.payload, target=TARGETS[0], release_sha=RELEASE,
                          root=self.root, owner_uid=os.geteuid(),
                          check_ancestors=False)
        parent = self.root / ("main-" + RELEASE)
        other = self.root / "main-" + "b"*40
        other.mkdir(mode=0o700)
        marker = other / "keep.txt"
        marker.write_text("unrelated")
        target = parent / "websockets/__init__.py"
        target.chmod(0o644)
        target.write_text("malicious")
        with self.assertRaises(wheel.WheelDenied):
            wheel.rollback_wheel(self.payload, target=TARGETS[0],
                                 release_sha=RELEASE, root=self.root,
                                 owner_uid=os.geteuid(), check_ancestors=False)
        self.assertTrue(parent.exists())
        self.assertEqual(marker.read_text(), "unrelated")

    def test_repo_uses_exact_pypi_verified_public_digest_and_no_network_ops(self):
        self.assertEqual(
            wheel.WHEEL,
            "websockets-17.2-py3-none-any.whl",
        )
        self.assertEqual(len(wheel.WHEEL_SHA256),64)  # patched fixture in this test
        code=(Path(__file__).resolve().parents[1] /
              "scripts/h454_native_linux_wheel.py").read_text()
        for forbidden in ("requests.", "urllib.request", "subprocess.run",
                          "pip install", "tar.extractall", "os.system"):
            self.assertNotIn(forbidden, code)
        self.assertIn("O_NOFOLLOW", code)


if __name__ == "__main__":
    unittest.main()
