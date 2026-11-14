"""H454 versioned disabled-only migration: synthetic local contract tests."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_native_linux_versioned_migrate as m


class NativeVersionedMigrationTests(unittest.TestCase):
    def test_bounded_read_rejects_symlink_and_group_writable(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            real = base / "real"
            real.write_bytes(b"data")
            real.chmod(0o600)
            link = base / "link"
            link.symlink_to(real)
            with self.assertRaises(m.Hold):
                m.bounded_read(link, 16, owners={os.geteuid()}, private=True)
            real.chmod(0o660)
            with self.assertRaises(m.Hold):
                m.bounded_read(real, 16, owners={os.geteuid()}, private=True)

    def test_new_file_is_exclusive_and_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "receipt"
            m.new_file(path, b"first")
            with self.assertRaises(m.Hold):
                m.new_file(path, b"second")
            self.assertEqual(path.read_bytes(), b"first")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_replace_file_is_atomic_and_cleans_sibling(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "service"
            path.write_bytes(b"old")
            m.replace_file(path, b"new", 0o644, os.geteuid(), os.getegid())
            self.assertEqual(path.read_bytes(), b"new")
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            self.assertEqual(list(Path(folder).iterdir()), [path])

    def test_relay_pinning_denies_dns_rotation_and_unauthorized_ips(self):
        active = (
            b"IPAddressAllow=188.114.96.1/32\n"
            b"IPAddressAllow=188.114.97.1/32\n"
            b"IPAddressAllow=127.0.0.53/32\n"
        )
        records = [(None, None, None, None, (ip, 443))
                   for ip in ("188.114.97.1", "188.114.96.1")]
        with patch.object(m.socket, "getaddrinfo", return_value=records):
            self.assertEqual(m.relay_ips(active),
                             ("188.114.96.1,188.114.97.1", "127.0.0.53"))
        rotated = [(None, None, None, None, ("104.21.57.247", 443))]
        with patch.object(m.socket, "getaddrinfo", return_value=rotated):
            with self.assertRaises(m.Hold):
                m.relay_ips(active)

    def test_stage_source_retains_file_bytes_and_requires_existing_target_absent(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            paths = m.Paths(base=base, state=base / "state",
                            units=base / "units", staged=base / "staged")
            (base / "releases").mkdir()
            sources = {
                "device_fabric/__init__.py": b"x=1\n",
                "scripts/h454_native_linux_service.py": b"y=2\n",
            }
            candidate = m.Candidate(
                b"", b"", {}, {}, {}, (0, 0), b"", b"", b"",
                sources, tuple(),
            )
            # Stage-source requires the complete authenticated allowlist in production.
            with patch.object(m, "SOURCE_FILES", tuple(sources)):
                m.stage_source(paths, candidate)
                self.assertEqual((paths.source / "device_fabric/__init__.py").read_bytes(), b"x=1\n")
                self.assertEqual((paths.source / "scripts/h454_native_linux_service.py").read_bytes(), b"y=2\n")
                self.assertEqual(paths.source.stat().st_mode & 0o777, 0o755)
                self.assertEqual((paths.source / "scripts").stat().st_mode & 0o777, 0o755)
                with self.assertRaises(m.Hold):
                    m.stage_source(paths, candidate)

    def test_summary_contains_no_original_paths_or_bearers(self):
        c = m.Candidate(
            b"bearer-not-for-output", b"new", {}, {
                "hermes-commander-native-preflight.service": b"preflight",
                "hermes-commander-native.service": b"active",
            }, {}, (0, 0), b"", b"", b"", {}, (),
        )
        result = str(m.summary(c))
        self.assertIn("new_manifest_sha256", result)
        self.assertNotIn("bearer-not-for-output", result)
        self.assertNotIn("/srv/", result)

    def test_migration_interface_does_not_offer_service_start(self):
        self.assertEqual(m.TARGET, "hermes-vps")
        self.assertEqual(m.NEW, "e8887bfb7a04aaff9cbb91a1c46003fcd8d5347a")
        self.assertFalse(hasattr(m, "start_service"))


if __name__ == "__main__":
    unittest.main()