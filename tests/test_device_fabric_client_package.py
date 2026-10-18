"""Source-only portable device agent archive: strict public-code allowlist."""
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile

from device_fabric.package_client import FILES, build_archive

ROOT = Path(__file__).resolve().parents[1]


class PortableDeviceClientPackageTests(unittest.TestCase):
    def test_archive_is_deterministic_without_keys_or_server_modules(self):
        with tempfile.TemporaryDirectory() as td:
            first = Path(td) / 'first.zip'
            second = Path(td) / 'second.zip'
            digest = build_archive(ROOT, first)
            self.assertEqual(digest, build_archive(ROOT, second))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first.stat().st_mode & 0o777, 0o600)
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(tuple(archive.namelist()), FILES)
                for name in FILES:
                    self.assertEqual(archive.read(name), (ROOT / name).read_bytes())
                self.assertNotIn('device_fabric/owner_enrollment.py', archive.namelist())
                self.assertNotIn('device_fabric/service.py', archive.namelist())
                self.assertFalse(any('token' in name or 'secret' in name or 'cert' in name
                                     for name in archive.namelist()))
            with self.assertRaises(ValueError):
                build_archive(ROOT, first)


if __name__ == "__main__":
    unittest.main()
