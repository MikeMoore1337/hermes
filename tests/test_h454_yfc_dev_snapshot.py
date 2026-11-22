import hashlib
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_yfc_dev_snapshot as snapshot


def archive(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as tar:
        for name, content, kind in entries:
            item = tarfile.TarInfo(name)
            item.type = kind
            item.size = len(content) if kind == tarfile.REGTYPE else 0
            tar.addfile(item, io.BytesIO(content) if item.size else None)
    return out.getvalue()


def checked(entries):
    raw = archive(entries)
    return snapshot.read_archive(raw, hashlib.sha256(raw).hexdigest())


class SnapshotTests(unittest.TestCase):
    def test_reads_exact_regular_sources(self):
        result = checked([('README.md', b'public', tarfile.REGTYPE),
                          ('app/main.py', b'pass\n', tarfile.REGTYPE)])
        self.assertEqual(result, {'README.md': b'public', 'app/main.py': b'pass\n'})

    def test_rejects_hash_drift_and_unsafe_archive_entries(self):
        raw = archive([('README.md', b'public', tarfile.REGTYPE)])
        with self.assertRaises(snapshot.SnapshotDenied):
            snapshot.read_archive(raw, '0' * 64)
        for name, kind in [('../outside.py', tarfile.REGTYPE),
                           ('private/source.py', tarfile.REGTYPE),
                           ('.env.dev', tarfile.REGTYPE),
                           ('link.py', tarfile.SYMTYPE),
                           ('README.md', tarfile.REGTYPE)]:
            with self.subTest(name=name), self.assertRaises(snapshot.SnapshotDenied):
                checked([('README.md', b'public', tarfile.REGTYPE), (name, b'x', kind)])

    @unittest.skipUnless(sys.platform == 'linux', 'Linux renameat2 fixture required')
    def test_never_replaces_existing_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'root'
            files = {'README.md': b'original'}
            with patch.object(snapshot, 'SNAPSHOT_ROOT', root), patch.object(snapshot, '_trusted_directory'), \
                    patch.object(os, 'geteuid', return_value=0):
                target = snapshot.install(files, root)
                with self.assertRaises(snapshot.SnapshotDenied):
                    snapshot.install({'README.md': b'changed'}, root)
            self.assertEqual((target / 'README.md').read_bytes(), b'original')
            self.assertEqual(list(root.iterdir()), [target])


if __name__ == '__main__':
    unittest.main()
