"""A Windows-produced Git archive must retain runnable Linux shell scripts."""
import io
from pathlib import Path
import subprocess
import tarfile
import unittest


class LinuxReleaseArchiveTests(unittest.TestCase):
    def test_windows_autocrlf_archive_preserves_linux_shebangs(self):
        root = Path(__file__).resolve().parents[1]
        names = ('scripts/h454_linux_personal_run.sh', 'scripts/h454_linux_personal_which.sh')
        process = subprocess.run(['git', '-c', 'core.autocrlf=true', 'archive',
                                  '--worktree-attributes', 'HEAD', *names],
                                 cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                                 timeout=15, check=True)
        with tarfile.open(fileobj=io.BytesIO(process.stdout), mode='r:') as archive:
            files = {item.name: archive.extractfile(item).read() for item in archive if item.isfile()}
        self.assertEqual(set(files), set(names))
        for name, content in files.items():
            with self.subTest(name=name):
                self.assertTrue(content.startswith(b'#!/bin/sh\n'))
                self.assertNotIn(b'\r', content)


if __name__ == '__main__':
    unittest.main()
