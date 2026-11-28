import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_personal_pdf_assets as assets


class PersonalPdfAssetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.release = self.root / 'release'
        (self.release / 'third_party').mkdir(parents=True)
        self.font = self.root / 'font'
        self.font.write_bytes(b'font')
        self.notice = self.root / 'notice'
        self.notice.write_bytes(b'notice')
        data = io.BytesIO()
        self.members = {}
        with tarfile.open(fileobj=data, mode='w:gz') as archive:
            for original, (name, _, _) in assets.MEMBERS.items():
                value = ('fixture-' + name).encode()
                info = tarfile.TarInfo(original)
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
                self.members[original] = (name, len(value), hashlib.sha256(value).hexdigest())
        self.archive = self.root / 'source.tgz'
        self.archive.write_bytes(data.getvalue())
        self.patches = patch.multiple(assets, MEMBERS=self.members,
            FONTKIT_SHA256=hashlib.sha256(data.getvalue()).hexdigest(),
            FONT_SHA256=hashlib.sha256(b'font').hexdigest(),
            NOTICE_SHA256=hashlib.sha256(b'notice').hexdigest())
        self.patches.start()
        self.addCleanup(self.patches.stop)

    def test_stages_exact_members_and_preserves_notices(self):
        assets.stage(self.release, self.archive, self.font, self.notice)
        files = self.release / 'third_party'
        self.assertEqual((files / 'h454-DejaVu-copyright.txt').read_bytes(), b'notice')
        for name, _, _ in self.members.values():
            self.assertEqual((files / name).read_bytes(), ('fixture-' + name).encode())
        with self.assertRaises(FileExistsError):
            assets.stage(self.release, self.archive, self.font, self.notice)

    def test_modified_source_is_denied_before_writing_anything(self):
        self.font.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            assets.stage(self.release, self.archive, self.font, self.notice)
        self.assertEqual(list((self.release / 'third_party').iterdir()), [])

    def test_symlinked_destination_is_denied(self):
        with patch.object(Path, 'is_symlink', return_value=True):
            with self.assertRaises(ValueError):
                assets.stage(self.release, self.archive, self.font, self.notice)


if __name__ == '__main__':
    unittest.main()
