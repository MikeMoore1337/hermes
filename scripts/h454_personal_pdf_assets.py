"""Stage fixed PDF assets from already downloaded, verified archives.

The caller prepares an otherwise disposable release directory and includes the
resulting files in its integrity manifest. This module never downloads or runs
third-party code during staging.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import tarfile

FONTKIT_SHA256 = '6dd0ae9209fce419b2ed76c97166863167b4df56d75fbe3c7f1d1e6e49c85867'
FONT_SHA256 = 'ae7b7855e115a5966d8b1b3f80f254ccc117ec86f9965e202ee2940453837280'
NOTICE_SHA256 = '63d3ba759d12804c5b31a9d5940d855c1820d1f5999e6b0872eb1c7ff045fbc9'
MEMBERS = {
    'package/dist/fontkit.umd.js': ('h454-fontkit.cjs', 1506282, 'd60739f02b41b636ee0cc2fb79ba589958144f9240e585dbc19e6a3b08d82825'),
    'package/README.md': ('h454-fontkit.README.md', 16875, '7315fcc54511f5ffc906969c39333f93cd47f5217ab014fe45acff14bd5ec4c0'),
    'package/package.json': ('h454-fontkit.package.json', 2278, '42b7a756ea4c11abfa664ffe9f9b67c1e30e564b5e2fb6db5b1775dac3eabb35'),
}


def _read_checked(path: Path, maximum: int, expected: str) -> bytes:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise ValueError('pdf_asset_denied')
    value = path.read_bytes()
    if len(value) > maximum or hashlib.sha256(value).hexdigest() != expected:
        raise ValueError('pdf_asset_denied')
    return value


def stage(release: Path, archive: Path, font: Path, notice: Path) -> None:
    destination = release / 'third_party'
    if (not isinstance(release, Path) or release.is_symlink() or not release.is_dir()
            or destination.is_symlink() or not destination.is_dir()):
        raise ValueError('pdf_asset_denied')
    compressed = _read_checked(archive, 2_000_000, FONTKIT_SHA256)
    assets = {
        'h454-DejaVuSans.ttf': _read_checked(font, 1_000_000, FONT_SHA256),
        'h454-DejaVu-copyright.txt': _read_checked(notice, 10_000, NOTICE_SHA256),
    }
    with tarfile.open(fileobj=io.BytesIO(compressed), mode='r:gz') as source:
        for original, (name, size, digest) in MEMBERS.items():
            member = source.getmember(original)
            if not member.isfile() or member.size != size:
                raise ValueError('pdf_asset_denied')
            reader = source.extractfile(member)
            if reader is None:
                raise ValueError('pdf_asset_denied')
            data = reader.read(size + 1)
            if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
                raise ValueError('pdf_asset_denied')
            assets[name] = data
    for name, data in assets.items():
        with (destination / name).open('xb') as output:
            output.write(data)
