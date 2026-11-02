"""Read the canonical Windows supervisor and verify its shared job guard."""
from pathlib import Path
import stat

from scripts.h454_windows_wss_launcher import JOB_GUARD


SOURCE = Path(__file__).with_suffix('.ps1')


def build() -> bytes:
    try:
        entry = SOURCE.lstat()
        if (not stat.S_ISREG(entry.st_mode) or stat.S_ISLNK(entry.st_mode) or
                getattr(entry, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400) or
                not 0 < entry.st_size <= 65536):
            raise ValueError('tunnel source drift')
        source = SOURCE.read_bytes()
        text = source.decode('utf-8')
    except (OSError, UnicodeError) as exc:
        raise ValueError('tunnel source unavailable') from exc
    if (not 0 < len(source) <= 65536 or b'\r' in source or text.count(JOB_GUARD) != 1 or
            not text.startswith('#requires -Version 5.1\n')):
        raise ValueError('tunnel source drift')
    return source
