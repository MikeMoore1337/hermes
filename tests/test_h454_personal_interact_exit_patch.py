"""The bounded upstream patch rejects drift and duplicate patching."""
import hashlib
import unittest
from unittest.mock import patch as mock_patch

from scripts import h454_personal_interact_exit_patch as fixer


class PersonalInteractExitPatchTests(unittest.TestCase):
    def test_checked_fixture_is_patched_once_and_drift_fails_closed(self):
        source = b'prefix\n' + fixer.ANCHOR + b'\nend\n'
        with mock_patch.object(fixer, 'SOURCE_SHA256', hashlib.sha256(source).hexdigest()):
            result = fixer.patch(source)
            self.assertEqual(result.count(fixer.INSERT), 1)
            self.assertEqual(result.replace(fixer.INSERT, b''), source)
            for invalid in (source + b'drift', result, source + fixer.ANCHOR):
                with self.subTest(length=len(invalid)), self.assertRaises(ValueError):
                    fixer.patch(invalid)


if __name__ == '__main__': unittest.main()
