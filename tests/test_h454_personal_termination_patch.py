import hashlib
import unittest
from unittest.mock import patch

from scripts import h454_personal_termination_patch as fixer


class PersonalTerminationPatchTests(unittest.TestCase):
    def test_patches_only_the_expected_spawn_and_termination(self):
        source = b'before\n' + fixer.SPAWN + b'\nbetween\n' + fixer.TERMINATE + b'\nafter'
        with patch.object(fixer, 'SOURCE_SHA256', hashlib.sha256(source).hexdigest()):
            result = fixer.patch(source)
        self.assertIn(fixer.SUPERVISED_SPAWN, result)
        self.assertIn(fixer.SUPERVISED_TERMINATE, result)
        self.assertNotIn(fixer.TERMINATE, result)

    def test_unreviewed_or_ambiguous_bundle_is_rejected(self):
        source = fixer.SPAWN + fixer.TERMINATE
        with self.assertRaises(ValueError):
            fixer.patch(source)
        ambiguous = source + fixer.SPAWN
        with patch.object(fixer, 'SOURCE_SHA256', hashlib.sha256(ambiguous).hexdigest()):
            with self.assertRaises(ValueError):
                fixer.patch(ambiguous)


if __name__ == '__main__':
    unittest.main()
