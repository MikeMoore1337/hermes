import hashlib
import unittest
from unittest.mock import patch

from scripts import h454_personal_search_patch as candidate


class PersonalSearchPatchTests(unittest.TestCase):
    def test_same_exclusions_are_added_after_the_user_globs_in_both_modes(self):
        source = (b"file:\n            args.push(options.rootPath);\ncontent:\n"
                  b"            args.push('--', options.pattern, options.rootPath);\n")
        with patch.object(candidate, "SOURCE_SHA256", hashlib.sha256(source).hexdigest()):
            result = candidate.patch(source)
        self.assertEqual(result.count(b"for (const rule of "), 2)
        self.assertEqual(result.count(b"!**/private-vault/**"), 2)
        self.assertEqual(result.count(b"!**/*.pem"), 2)
        self.assertLess(result.index(b"for (const rule of "), result.index(b"args.push(options.rootPath)"))
        self.assertLess(result.rindex(b"for (const rule of "), result.index(b"args.push('--', options.pattern"))

    def test_changed_or_duplicate_source_is_rejected(self):
        for value in (b"", b"not the pinned source", None):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                candidate.patch(value)
