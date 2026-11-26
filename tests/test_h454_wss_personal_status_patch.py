from pathlib import Path
import unittest

from scripts import h454_wss_personal_status_patch as candidate

ROOT = Path(__file__).resolve().parents[1]


class PersonalStatusPatchTests(unittest.TestCase):
    def setUp(self):
        self.original = (ROOT / "scripts" / "h454_wss_relay_proxy.mjs").read_bytes().replace(b"\r\n", b"\n")

    def test_only_the_personal_identity_pattern_is_added(self):
        patched = candidate.patch(self.original)
        self.assertEqual(patched.replace(candidate.AFTER, candidate.BEFORE, 1), self.original)
        self.assertEqual(patched.count(candidate.AFTER), 1)

    def test_changed_or_already_patched_source_is_rejected(self):
        for raw in (self.original + b"\n", candidate.patch(self.original), b"invalid", None):
            with self.subTest(value=type(raw).__name__), self.assertRaises(ValueError):
                candidate.patch(raw)
