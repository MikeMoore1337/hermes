"""The capacity patch accepts only the reviewed personal proxy source."""
from pathlib import Path
import unittest

from scripts import h454_wss_capacity_patch as capacity
from scripts import h454_wss_personal_status_patch as personal

ROOT = Path(__file__).resolve().parents[1]


class ProxyCapacityPatchTests(unittest.TestCase):
    def setUp(self):
        source = (ROOT / 'scripts/h454_wss_relay_proxy.mjs').read_bytes().replace(b'\r\n', b'\n')
        self.original = personal.patch(source)

    def test_only_bounded_connection_limit_changes(self):
        candidate = capacity.patch(self.original)
        self.assertEqual(candidate.replace(capacity.AFTER, capacity.BEFORE, 1), self.original)
        self.assertEqual(candidate.count(capacity.AFTER), 1)

    def test_changed_or_repatched_source_is_denied(self):
        for source in (self.original + b'\n', capacity.patch(self.original), b'invalid', None):
            with self.subTest(source=type(source).__name__), self.assertRaises(ValueError):
                capacity.patch(source)
