"""Offline contract checks for direct OAuth systemd migration (no host changes)."""
import unittest
from unittest.mock import patch

from scripts.h15_migrate_direct_oauth import _direct_dropin, CREDENTIALS


class DirectMigrationTests(unittest.TestCase):
    def test_replaces_broker_dependencies_and_resets_egress(self):
        old = (
            "[Unit]\nAfter=hermes-oauth-broker.service\n"
            "Requires=hermes-oauth-broker.service\n"
            "[Service]\nLoadCredential=web.env:" + str(CREDENTIALS / "web.env") + "\n"
        )
        candidate = _direct_dropin(old)
        self.assertNotIn("Requires=", candidate)
        self.assertNotIn("After=hermes-oauth-broker", candidate)
        self.assertIn("LoadCredential=web.env:", candidate)
        self.assertIn("LoadCredential=broker.env:", candidate)
        self.assertIn("IPAddressDeny=\n", candidate)
        self.assertIn("IPAddressAllow=\n", candidate)
        self.assertEqual(_direct_dropin(candidate), candidate)

    def test_unknown_dropins_fail_closed(self):
        for value in ("", "[Service]\nIPAddressDeny=any\n",
                      "[Unit]\nRequires=evil.service\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _direct_dropin(value)


if __name__ == "__main__":
    unittest.main()
