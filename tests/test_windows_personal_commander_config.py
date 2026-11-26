"""Synthetic personal Windows configuration; no pairing or host-file access."""
from __future__ import annotations

import json
import os
import unittest
from dataclasses import replace

from device_fabric.native_brc_enrollment import Paired
from device_fabric import windows_personal_commander_config as config
from device_fabric import windows_native_dpapi as dpapi

SID = "S-1-5-21-1-2-3-1001"
DEVICE = "h454-win-personal-" + "a" * 32
TOKEN = "brc_dev_" + "b" * 64
CA = b"-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----\n"
BUNDLE = "c" * 64
RELEASE = "d" * 40
SEALED = b"s" * 64


def paired(target="windows-personal", device=DEVICE):
    return Paired(target, device, TOKEN, "wss://hermes.mikemoore.top/ws")


class PersonalCommanderConfigTests(unittest.TestCase):
    def prepare(self, value=None):
        return config.prepare_config(value or paired(), owner_sid=SID, release_sha=RELEASE,
            ca=CA, bundle_sha256=BUNDLE, now=1000, seal=lambda *_a, **_k: SEALED)

    def test_round_trip_binds_owner_ca_bundle_and_separate_device(self):
        self.assertEqual(set(config.PERSONAL_ROOTS),
                         {"hermes", "your-fitness-coach", "financial-horizon"})
        raw = self.prepare()
        self.assertNotIn(TOKEN.encode(), raw)
        parsed = config.parse_config(raw)
        self.assertNotIn(DEVICE, repr(parsed))
        self.assertEqual(parsed.device_id, DEVICE)
        calls = []
        def decrypt(value, **scope):
            calls.append((value, scope))
            return TOKEN
        self.assertEqual(config.unseal(parsed, owner_sid=SID, ca=CA,
                                      bundle_sha256=BUNDLE, decrypt=decrypt), TOKEN)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1]["device_id"], DEVICE)
        self.assertEqual(calls[0][1]["manifest_sha256"],
                         config.policy_digest(parsed.ca_sha256, BUNDLE))

    def test_old_read_only_identity_never_becomes_personal(self):
        for other in (paired("windows", "h454-win-native-" + "a" * 32),
                      paired("windows-personal", "h454-win-native-" + "a" * 32)):
            with self.subTest(target=other.target), self.assertRaises(config.PersonalCommanderDenied):
                self.prepare(other)

    def test_wrong_owner_ca_or_bundle_never_calls_decrypt(self):
        parsed = config.parse_config(self.prepare())
        for owner, ca, bundle in (("S-1-5-99", CA, BUNDLE),
                                  (SID, b"another CA", BUNDLE),
                                  (SID, CA, "e" * 64)):
            with self.subTest(owner=owner, bundle=bundle), self.assertRaises(config.PersonalCommanderDenied):
                config.unseal(parsed, owner_sid=owner, ca=ca, bundle_sha256=bundle,
                              decrypt=lambda *_a, **_k: self.fail("decrypt called"))

    def test_constructed_invalid_config_cannot_skip_parse_validation(self):
        parsed = config.parse_config(self.prepare())
        for changed in (replace(parsed, device_id="h454-win-native-" + "a" * 32),
                        replace(parsed, release_sha="invalid"),
                        replace(parsed, created_at=True), replace(parsed, sealed_bearer=b"short")):
            with self.subTest(changed=changed), self.assertRaises(config.PersonalCommanderDenied):
                config.unseal(changed, owner_sid=SID, ca=CA, bundle_sha256=BUNDLE,
                              decrypt=lambda *_a, **_k: self.fail("decrypt called"))

    def test_noncanonical_duplicate_and_bad_fields_are_rejected(self):
        raw = self.prepare()
        bad = [raw + b"\n", raw.replace(b'"schema":', b'"schema":"duplicate","schema":')]
        for key, value in (("device_id", "h454-win-native-" + "a" * 32),
                           ("bundle_sha256", "x" * 64), ("created_at", True),
                           ("sealed_bearer_b64", "!")):
            obj = json.loads(raw)
            obj[key] = value
            bad.append(config._encode(obj))
        for value in bad:
            with self.subTest(value=value[:30]), self.assertRaises(config.PersonalCommanderDenied):
                config.parse_config(value)

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI integration")
    def test_real_current_user_dpapi_round_trip_and_domain_separation(self):
        raw = config.prepare_config(paired(), owner_sid=SID, release_sha=RELEASE,
                                    ca=CA, bundle_sha256=BUNDLE, now=1000)
        parsed = config.parse_config(raw)
        self.assertNotIn(TOKEN.encode(), raw)
        self.assertEqual(config.unseal(parsed, owner_sid=SID, ca=CA,
                                       bundle_sha256=BUNDLE), TOKEN)
        with self.assertRaises(dpapi.NativeDpapiDenied):
            dpapi.unseal_for_current_user(parsed.sealed_bearer,
                manifest_sha256=config.policy_digest(parsed.ca_sha256, BUNDLE), device_id=DEVICE)


if __name__ == "__main__":
    unittest.main()
