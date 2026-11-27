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

    def test_yfc_profile_binds_only_the_owner_approved_dev_root(self):
        calls = []
        def seal(_token, **scope):
            calls.append(scope)
            return bytes.fromhex(scope["manifest_sha256"]) + b"s" * 32
        raw = config.prepare_config(paired(), owner_sid=SID, release_sha=RELEASE,
            ca=CA, bundle_sha256=BUNDLE, now=1000, profile="yfc-dev", seal=seal)
        parsed = config.parse_config(raw)
        self.assertEqual(parsed.profile, "yfc-dev")
        self.assertEqual(config.roots_for(parsed.profile), (r"D:\Pet-projects\yfc-dev",))
        self.assertNotEqual(calls[0]["manifest_sha256"], config.policy_digest(parsed.ca_sha256, BUNDLE))
        def decrypt(ciphertext, **scope):
            if ciphertext[:32] != bytes.fromhex(scope["manifest_sha256"]):
                raise ValueError("wrong scope")
            return TOKEN
        self.assertEqual(config.unseal(parsed, owner_sid=SID, ca=CA, bundle_sha256=BUNDLE, decrypt=decrypt), TOKEN)
        altered = json.loads(raw)
        altered["schema"] = config.SCHEMA
        with self.assertRaises(config.PersonalCommanderDenied):
            config.unseal(config.parse_config(config._encode(altered)), owner_sid=SID, ca=CA,
                          bundle_sha256=BUNDLE, decrypt=decrypt)

    def test_unknown_profile_is_denied(self):
        with self.assertRaises(config.PersonalCommanderDenied):
            config.prepare_config(paired(), owner_sid=SID, release_sha=RELEASE, ca=CA,
                bundle_sha256=BUNDLE, now=1000, profile="arbitrary", seal=lambda *_a, **_k: SEALED)

    def test_multiple_roots_are_bound_to_the_sealed_bearer(self):
        roots = (r'D:\Pet-projects\yfc-dev', r'D:\Pet-projects\hermes')
        def seal(_token, **scope):
            return bytes.fromhex(scope['manifest_sha256']) + b's' * 32
        def decrypt(value, **scope):
            if value[:32] != bytes.fromhex(scope['manifest_sha256']):
                raise ValueError('wrong scope')
            return TOKEN
        raw = config.prepare_config(paired(), owner_sid=SID, release_sha=RELEASE, ca=CA,
            bundle_sha256=BUNDLE, now=1000, profile='owner-projects', roots=roots, seal=seal)
        parsed = config.parse_config(raw)
        self.assertEqual(config.roots_for(parsed.profile, roots=parsed.roots), roots)
        self.assertEqual(config.unseal(parsed, owner_sid=SID, ca=CA, bundle_sha256=BUNDLE, decrypt=decrypt), TOKEN)
        changed = replace(parsed, roots=(roots[0], r'D:\Pet-projects\another'))
        with self.assertRaises(config.PersonalCommanderDenied):
            config.unseal(changed, owner_sid=SID, ca=CA, bundle_sha256=BUNDLE, decrypt=decrypt)

    def test_project_roots_reject_broad_nested_private_and_ambiguous_paths(self):
        first = r'D:\Pet-projects\yfc-dev'
        for extra in (r'D:\Pet-projects', r'C:\Windows', r'D:\Pet-projects\yfc-dev\nested',
                      r'D:\Pet-projects\second-brain-workspace\code', r'D:\Pet-projects\vault',
                      r'D:\Pet-projects\hermes\..\other', r'D:\Pet-projects\NUL',
                      r'D:\Pet-projects\hermes:stream', r'\\server\share\project'):
            with self.subTest(extra=extra), self.assertRaises(config.PersonalCommanderDenied):
                config.roots_for('owner-projects', roots=(first, extra))
        with self.assertRaises(config.PersonalCommanderDenied):
            config.roots_for('owner-projects', roots=(first, r'D:\Pet-projects\z', r'D:\Pet-projects\a'))

    def test_add_project_reseals_existing_grant_and_preserves_identity(self):
        def seal(_token, **scope):
            return bytes.fromhex(scope['manifest_sha256']) + b's' * 32
        def decrypt(ciphertext, **scope):
            if ciphertext[:32] != bytes.fromhex(scope['manifest_sha256']):
                raise ValueError('wrong scope')
            return TOKEN
        roots = (r'D:\Pet-projects\yfc-dev', r'D:\Pet-projects\hermes')
        raw = config.prepare_config(paired(), owner_sid=SID, release_sha=RELEASE, ca=CA,
            bundle_sha256=BUNDLE, now=1000, profile='owner-projects', roots=roots, seal=seal)
        result = config.add_project(raw, r'D:\Pet-projects\financial-horizon', owner_sid=SID,
            ca=CA, bundle_sha256=BUNDLE, seal=seal, decrypt=decrypt)
        current, updated = config.parse_config(raw), config.parse_config(result)
        self.assertEqual(updated.roots, (roots[0], r'D:\Pet-projects\financial-horizon', roots[1]))
        self.assertEqual((updated.device_id, updated.release_sha, updated.created_at),
                         (current.device_id, current.release_sha, current.created_at))
        self.assertEqual(config.unseal(updated, owner_sid=SID, ca=CA, bundle_sha256=BUNDLE, decrypt=decrypt), TOKEN)
        with self.assertRaises(config.PersonalCommanderDenied):
            config.unseal(replace(updated, roots=roots), owner_sid=SID, ca=CA,
                          bundle_sha256=BUNDLE, decrypt=decrypt)

    def test_add_project_is_idempotent_and_rejects_private_or_wrong_owner(self):
        raw = config.prepare_config(paired(), owner_sid=SID, release_sha=RELEASE,
            ca=CA, bundle_sha256=BUNDLE, now=1000, profile='yfc-dev', seal=lambda *_a, **_k: SEALED)
        self.assertEqual(config.add_project(raw, r'D:\Pet-projects\YFC-DEV', owner_sid=SID,
            ca=CA, bundle_sha256=BUNDLE, decrypt=lambda *_a, **_k: TOKEN), raw)
        for project, owner in ((r'D:\Pet-projects\second-brain-workspace', SID),
                               (r'C:\Windows', SID),
                               (r'D:\Pet-projects\hermes', 'S-1-5-99')):
            with self.subTest(project=project), self.assertRaises(config.PersonalCommanderDenied):
                config.add_project(raw, project, owner_sid=owner, ca=CA, bundle_sha256=BUNDLE,
                    decrypt=lambda *_a, **_k: self.fail('unexpected unseal'), seal=lambda *_a, **_k: SEALED)

    def _real_owner_projects_dpapi_refuses_changed_scope(self):
        roots = (r'D:\Pet-projects\yfc-dev', r'D:\Pet-projects\hermes')
        raw = config.prepare_config(paired(), owner_sid=SID, release_sha=RELEASE, ca=CA,
            bundle_sha256=BUNDLE, now=1000, profile='owner-projects', roots=roots)
        parsed = config.parse_config(raw)
        self.assertEqual(config.unseal(parsed, owner_sid=SID, ca=CA, bundle_sha256=BUNDLE), TOKEN)
        with self.assertRaises(config.PersonalCommanderDenied):
            config.unseal(replace(parsed, roots=(roots[0], r'D:\Pet-projects\another')),
                          owner_sid=SID, ca=CA, bundle_sha256=BUNDLE)

    def _real_add_project_reseals_for_current_user(self):
        raw = config.prepare_config(paired(), owner_sid=SID, release_sha=RELEASE,
            ca=CA, bundle_sha256=BUNDLE, now=1000, profile='yfc-dev')
        result = config.add_project(raw, r'D:\Pet-projects\hermes', owner_sid=SID, ca=CA, bundle_sha256=BUNDLE)
        updated = config.parse_config(result)
        self.assertEqual(updated.roots, (r'D:\Pet-projects\yfc-dev', r'D:\Pet-projects\hermes'))
        self.assertEqual(config.unseal(updated, owner_sid=SID, ca=CA, bundle_sha256=BUNDLE), TOKEN)
        with self.assertRaises(config.PersonalCommanderDenied):
            config.unseal(replace(updated, roots=(updated.roots[0], r'D:\Pet-projects\other')),
                          owner_sid=SID, ca=CA, bundle_sha256=BUNDLE)

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

    def _real_current_user_dpapi_round_trip_and_domain_separation(self):
        raw = config.prepare_config(paired(), owner_sid=SID, release_sha=RELEASE,
                                    ca=CA, bundle_sha256=BUNDLE, now=1000)
        parsed = config.parse_config(raw)
        self.assertNotIn(TOKEN.encode(), raw)
        self.assertEqual(config.unseal(parsed, owner_sid=SID, ca=CA,
                                       bundle_sha256=BUNDLE), TOKEN)
        with self.assertRaises(dpapi.NativeDpapiDenied):
            dpapi.unseal_for_current_user(parsed.sealed_bearer,
                manifest_sha256=config.policy_digest(parsed.ca_sha256, BUNDLE), device_id=DEVICE)

    def _real_yfc_profile_dpapi_rejects_legacy_scope(self):
        raw = config.prepare_config(paired(), owner_sid=SID, release_sha=RELEASE,
            ca=CA, bundle_sha256=BUNDLE, now=1000, profile="yfc-dev")
        parsed = config.parse_config(raw)
        self.assertEqual(config.unseal(parsed, owner_sid=SID, ca=CA, bundle_sha256=BUNDLE), TOKEN)
        with self.assertRaises(config.PersonalCommanderDenied):
            config.unseal(replace(parsed, profile="legacy"), owner_sid=SID, ca=CA, bundle_sha256=BUNDLE)


if os.name == "nt":
    PersonalCommanderConfigTests.test_real_add_project_reseals_for_current_user = (
        PersonalCommanderConfigTests._real_add_project_reseals_for_current_user)
    PersonalCommanderConfigTests.test_real_owner_projects_dpapi_refuses_changed_scope = (
        PersonalCommanderConfigTests._real_owner_projects_dpapi_refuses_changed_scope)
    PersonalCommanderConfigTests.test_real_current_user_dpapi_round_trip_and_domain_separation = (
        PersonalCommanderConfigTests._real_current_user_dpapi_round_trip_and_domain_separation)
    PersonalCommanderConfigTests.test_real_yfc_profile_dpapi_rejects_legacy_scope = (
        PersonalCommanderConfigTests._real_yfc_profile_dpapi_rejects_legacy_scope)

if __name__ == "__main__":
    unittest.main()
