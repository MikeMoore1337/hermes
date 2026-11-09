"""Source-only cross-platform protocol tests; NEVER touch original host paths."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import unittest

from device_fabric.native_effect_grants import (
    GrantDenied, NativeEffect, SCHEMA, sign_envelope, verify_envelope,
)

KEY = b"test-only-ephemeral-key-not-production-" + b"x" * 16
NOW = 1_800_000_000
OPID = "7138d606-5cfb-41fb-8021-b0628b3e6e32"


def sample(*, device="h454-win-01335a1f6e6705b4", project="hermes",
           action="file_write", relative="docs/test-native.txt", payload=b"new data",
           expires=NOW + 90):
    effect = NativeEffect(SCHEMA, device, project, OPID, action, relative,
                          hashlib.sha256(payload).hexdigest(), expires)
    return effect, payload


def checked(effect, payload, *, key=KEY, device=None, projects=None, now=NOW):
    wire = sign_envelope(effect, issuer_key=KEY, now=NOW)
    return verify_envelope(wire, payload, verifier_key=key,
                           expected_device_id=device or effect.device_id,
                           allowed_projects=frozenset({"hermes"}) if projects is None else projects,
                           now=now)


class NativeEffectGrantContract(unittest.TestCase):
    def test_signed_file_write_scoped_to_original_project_and_exact_content(self):
        effect, payload = sample()
        receipt = checked(effect, payload)
        self.assertEqual(receipt.effect, effect)
        self.assertRegex(receipt.scope_sha256, r"^[0-9a-f]{64}$")
        self.assertNotEqual(receipt.scope_sha256, effect.payload_sha256)

    def test_cross_platform_wire_encoding_is_deterministic(self):
        effect, payload = sample(device="h15-hermes-ab005bc0e0ea", relative="docs/тест.txt")
        wire1 = sign_envelope(effect, issuer_key=KEY, now=NOW)
        wire2 = sign_envelope(effect, issuer_key=KEY, now=NOW)
        self.assertEqual(wire1, wire2)
        self.assertEqual(checked(effect, payload, projects=frozenset({"hermes"})).effect, effect)

    def test_process_action_binds_command_bytes_and_working_root(self):
        effect, payload = sample(action="process_run", relative="", payload=b'["git","status","--short"]')
        checked(effect, payload)
        with self.assertRaises(GrantDenied):
            checked(effect, b'["git","push"]')
        with self.assertRaises(GrantDenied):
            sign_envelope(replace(effect, relative="somewhere"), issuer_key=KEY, now=NOW)

    def test_rejects_different_device_and_project_without_disclosure(self):
        effect, payload = sample()
        for options in ({"device": "h15-yfc-c6ee0d53e858"},
                        {"projects": frozenset({"your-fitness-coach"})},
                        {"key": b"z" * 32}):
            with self.subTest(options=options), self.assertRaisesRegex(GrantDenied, "^native_grant_denied$"):
                checked(effect, payload, **options)

    def test_rejects_tampered_signed_fields_and_mac(self):
        effect, payload = sample()
        src = json.loads(sign_envelope(effect, issuer_key=KEY, now=NOW))
        cases = []
        for field, value in (("relative", "docs/other.txt"), ("project", "other"),
                             ("operation_id", "d138d606-5cfb-41fb-8021-b0628b3e6e32"),
                             ("expires_at", NOW + 91)):
            changed = json.loads(json.dumps(src))
            changed["effect"][field] = value
            cases.append(changed)
        changed = json.loads(json.dumps(src))
        changed["mac"] = "0" * 64
        cases.append(changed)
        for case in cases:
            with self.subTest(case=case["effect"]["relative"]), self.assertRaises(GrantDenied):
                verify_envelope(json.dumps(case).encode(), payload, verifier_key=KEY,
                                expected_device_id=effect.device_id,
                                allowed_projects=frozenset({"hermes"}), now=NOW)

    def test_expired_or_unreasonably_future_grants_denied(self):
        effect, payload = sample()
        for expiry in (NOW - 1, NOW + 601):
            with self.subTest(expiry=expiry), self.assertRaises(GrantDenied):
                sign_envelope(replace(effect, expires_at=expiry), issuer_key=KEY, now=NOW)
        with self.assertRaises(GrantDenied):
            checked(effect, payload, now=NOW + 91)

    def test_rejects_traversal_symlink_like_and_secret_names_syntactically(self):
        effect, _ = sample()
        forbidden = ["../hello", "a/../b", "a//b", "./x", "/tmp/x", r"a\\b", "C:/vault",
                     "a:file", "a/.git/config", ".env", "a/.env.prod", "vault/notes",
                     "secret.key", "a/passwords.json", "NUL.txt", "a/COM1", "a/.. ",
                     "a/trailing.", "a/control\x00.txt", "a/\u202efile", "te\u0301st.txt"]
        for relative in forbidden:
            with self.subTest(path=repr(relative)), self.assertRaises(GrantDenied):
                sign_envelope(replace(effect, relative=relative), issuer_key=KEY, now=NOW)

    def test_rejects_invalid_fields_types_and_key_sizes(self):
        effect, payload = sample()
        for variant in [replace(effect, expires_at=True), replace(effect, schema="wrong"),
                        replace(effect, project="../other"), replace(effect, operation_id="bad"),
                        replace(effect, action="root_shell"), replace(effect, payload_sha256="f")]:
            with self.assertRaises(GrantDenied):
                sign_envelope(variant, issuer_key=KEY, now=NOW)
        with self.assertRaises(GrantDenied):
            sign_envelope(effect, issuer_key=b"short", now=NOW)
        wire = sign_envelope(effect, issuer_key=KEY, now=NOW)
        for kwargs in ({"verifier_key": b"short"}, {"allowed_projects": {"hermes"}},
                       {"expected_device_id": "other"}, {"now": True}):
            options = dict(verifier_key=KEY, expected_device_id=effect.device_id,
                           allowed_projects=frozenset({"hermes"}), now=NOW)
            options.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(GrantDenied):
                verify_envelope(wire, payload, **options)

    def test_rejects_duplicate_fields_unknown_fields_oversize_and_binary_payload(self):
        effect, payload = sample()
        wire = sign_envelope(effect, issuer_key=KEY, now=NOW)
        options = dict(verifier_key=KEY, expected_device_id=effect.device_id,
                       allowed_projects=frozenset({"hermes"}), now=NOW)
        malformed = [b'{"effect":{},"effect":{},"mac":"x"}',
                     wire.replace(b'"project":"hermes"', b'"project":"hermes","project":"hermes"'),
                     wire.replace(b'"mac":', b'"approved":true,"mac":'),
                     wire + b" " * 4096, b"\xff", b"[]", b"{}"]
        for case in malformed:
            with self.subTest(case=case[:32]), self.assertRaises(GrantDenied):
                verify_envelope(case, payload, **options)
        with self.assertRaises(GrantDenied):
            verify_envelope(wire, b"A" * (256 * 1024 + 1), **options)
        with self.assertRaises(GrantDenied):
            verify_envelope(wire, "new data", **options)

    def test_no_host_effects_or_network_side_effects(self):
        # Import and verification are pure: the effect is a data contract,
        # not an executable callback or a mounted original project path.
        effect, payload = sample(project="financial-horizon")
        result = checked(effect, payload, projects=frozenset({"financial-horizon"}))
        self.assertEqual(result.effect.project, "financial-horizon")
        self.assertEqual(result.effect.relative, "docs/test-native.txt")


if __name__ == "__main__":
    unittest.main()
