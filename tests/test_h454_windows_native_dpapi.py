"""H454 Windows DPAPI CurrentUser: real GitHub Windows kernel fixture.

Never contacts owner devices, relay, filesystem or credential issuer.
Uses a disposable synthetic bearer protected under the CI runner identity.
"""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from device_fabric import windows_native_dpapi as native

DEVICE = "h454-win-native-" + "a" * 32
OTHER = "h454-win-native-" + "b" * 32
SHA = "c" * 64
TOKEN = "brc_dev_" + "n" * 72


class PortableDenyContracts(unittest.TestCase):
    def test_manifest_id_and_token_formats_are_strict(self):
        for identity in (
            "h454-win-01335a1f6e6705b4",
            "h15-win-05be75515428", OTHER.upper(),
            "h454-win-native-" + "a" * 16, "h454-win-native-" + "z" * 32,
            "", None,
        ):
            with self.subTest(identity=identity), self.assertRaises(native.NativeDpapiDenied):
                native._entropy(manifest_sha256=SHA, device_id=identity)
        for invalid in ("", "0"*63, "g"*64, SHA.upper(), None):
            with self.subTest(sha=invalid), self.assertRaises(native.NativeDpapiDenied):
                native._entropy(manifest_sha256=invalid, device_id=DEVICE)
        self.assertNotEqual(
            native._entropy(manifest_sha256=SHA, device_id=DEVICE),
            native._entropy(manifest_sha256=SHA, device_id=OTHER),
        )
        self.assertNotEqual(
            native._entropy(manifest_sha256=SHA, device_id=DEVICE),
            native._entropy(manifest_sha256="d"*64, device_id=DEVICE),
        )

    def test_rejects_bad_input_before_calling_windows_crypto(self):
        with patch.object(native, "_crypt", side_effect=AssertionError("crypt invoked")):
            for value in ("", "x"*20, "invalid token space",
                          "x"*257, None, b"not a string"):
                with self.subTest(value=str(value)[:15]), self.assertRaises(
                    native.NativeDpapiDenied
                ):
                    native.seal_for_current_user(
                        value, manifest_sha256=SHA, device_id=DEVICE
                    )
            for value in (b"", b"x", b"x" * 5000, None, "not bytes"):
                with self.subTest(value=str(value)[:15]), self.assertRaises(
                    native.NativeDpapiDenied
                ):
                    native.unseal_for_current_user(
                        value, manifest_sha256=SHA, device_id=DEVICE
                    )

    @unittest.skipIf(os.name == "nt", "Linux refusal checked in main repository CI")
    def test_non_windows_denies_even_correct_bearer(self):
        with self.assertRaisesRegex(
            native.NativeDpapiDenied, "^native_dpapi_denied$",
        ):
            native.seal_for_current_user(
                TOKEN, manifest_sha256=SHA, device_id=DEVICE
            )


@unittest.skipUnless(os.name == "nt", "real DPAPI available only on Windows CI")
class ActualWindowsCurrentUserDPAPI(unittest.TestCase):
    def test_real_round_trip_and_wrong_identity_manifest_refusal(self):
        sealed = native.seal_for_current_user(
            TOKEN, manifest_sha256=SHA, device_id=DEVICE
        )
        self.assertGreaterEqual(len(sealed), 32)
        self.assertLessEqual(len(sealed), native.MAX_CIPHERTEXT)
        self.assertNotIn(TOKEN.encode("ascii"), sealed)
        self.assertEqual(
            native.unseal_for_current_user(
                sealed, manifest_sha256=SHA, device_id=DEVICE
            ),
            TOKEN,
        )
        for changed in (
            {"manifest_sha256": "d"*64, "device_id": DEVICE},
            {"manifest_sha256": SHA, "device_id": OTHER},
        ):
            with self.subTest(changed=changed), self.assertRaisesRegex(
                native.NativeDpapiDenied, "^native_dpapi_denied$"
            ):
                native.unseal_for_current_user(sealed, **changed)

    def test_ciphertext_modification_denied_and_no_secret_in_exception(self):
        sealed = native.seal_for_current_user(
            TOKEN, manifest_sha256=SHA, device_id=DEVICE
        )
        corrupted = bytearray(sealed)
        corrupted[len(corrupted) // 2] ^= 0x01
        for value in (bytes(corrupted), b"\x00"*80):
            with self.subTest(len=len(value)), self.assertRaises(
                native.NativeDpapiDenied
            ) as context:
                native.unseal_for_current_user(
                    value, manifest_sha256=SHA, device_id=DEVICE
                )
            self.assertEqual(str(context.exception), "native_dpapi_denied")
            self.assertNotIn(TOKEN, str(context.exception))

    def test_no_files_network_shell_or_services_used_by_dpapi_primitive(self):
        with patch("builtins.open", side_effect=AssertionError("unexpected IO")), \
             patch("subprocess.run", side_effect=AssertionError("shell forbidden")):
            sealed = native.seal_for_current_user(
                TOKEN, manifest_sha256=SHA, device_id=DEVICE
            )
            recovered = native.unseal_for_current_user(
                sealed, manifest_sha256=SHA, device_id=DEVICE
            )
        self.assertEqual(recovered, TOKEN)


if __name__ == "__main__":
    unittest.main()
