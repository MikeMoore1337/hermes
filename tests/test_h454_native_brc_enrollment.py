"""H454 new-native device-code pairing with existing relay, synthetic only."""
from __future__ import annotations
import json
import unittest

from device_fabric import native_brc_enrollment as pairing

TARGETS = list(pairing.NAME)
CODE = "a"*48
USER = "ABCD-2345"
TOKEN = "brc_dev_" + "z"*64


def enc(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")


def pending():
    return {
        "device_code": CODE, "user_code": USER,
        "verification_uri": "http://127.0.0.1:38183/device/verify",
        "verification_uri_complete": "http://127.0.0.1:38183/device/verify?user_code=" + USER,
        "expires_in": 900, "interval": 3,
    }


def grant(target):
    return {
        "device_token": TOKEN,
        "device_id": {
            "windows": "h454-win-native-" + "a"*32,
            "hermes-vps": "h454-linux-hermes-" + "a"*32,
            "yfc-vps": "h454-linux-yfc-" + "a"*32,
        }[target],
        "token_type": "bearer", "ws_url": "ws://127.0.0.1:38183/ws",
    }


class NativePairingProtocol(unittest.TestCase):
    def test_real_device_code_protocol_with_owner_bound_new_id_all_three(self):
        for target in TARGETS:
            with self.subTest(target=target):
                requests = []
                def start_request(path, content):
                    requests.append((path, json.loads(content)))
                    return 200, enc(pending())
                one = pairing.start(target, post=start_request)
                self.assertEqual(one.user_code, USER)
                self.assertNotIn(CODE, repr(one))
                self.assertEqual(requests, [
                    ("/device/start", {"client_name": pairing.NAME[target]})
                ])
                requests = []
                replies = [(400, enc({"error": "authorization_pending", "interval": 3})),
                           (200, enc(grant(target)))]
                def poll_request(path, content):
                    requests.append((path, json.loads(content)))
                    return replies.pop(0)
                delays = []
                paired = pairing.poll(one, post=poll_request,
                                      sleep=lambda t: delays.append(t),
                                      monotonic=lambda: 0)
                self.assertEqual(delays, [3])
                self.assertEqual(len(requests), 2)
                for path, args in requests:
                    self.assertEqual(path, "/device/poll")
                    self.assertEqual(set(args), {"device_code", "name", "platform"})
                    self.assertNotIn("device_id", args)
                    self.assertEqual(args["name"], pairing.NAME[target])
                    self.assertEqual(args["platform"], pairing.PLATFORM[target])
                self.assertEqual(paired.device_id, grant(target)["device_id"])
                self.assertEqual(paired.token, TOKEN)
                self.assertNotIn(TOKEN, repr(paired))
                self.assertNotIn(CODE, repr(paired))

    def test_unapproved_code_denies_after_exact_budget(self):
        one = pairing.start("windows", post=lambda *_: (200, enc(pending())))
        count = []
        def pending_forever(*_):
            count.append(1)
            return 400, enc({"error": "authorization_pending", "interval": 3})
        with self.assertRaises(pairing.EnrollmentDenied):
            pairing.poll(one, post=pending_forever,
                         sleep=lambda *_: None, monotonic=lambda: 0)
        self.assertEqual(len(count), pairing.MAX_POLLS)

    def test_missing_owner_approval_invalid_server_reply_and_bad_identity(self):
        one = pairing.start("windows", post=lambda *_: (200, enc(pending())))
        for value in (
            {"error": "access_denied"},
            {"error": "expired_token"},
            {"error": "authorization_pending", "interval": "3"},
            {"error": "authorization_pending", "interval": 999},
            {"error": "authorization_pending", "interval": True},
            {"error": "authorization_pending", "interval": 3, "approved": True},
            {**grant("windows"), "device_id": pairing.OLD_WINDOWS},
            {**grant("windows"), "device_id": "h15-win-05be75515428"},
            {**grant("windows"), "device_id": "h454-win-native-" + "x"*32},
            {**grant("windows"), "device_token": "unauthorized short"},
            {**grant("windows"), "ws_url": "wss://evil.example/ws"},
            {**grant("windows"), "extra": True},
        ):
            with self.subTest(case=str(value)[:65]), \
                 self.assertRaises(pairing.EnrollmentDenied):
                pairing.poll(one, post=lambda *_: (200, enc(value)),
                             sleep=lambda _: None, monotonic=lambda: 0)

    def test_untrusted_start_shape_duplicate_keys_and_unexpected_code_denied(self):
        data = pending()
        cases = [
            (200, b""), (200, b'{"device_code":"a","device_code":"b"}'),
            (200, enc({**data, "user_code": "A0B0-2345"})),
            (200, enc({**data, "interval": False})),
            (200, enc({**data, "expires_in": 0})),
            (200, enc({**data, "owner_confirmed": True})),
            (500, enc(data)), (200, b"x"*10000),
        ]
        for status, raw in cases:
            with self.subTest(status=status, body=raw[:60]), \
                 self.assertRaises(pairing.EnrollmentDenied):
                pairing.start("windows", post=lambda *_: (status, raw))

    def test_no_new_remote_server_or_network_by_default(self):
        with self.assertRaises(pairing.EnrollmentDenied):
            pairing.start("foreign", post=lambda *_: (_ for _ in ()).throw(
                AssertionError("unexpected network")))
        with self.assertRaises(pairing.EnrollmentDenied):
            pairing.start("windows", post=lambda *_: (_ for _ in ()).throw(
                OSError("Bearer brc_dev_private_data")))


if __name__ == "__main__":
    unittest.main()
