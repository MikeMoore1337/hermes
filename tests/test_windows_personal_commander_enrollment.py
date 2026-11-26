"""Personal Commander pairing remains separate from the pinned READ client."""
import json
import unittest

from device_fabric import windows_personal_commander_enrollment as pairing

CODE = "a" * 48
TOKEN = "brc_dev_" + "b" * 64
DEVICE = "h454-win-personal-" + "c" * 32
URL = "wss://hermes.mikemoore.top/ws"


def encode(data):
    return json.dumps(data, separators=(",", ":")).encode("ascii")


def pending():
    return {"device_code": CODE, "user_code": "ABCD-2345", "verification_uri": "local",
            "verification_uri_complete": "local", "expires_in": 900, "interval": 3}


def result(device=DEVICE):
    return {"device_token": TOKEN, "device_id": device, "token_type": "bearer", "ws_url": URL}


class WindowsPersonalCommanderEnrollmentTests(unittest.TestCase):
    def test_owner_bound_id_is_polled_without_an_agent_selected_id(self):
        requests = []
        def start(path, raw):
            requests.append((path, json.loads(raw)))
            return 200, encode(pending())
        code = pairing.start(post=start)
        self.assertEqual(requests, [("/device/start", {"client_name": pairing.NAME})])
        self.assertNotIn(CODE, repr(code))
        requests.clear()
        def poll(path, raw):
            requests.append((path, json.loads(raw)))
            return 200, encode(result())
        device = pairing.poll(code, post=poll, expected_ws_url=URL)
        self.assertEqual(device.device_id, DEVICE)
        self.assertNotIn(TOKEN, repr(device))
        self.assertEqual(requests, [("/device/poll", {"device_code": CODE,
            "name": pairing.NAME, "platform": "win32"})])

    def test_old_read_only_identity_and_foreign_relay_are_denied(self):
        code = pairing.start(post=lambda *_: (200, encode(pending())))
        for response, url in ((result("h454-win-native-" + "c" * 32), URL),
                              (result(), "wss://foreign.invalid/ws")):
            with self.subTest(url=url), self.assertRaises(pairing.EnrollmentDenied):
                pairing.poll(code, post=lambda *_: (200, encode(response)), expected_ws_url=url)

    def test_pending_poll_is_bounded(self):
        code = pairing.start(post=lambda *_: (200, encode(pending())))
        calls = []
        def waiting(*_args):
            calls.append(1)
            return 400, encode({"error": "authorization_pending", "interval": 3})
        with self.assertRaises(pairing.EnrollmentDenied):
            pairing.poll(code, post=waiting, expected_ws_url=URL,
                         sleep=lambda _n: None, monotonic=lambda: 0)
        self.assertEqual(len(calls), pairing.MAX_POLLS)


if __name__ == "__main__":
    unittest.main()
