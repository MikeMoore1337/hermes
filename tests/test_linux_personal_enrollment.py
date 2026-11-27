"""Linux personal enrollment accepts only owner-bound host-specific IDs."""
import json
import unittest

from device_fabric import linux_personal_enrollment as enrollment

CODE = 'a' * 48
TOKEN = 'brc_dev_' + 'b' * 64
URL = 'wss://hermes.mikemoore.top/ws'


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode('ascii')


def pending_packet():
    return {'device_code': CODE, 'user_code': 'ABCD-2345', 'verification_uri': 'local',
            'verification_uri_complete': 'local', 'expires_in': 900, 'interval': 3}


def paired_packet(ident):
    return {'device_token': TOKEN, 'device_id': ident, 'token_type': 'bearer', 'ws_url': URL}


class LinuxPersonalEnrollmentTests(unittest.TestCase):
    def test_each_host_polls_only_its_owner_selected_identity(self):
        for target, suffix in (('hermes-vps', 'hermes'), ('yfc-vps', 'yfc')):
            with self.subTest(target=target):
                requests = []
                def post_start(path, raw):
                    requests.append((path, json.loads(raw)))
                    return 200, encoded(pending_packet())
                pending = enrollment.start(target, post=post_start)
                self.assertEqual(requests, [('/device/start', {'client_name': enrollment.NAMES[target]})])
                requests.clear()
                ident = 'h454-linux-personal-' + suffix + '-' + 'c' * 32
                def post_poll(path, raw):
                    requests.append((path, json.loads(raw)))
                    return 200, encoded(paired_packet(ident))
                paired = enrollment.poll(pending, post=post_poll, expected_ws_url=URL)
                self.assertEqual(paired.device_id, ident)
                self.assertNotIn(TOKEN, repr(paired))
                self.assertEqual(requests, [('/device/poll', {'device_code': CODE,
                    'name': enrollment.NAMES[target], 'platform': 'linux'})])

    def test_read_only_cross_host_or_foreign_relay_are_denied(self):
        pending = enrollment.start('yfc-vps', post=lambda *_: (200, encoded(pending_packet())))
        for ident, url in (('h454-linux-yfc-' + 'c' * 32, URL),
                           ('h454-linux-personal-hermes-' + 'c' * 32, URL),
                           ('h454-linux-personal-yfc-' + 'c' * 32, 'wss://foreign.invalid/ws')):
            with self.subTest(ident=ident, url=url), self.assertRaises(enrollment.EnrollmentDenied):
                enrollment.poll(pending, post=lambda *_: (200, encoded(paired_packet(ident))),
                                expected_ws_url=url)

    def test_pending_poll_has_a_strict_call_limit(self):
        pending = enrollment.start('hermes-vps', post=lambda *_: (200, encoded(pending_packet())))
        calls = []
        def waiting(*_args):
            calls.append(True)
            return 400, encoded({'error': 'authorization_pending', 'interval': 3})
        with self.assertRaises(enrollment.EnrollmentDenied):
            enrollment.poll(pending, post=waiting, expected_ws_url=URL,
                            sleep=lambda _seconds: None, monotonic=lambda: 0)
        self.assertEqual(len(calls), enrollment.MAX_POLLS)


if __name__ == '__main__':
    unittest.main()
