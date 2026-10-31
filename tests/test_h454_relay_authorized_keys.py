import base64
import hashlib
import unittest

from scripts.h454_relay_authorized_keys import ForwardAuthorizationError, prepare, restricted_second_key


KEY = "ssh-ed25519 " + base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(range(32))).decode()
HOST = "172.20.0.4"
OLD = f'command="/usr/sbin/nologin",restrict,port-forwarding,permitopen="{HOST}:3000"'
NEW = OLD + f',permitopen="{HOST}:3001"'
LINE = f"{OLD} {KEY} fixture"


class RelayForwardAuthorizationTests(unittest.TestCase):
    def prepare(self, source: bytes, **overrides):
        args = {"source_sha256": hashlib.sha256(source).hexdigest(), "public_key": KEY, "relay_ip": HOST}
        args.update(overrides)
        return prepare(source, **args)

    def test_adds_only_exact_second_forward_and_preserves_other_bytes(self):
        other = "ssh-ed25519 " + base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + b"x" * 32).decode()
        source = ("# unrelated\r\n" + other + "\r\n" + LINE + "\r\n# tail without newline").encode()
        result = self.prepare(source)
        self.assertEqual(result, source.replace(LINE.encode(), LINE.replace(OLD, NEW).encode()))

    def test_drift_duplicate_broader_policy_and_untrusted_pins_are_refused(self):
        cases = (
            (LINE + "\n" + LINE + "\n").encode(),
            (LINE + "\n" + KEY.replace(" ", "\t", 1) + "\n").encode(),
            LINE.replace("restrict,port-forwarding,", "").encode(),
            LINE.replace(f'{HOST}:3000', '*:3000').encode(),
            LINE.replace(OLD, NEW).encode(),
            ("# " + LINE).encode(),
            LINE.replace("/usr/sbin/nologin", "/bin/sh").encode(),
        )
        for source in cases:
            with self.subTest(source=source[:32]), self.assertRaises(ForwardAuthorizationError):
                self.prepare(source)
        for args in ({"source_sha256": "0" * 64}, {"relay_ip": "8.8.8.8"},
                     {"relay_ip": "0172.20.0.4"}, {"public_key": "ssh-ed25519 AAAA"},
                     {"public_key": KEY + "\n" + KEY}):
            with self.subTest(args=args), self.assertRaises(ForwardAuthorizationError):
                self.prepare(LINE.encode(), **args)

    def test_distinct_key_only_allows_the_new_private_forward(self):
        result = restricted_second_key(KEY + " comment", HOST)
        self.assertEqual(result, (f'command="/usr/sbin/nologin",restrict,port-forwarding,'
                                  f'permitopen="{HOST}:3001" {KEY}\n').encode())
        for public_key, relay_ip in ((KEY, "8.8.8.8"), (KEY, "0172.20.0.4"),
                                     ("ssh-ed25519 AAAA", HOST), (KEY + "\n" + KEY, HOST)):
            with self.subTest(relay_ip=relay_ip), self.assertRaises(ForwardAuthorizationError):
                restricted_second_key(public_key, relay_ip)


if __name__ == "__main__":
    unittest.main()
