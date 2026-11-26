"""Private status checks use only synthetic connections and credentials."""
import json
import ssl
import unittest
from unittest.mock import Mock, patch

from device_fabric import native_private_tls as private
from device_fabric import windows_personal_commander_status as status

DEVICE = "h454-win-personal-" + "a" * 32
TOKEN = "brc_dev_" + "b" * 64
RELAY = private.PrivateRelay("windows", "c" * 40, private.WINDOWS_LOOPBACK, b"synthetic-ca")


def body(**changes):
    data = {"schema": status.SCHEMA, "device_id": DEVICE, "active": True, "owner_bound": True}
    data.update(changes)
    return json.dumps(data, separators=(",", ":")).encode("ascii")


class PersonalStatusTests(unittest.TestCase):
    def call(self, *, code=200, raw=None, exception=None):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        response = Mock(status=code)
        response.getheader.side_effect = lambda key: "application/json" if key == "Content-Type" else None
        response.read.return_value = body() if raw is None else raw
        with patch.object(private, "_connection", side_effect=exception or (lambda *_: connection)) as connect, \
             patch.object(status.http.client, "HTTPResponse", return_value=response):
            result = status.bearer_state(RELAY, device_id=DEVICE, bearer=TOKEN)
        return result, connect

    def test_current_personal_owner_bearer(self):
        result, connect = self.call()
        self.assertIs(result, True)
        connect.assert_called_once()

    def test_revoked_invalid_or_wrong_profile_denied(self):
        for code, raw in ((403, body()), (200, body(owner_bound=False)),
                          (200, body(device_id="h454-win-native-" + "a" * 32)),
                          (200, b"not-json")):
            with self.subTest(code=code, raw=raw):
                self.assertIs(self.call(code=code, raw=raw)[0], False)
        with patch.object(private, "_connection") as connect:
            self.assertFalse(status.bearer_state(RELAY, device_id="h454-win-native-" + "a" * 32,
                                                bearer=TOKEN))
            connect.assert_not_called()

    def test_temporary_outage_differs_from_tls_identity_failure(self):
        self.assertIsNone(self.call(code=503)[0])
        self.assertIsNone(self.call(exception=OSError("synthetic"))[0])
        self.assertIs(self.call(exception=ssl.SSLError("synthetic"))[0], False)


if __name__ == "__main__":
    unittest.main()
