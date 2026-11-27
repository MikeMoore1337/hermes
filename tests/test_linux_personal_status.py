"""The personal Linux status client requires the exact current grant."""
import json
import ssl
import unittest
from unittest.mock import MagicMock, patch

from device_fabric import linux_personal_status as status
from device_fabric.native_private_tls import PrivateRelay


class PersonalLinuxStatusTests(unittest.TestCase):
    def setUp(self):
        self.config = PrivateRelay('yfc-vps', 'a' * 40, 'unix:/fixture', b'fixture')
        self.ident = 'h454-linux-personal-yfc-' + 'b' * 32
        self.bearer = 'brc_dev_' + 'c' * 64
        self.packet = json.dumps({'schema': status.SCHEMA, 'device_id': self.ident,
                                  'active': True, 'owner_bound': True},
                                 separators=(',', ':')).encode('ascii')

    def state(self, code=200, raw=None, content_type='application/json'):
        secure, response = MagicMock(), MagicMock()
        response.status = code
        response.getheader.side_effect = lambda name: content_type if name == 'Content-Type' else None
        response.read.return_value = self.packet if raw is None else raw
        connection = MagicMock()
        connection.__enter__.return_value = secure
        with patch.object(status.private, '_connection', return_value=connection), \
             patch.object(status.http.client, 'HTTPResponse', return_value=response):
            result = status.bearer_state(self.config, target='yfc-vps', device_id=self.ident,
                                         bearer=self.bearer)
        return result, secure

    def test_active_current_grant_and_denials(self):
        result, secure = self.state()
        self.assertIs(result, True)
        self.assertIn(('Bearer ' + self.bearer).encode(), secure.sendall.call_args.args[0])
        self.assertIs(self.state(code=403)[0], False)
        self.assertIsNone(self.state(code=503)[0])
        self.assertIs(self.state(raw=self.packet.replace(b'"active":true', b'"active":false'))[0], False)
        self.assertIs(self.state(raw=self.packet.replace(b'"active":true', b'"active":true,"active":true'))[0], False)
        self.assertIs(self.state(content_type='text/plain')[0], False)

    def test_cross_host_or_wrong_identity_is_refused_without_network(self):
        with patch.object(status.private, '_connection') as connect:
            for target, ident in (('hermes-vps', self.ident),
                                  ('yfc-vps', 'h454-linux-personal-hermes-' + 'b' * 32),
                                  ('yfc-vps', 'h454-linux-yfc-' + 'b' * 32)):
                with self.subTest(target=target, ident=ident):
                    self.assertIs(status.bearer_state(self.config, target=target, device_id=ident,
                                                      bearer=self.bearer), False)
            connect.assert_not_called()

    def test_tls_failure_and_temporary_network_failure_are_distinct(self):
        for failure, expected in ((ssl.SSLError(), False), (OSError(), None)):
            with self.subTest(failure=type(failure)), \
                 patch.object(status.private, '_connection', side_effect=failure):
                self.assertIs(status.bearer_state(self.config, target='yfc-vps', device_id=self.ident,
                                                  bearer=self.bearer), expected)


if __name__ == '__main__':
    unittest.main()
