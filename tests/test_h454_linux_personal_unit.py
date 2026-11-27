"""Generated units restrict credentials, writable roots and network scope."""
import unittest

from scripts.h454_linux_personal_unit import render


class PersonalLinuxUnitTests(unittest.TestCase):
    def setUp(self):
        self.options = dict(target='yfc-vps', release_sha='a' * 40, dependency_sha='b' * 40,
                            project='/srv/yfc/project with spaces', project_group='yfc-deploy')

    def test_yfc_unit_has_project_scope_and_private_unix_network(self):
        unit = render(**self.options)
        self.assertIn('User=hermes-commander-personal\n', unit)
        self.assertIn('NoNewPrivileges=yes\nCapabilityBoundingSet=\n', unit)
        self.assertIn('PrivateNetwork=yes\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\n', unit)
        self.assertIn('ReadWritePaths="/srv/yfc/project with spaces" ', unit)
        self.assertIn('SupplementaryGroups=hermes-commander-native yfc-deploy\n', unit)
        self.assertNotIn('IPAddressAllow=', unit)

    def test_hermes_unit_only_allows_the_approved_private_relay(self):
        self.options.update(target='hermes-vps', relay_ip='172.20.0.7')
        unit = render(**self.options)
        self.assertIn('IPAddressDeny=any\nIPAddressAllow=172.20.0.7/32\n', unit)
        self.assertIn('RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6\n', unit)
        self.assertNotIn('SupplementaryGroups=hermes-commander-native', unit)

    def test_untrusted_paths_groups_and_relay_addresses_are_rejected(self):
        for changes in ({'project': '/srv/second-brain'}, {'project': '/tmp/project\nUser=root'},
                        {'project_group': 'wheel\nUser=root'}, {'relay_ip': '127.0.0.1'},
                        {'target': 'hermes-vps', 'relay_ip': '8.8.8.8'}, {'release_sha': 'x' * 40}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                render(**{**self.options, **changes})

    def test_systemd_specifiers_and_quotes_are_escaped(self):
        self.options['project'] = '/srv/yfc/proj%t "x"'
        unit = render(**self.options)
        self.assertIn('ReadWritePaths="/srv/yfc/proj%%t \\"x\\"" ', unit)


if __name__ == '__main__':
    unittest.main()
