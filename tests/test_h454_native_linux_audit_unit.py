"""The YFC audit socket exposes one fixed systemd query, never commands."""
import unittest

from device_fabric.native_private_tls import AUDIT_SOCKET
from scripts.h454_native_linux_audit_unit import render_audit_units
from scripts.h454_native_linux_service import SHOW_KEYS, UNIT


class AuditUnitTests(unittest.TestCase):
    def test_fixed_socket_and_unprivileged_fixed_query(self):
        listener, worker = render_audit_units()
        self.assertIn('ListenStream=' + AUDIT_SOCKET + '\n', listener)
        self.assertIn('SocketUser=root\nSocketGroup=hermes-commander-native\nSocketMode=0660\n', listener)
        self.assertIn('Accept=yes\nMaxConnections=4\n', listener)
        self.assertIn('User=hermes-commander-audit\nGroup=hermes-commander-audit\nNoNewPrivileges=yes\nCapabilityBoundingSet=\n', worker)
        self.assertIn('PrivateNetwork=yes\nRestrictAddressFamilies=AF_UNIX\nIPAddressDeny=any\n', worker)
        self.assertIn('StandardInput=null\nStandardOutput=socket\nStandardError=null\n', worker)
        self.assertEqual([x for x in worker.splitlines() if x.startswith('ExecStart=')],
            ['ExecStart=/usr/bin/systemctl show ' + UNIT + ' --no-pager --property=' + ','.join(SHOW_KEYS)])


if __name__ == '__main__':
    unittest.main()
