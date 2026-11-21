"""The YFC forward is a fixed, private, pinned SSH service candidate."""
import shlex
import shutil
import subprocess
import sys
import unittest

from scripts.h454_native_yfc_tunnel_unit import YfcTunnelDenied, render_tunnel_unit


class TunnelUnitTests(unittest.TestCase):
    def test_fixed_identity_socket_host_key_and_egress(self):
        text=render_tunnel_unit(ssh_ipv4='8.8.8.8',relay_ipv4='172.29.251.2')
        for item in ('User=hermes-commander-tunnel\n', 'Group=hermes-commander-native\n',
                     'RuntimeDirectoryMode=0750\n', 'IPAddressDeny=any\n',
                     'IPAddressAllow=8.8.8.8/32\n', 'StrictHostKeyChecking=yes',
                     'UserKnownHostsFile=/etc/hermes-commander-tunnel/known_hosts',
                     'IdentityAgent=none', 'StreamLocalBindMask=0117',
                     'ClearAllForwardings=no', 'ExitOnForwardFailure=yes', 'ForwardAgent=no',
                     '/run/hermes-commander-tunnel/relay.sock:172.29.251.2:3001',
                     'hermes-yfc-forward@8.8.8.8'):
            self.assertIn(item,text)
        self.assertEqual(len([x for x in text.splitlines() if x.startswith('IPAddressAllow=')]),1)

    def test_untrusted_or_public_relay_addresses_are_denied(self):
        for ssh,relay in (('127.0.0.1','172.29.251.2'),('224.0.0.1','172.29.251.2'),('8.8.8.8','8.8.4.4'),
                          ('8.8.8.8;id','172.29.251.2'),('8.8.8.8','172.29.251.2\nUser=root'),
                          ('8.8.8.8','127.0.0.1'),(None,'172.29.251.2')):
            with self.subTest(ssh=ssh,relay=relay), self.assertRaises(YfcTunnelDenied):
                render_tunnel_unit(ssh_ipv4=ssh,relay_ipv4=relay)

    @unittest.skipUnless(sys.platform == 'linux' and shutil.which('ssh'), 'Linux OpenSSH required')
    def test_openssh_keeps_exactly_one_local_forward(self):
        text=render_tunnel_unit(ssh_ipv4='8.8.8.8',relay_ipv4='172.29.251.2')
        command=next(x.removeprefix('ExecStart=') for x in text.splitlines() if x.startswith('ExecStart='))
        args=shlex.split(command)
        result=subprocess.run([args[0],'-G',*args[1:]],capture_output=True,text=True,timeout=8,check=True)
        forwards=[x for x in result.stdout.splitlines() if x.startswith('localforward ')]
        self.assertEqual(forwards,['localforward /run/hermes-commander-tunnel/relay.sock [172.29.251.2]:3001'])


if __name__ == '__main__':
    unittest.main()
