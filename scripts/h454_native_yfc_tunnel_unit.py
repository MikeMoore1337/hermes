"""Render a disabled, dedicated SSH forward for the YFC native relay."""
import ipaddress

from device_fabric.native_private_tls import UNIX_DIRECTORY, UNIX_SOCKET, _private_ip


class YfcTunnelDenied(ValueError):
    pass


def render_tunnel_unit(*, ssh_ipv4: str, relay_ipv4: str) -> str:
    try:
        if type(ssh_ipv4) is not str or type(relay_ipv4) is not str:
            raise YfcTunnelDenied()
        ip = ipaddress.IPv4Address(ssh_ipv4)
        if str(ip) != ssh_ipv4 or not ip.is_global or ip.is_multicast or not _private_ip(relay_ipv4):
            raise YfcTunnelDenied()
        ssh = [
            '/usr/bin/ssh', '-N', '-T', '-F', '/dev/null',
            '-i', '/var/lib/hermes-commander-tunnel/identity',
            '-o', 'UserKnownHostsFile=/etc/hermes-commander-tunnel/known_hosts',
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
            '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none',
            '-o', 'ClearAllForwardings=no', '-o', 'ExitOnForwardFailure=yes',
            '-o', 'StreamLocalBindMask=0117', '-o', 'StreamLocalBindUnlink=no',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
            '-o', 'ConnectTimeout=10', '-o', 'BatchMode=yes',
            '-o', 'PermitLocalCommand=no', '-o', 'ControlMaster=no',
            '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no',
            '-L', UNIX_SOCKET + ':' + relay_ipv4 + ':3001',
            '-p', '25566', 'hermes-yfc-forward@' + ssh_ipv4,
        ]
        return '\n'.join((
            '[Unit]', 'Description=Hermes YFC restricted private relay tunnel',
            'Wants=network-online.target', 'After=network-online.target',
            'StartLimitIntervalSec=300', 'StartLimitBurst=3',
            '[Service]', 'Type=exec', 'User=hermes-commander-tunnel',
            'Group=hermes-commander-native', 'RuntimeDirectory=' + UNIX_DIRECTORY.rsplit('/', 1)[-1],
            'RuntimeDirectoryMode=0750', 'UMask=0077',
            'ExecStart=' + ' '.join(ssh), 'Restart=always', 'RestartSec=5s',
            "ExecStartPost=/usr/bin/timeout 25 /bin/sh -c 'until /usr/bin/timeout 3 "
            "/usr/bin/openssl s_client -unix /run/hermes-commander-tunnel/relay.sock "
            "-servername brc-agent.internal -verify_hostname brc-agent.internal "
            "-verify_return_error -no-CApath -no-CAstore -CAfile /opt/hermes-commander-native/trust/ca.crt "
            "</dev/null >/dev/null 2>&1; do sleep 1; done'",
            'NoNewPrivileges=yes', 'CapabilityBoundingSet=', 'AmbientCapabilities=',
            'ProtectSystem=strict', 'ProtectHome=yes', 'PrivateTmp=yes', 'PrivateDevices=yes',
            'ProtectControlGroups=yes', 'ProtectKernelTunables=yes', 'ProtectKernelModules=yes',
            'RestrictNamespaces=yes', 'RestrictRealtime=yes', 'LockPersonality=yes',
            'RestrictAddressFamilies=AF_UNIX AF_INET', 'IPAddressDeny=any',
            'IPAddressAllow=' + ssh_ipv4 + '/32', 'MemoryMax=64M', 'CPUQuota=10%', 'TasksMax=8',
            'StandardOutput=journal', 'StandardError=journal',
            '[Install]', 'WantedBy=multi-user.target', '',
        ))
    except (ValueError, TypeError):
        raise YfcTunnelDenied('h454_yfc_tunnel_denied') from None
