"""Render the fixed, read-only systemd properties socket for YFC."""

from device_fabric.native_private_tls import AUDIT_SOCKET
from scripts.h454_native_linux_service import SHOW_KEYS, UNIT


def render_audit_units() -> tuple[str, str]:
    socket_unit = '\n'.join((
        '[Unit]',
        'Description=Hermes native read-only systemd properties socket',
        '[Socket]',
        'ListenStream=' + AUDIT_SOCKET,
        'SocketUser=root',
        'SocketGroup=hermes-commander-native',
        'SocketMode=0660',
        'DirectoryMode=0755',
        'Accept=yes',
        'MaxConnections=4',
        'RemoveOnStop=yes',
        '[Install]',
        'WantedBy=sockets.target',
        '',
    ))
    service_unit = '\n'.join((
        '[Unit]',
        'Description=Hermes native fixed systemd properties query',
        '[Service]',
        'Type=exec',
        'User=hermes-commander-audit',
        'Group=hermes-commander-audit',
        'NoNewPrivileges=yes',
        'CapabilityBoundingSet=',
        'ProtectSystem=strict',
        'ProtectHome=yes',
        'PrivateTmp=yes',
        'PrivateDevices=yes',
        'PrivateNetwork=yes',
        'RestrictAddressFamilies=AF_UNIX',
        'IPAddressDeny=any',
        'MemoryMax=32M',
        'TasksMax=4',
        'RuntimeMaxSec=8s',
        'Environment=LC_ALL=C PATH=/usr/bin:/bin',
        'StandardInput=null',
        'StandardOutput=socket',
        'StandardError=null',
        'ExecStart=/usr/bin/systemctl show ' + UNIT + ' --no-pager --property=' + ','.join(SHOW_KEYS),
        '',
    ))
    return socket_unit, service_unit
