"""Render a disabled personal Linux unit; no filesystem or systemd changes."""
from __future__ import annotations

import re

from device_fabric.linux_personal_config import SHA40
from device_fabric.linux_personal_sandbox import _project_path
from device_fabric.native_private_tls import _private_ip
from scripts.h454_linux_personal_service import UNITS

GROUP = re.compile(r'[a-z_][a-z0-9_-]{0,31}\Z')


def _quote(value: str) -> str:
    if (type(value) is not str or not value or
            any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
        raise ValueError('personal_linux_unit_denied')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'


def render(*, target: str, release_sha: str, dependency_sha: str, project: str,
           project_group: str, relay_ip: str | None = None) -> str:
    """Prepare a root-installed unit using exactly one owner-selected root."""
    try:
        if (target not in UNITS or type(release_sha) is not str or SHA40.fullmatch(release_sha) is None or
            type(dependency_sha) is not str or SHA40.fullmatch(dependency_sha) is None or
            type(project_group) is not str or GROUP.fullmatch(project_group) is None):
            raise ValueError()
        _project_path(project)
        project_arg = _quote(project)
        if target == 'yfc-vps':
            if relay_ip is not None:
                raise ValueError()
            network = 'PrivateNetwork=yes\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\n'
            groups = 'hermes-commander-native ' + project_group
        else:
            if type(relay_ip) is not str or not _private_ip(relay_ip):
                raise ValueError()
            network = ('PrivateNetwork=no\nRestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6\n'
                       'IPAddressDeny=any\nIPAddressAllow=' + relay_ip + '/32\n')
            groups = project_group
        release = '/opt/hermes-commander-personal/releases/main-' + release_sha
        deps = '/opt/hermes-commander-native/deps/main-' + dependency_sha
        return ('[Unit]\nDescription=Hermes personal Commander (' + target + ')\n'
            'After=network.target\n\n[Service]\nType=simple\n'
            'User=hermes-commander-personal\nGroup=hermes-commander-personal\n'
            'SupplementaryGroups=' + groups + '\n'
            'WorkingDirectory=' + release + '\n'
            'Environment=PYTHONPATH=' + deps + '\nEnvironment=PYTHONNOUSERSITE=1\n'
            'Environment=PYTHONDONTWRITEBYTECODE=1\n'
            'ExecStart=/usr/bin/python3 -B -m scripts.h454_linux_personal_service --target ' + target + '\n'
            'Restart=on-failure\nRestartSec=5\nNoNewPrivileges=yes\nCapabilityBoundingSet=\n'
            'ProtectSystem=strict\nPrivateTmp=yes\nPrivateDevices=yes\n'
            'RestrictNamespaces=user mnt pid net ipc uts cgroup\n' + network +
            'ReadWritePaths=' + project_arg + ' /var/lib/hermes-commander-personal/' + target + '\n'
            'UMask=0077\nTasksMax=128\nMemoryMax=1G\n'
            'StandardInput=null\nStandardOutput=journal\nStandardError=journal\n\n'
            '[Install]\nWantedBy=multi-user.target\n')
    except Exception:
        raise ValueError('personal_linux_unit_denied') from None
