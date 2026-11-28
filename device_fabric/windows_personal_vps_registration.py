"""Bounded VPS project registration through the owner's existing SSH setup."""
from __future__ import annotations

import base64
import json
import ntpath
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Callable

from device_fabric.linux_personal_sandbox import _project_path

NAME = 'connect_original_vps_project'
ALIAS = re.compile(r'[a-z][a-z0-9-]{0,63}\Z')
PROJECT = re.compile(r'[a-z][a-z0-9-]{0,63}\Z')
BACKUP = re.compile(r'project-registration-[a-f0-9]{32}\Z')
SCHEMA = {
    'name': NAME,
    'description': 'Plan or connect an existing original project on an owner VPS. No existing project is overwritten.',
    'inputSchema': {'type': 'object', 'properties': {
        'target': {'type': 'string', 'enum': ['hermes-vps', 'yfc-vps']},
        'name': {'type': 'string', 'minLength': 1, 'maxLength': 64},
        'path': {'type': 'string', 'minLength': 1, 'maxLength': 2048},
        'mode': {'type': 'string', 'enum': ['plan', 'execute']},
    }, 'required': ['target', 'name', 'path', 'mode'], 'additionalProperties': False},
}


def _read_bounded(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or getattr(before, 'st_file_attributes', 0) & 0x400
            or not 0 < before.st_size <= maximum):
        raise ValueError('vps_registration_file_denied')
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns')
    if len(data) != before.st_size or any(getattr(before, key) != getattr(opened, key)
                                          or getattr(opened, key) != getattr(after, key) for key in keys):
        raise ValueError('vps_registration_file_denied')
    return data


def from_owner_state(private: Path, release: Path, *, system_root: str) -> 'VpsProjectRegistration | None':
    """Load optional owner-local host aliases; no secret or endpoint is bundled."""
    from device_fabric.windows_personal_yfc_psec import _real_directory
    if not isinstance(private, Path) or not isinstance(release, Path) or not ntpath.isabs(system_root):
        raise ValueError('vps_registration_config_denied')
    config_path = private / 'vps-registration.json'
    if not config_path.exists() and not config_path.is_symlink():
        return None
    _real_directory(private)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError()
            result[key] = value
        return result
    obj = json.loads(_read_bounded(config_path, 4096).decode('ascii'), object_pairs_hook=unique)
    if type(obj) is not dict or set(obj) != {'schema', 'aliases'} or obj['schema'] != 'h454-vps-registration-v1':
        raise ValueError('vps_registration_config_denied')
    source = release / 'code' / 'device_fabric' / 'linux_personal_remote_operator.py'
    for directory in (release, source.parent.parent, source.parent):
        _real_directory(directory)
    return VpsProjectRegistration(obj['aliases'], _read_bounded(source, 32768),
        ssh=ntpath.join(system_root, 'System32', 'OpenSSH', 'ssh.exe'))


class VpsProjectRegistration:
    """Call one fixed, pinned remote operator; no shell-supplied user values."""

    def __init__(self, aliases: dict[str, str], remote_source: bytes, *,
                 ssh: str, run: Callable = subprocess.run):
        if (type(aliases) is not dict or set(aliases) != {'hermes-vps', 'yfc-vps'}
                or any(type(v) is not str or ALIAS.fullmatch(v) is None for v in aliases.values())
                or len(set(aliases.values())) != 2 or type(remote_source) is not bytes
                or not 0 < len(remote_source) <= 32768 or type(ssh) is not str
                or not ntpath.isabs(ssh) or not ssh.lower().endswith('\\openssh\\ssh.exe')
                or not callable(run)):
            raise ValueError('vps_registration_invalid')
        compile(remote_source, 'linux_personal_remote_operator', 'exec')
        self._aliases = dict(aliases)
        self._source = remote_source
        self._ssh = ssh
        self._run = run

    def dispatch(self, args: dict) -> dict:
        attempted = False
        try:
            if (type(args) is not dict or set(args) != {'target', 'name', 'path', 'mode'}
                    or args['target'] not in self._aliases or type(args['name']) is not str
                    or PROJECT.fullmatch(args['name']) is None or args['mode'] not in ('plan', 'execute')):
                raise ValueError()
            _project_path(args['path'])
            # The service has PrivateTmp=yes, so host /tmp directories cannot
            # be mounted into its namespace and are unsuitable as durable roots.
            if args['path'].startswith('/tmp/'):
                raise ValueError()
            request = json.dumps(args, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
            if len(request) > 8192:
                raise ValueError()
            encoded = base64.b64encode(self._source).decode('ascii')
            command = "python3 -I -B -c 'import base64;exec(compile(base64.b64decode(\"" + encoded + "\"),\"operator\",\"exec\"))'"
            try:
                attempted = True
                result = self._run([self._ssh, '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                    '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=10', self._aliases[args['target']], command],
                    input=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), check=False)
            except (OSError, subprocess.TimeoutExpired):
                # An interrupted SSH command can have changed the remote host.
                return self._reply({'status': 'unknown', 'reason': 'connection_interrupted'}, error=True)
            if type(result.stdout) is not bytes or type(result.stderr) is not bytes or len(result.stdout) > 4096 or len(result.stderr) > 4096:
                return self._reply({'status': 'unknown', 'reason': 'unrecognized_operator_result'}, error=True)
            try:
                out = result.stdout.decode('ascii', 'strict').strip()
            except UnicodeError:
                return self._reply({'status': 'unknown', 'reason': 'unrecognized_operator_result'}, error=True)
            if result.returncode == 255:
                return self._reply({'status': 'unknown', 'reason': 'connection_interrupted'}, error=True)
            if result.returncode == 0 and out == 'H454_LINUX_PROJECT=PLAN_PASS' and args['mode'] == 'plan':
                return self._reply({'status': 'plan_pass'})
            if result.returncode == 0 and out == 'H454_LINUX_PROJECT=ALREADY_CONFIGURED':
                return self._reply({'status': 'already_configured', 'verification_required': True})
            prefix = 'H454_LINUX_PROJECT=TASK_STARTED REMOTE_ACCESS=NOT_VERIFIED BACKUP='
            if result.returncode == 0 and args['mode'] == 'execute' and out.startswith(prefix):
                backup = out[len(prefix):]
                if BACKUP.fullmatch(backup) is None:
                    return self._reply({'status': 'unknown', 'reason': 'unrecognized_operator_result'}, error=True)
                return self._reply({'status': 'applied', 'backup': backup, 'verification_required': True})
            if b'ROLLBACK=FAILED' in result.stderr:
                return self._reply({'status': 'failed', 'reason': 'rollback_failed'}, error=True)
            if (result.returncode == 2 and (b'H454_LINUX_PROJECT=HOLD' in result.stderr
                                            or b'H454_REMOTE_PROJECT=HOLD' in result.stderr)):
                return self._reply({'status': 'failed', 'reason': 'registration_denied'}, error=True)
            return self._reply({'status': 'unknown', 'reason': 'unrecognized_operator_result'}, error=True)
        except Exception:
            if attempted:
                return self._reply({'status': 'unknown', 'reason': 'unrecognized_operator_result'}, error=True)
            return self._reply({'status': 'refused', 'reason': 'invalid_request'}, error=True)

    @staticmethod
    def _reply(value: dict, *, error: bool = False) -> dict:
        return {'content': [{'type': 'text', 'text': json.dumps(value, separators=(',', ':'))}], 'isError': error}

    def close(self) -> None:
        pass
