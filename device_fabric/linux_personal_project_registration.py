"""Prepare an explicitly scoped additional original Linux project.

These pure functions do not read a project, change access, or restart systemd.
The root-owned operator must independently verify host paths and permissions.
"""
from __future__ import annotations

import json
from typing import Callable

from device_fabric import linux_personal_config as config
from device_fabric.linux_personal_sandbox import validate_projects
from scripts.h454_linux_personal_unit import _quote


class ProjectRegistrationDenied(ValueError):
    """Do not include local paths or configuration in errors."""


class ProjectRollbackFailed(ProjectRegistrationDenied):
    """The protected backup must be used for manual recovery."""


def _canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def prepare(raw: bytes, unit: bytes, *, target: str, name: str, project: str) -> tuple[bytes, bytes]:
    """Add one independent root, preserving device identity and all other unit settings."""
    try:
        current = config.parse(raw, target=target)
        if type(unit) is not bytes or not 0 < len(unit) <= 65536 or b'\r' in unit:
            raise ValueError()
        text = unit.decode('utf-8')
        if not text.endswith('\n'):
            raise ValueError()
        existing = current.additional_projects
        unchanged = False
        if any(existing_name == name or existing_path == project for existing_name, existing_path in existing):
            if (name, project) in existing:
                unchanged = True
            else:
                raise ValueError()
        projects = existing if unchanged else tuple(sorted((*existing, (name, project))))
        validate_projects(current.project, projects)
        state = '/var/lib/hermes-commander-personal/' + target
        def line(roots):
            return 'ReadWritePaths=' + ' '.join(_quote(value) for value in
                (current.project, *(path for _, path in roots))) + ' ' + state
        old_line, new_line = line(existing), line(projects)
        lines = text.splitlines()
        matching = [index for index, value in enumerate(lines) if value.startswith('ReadWritePaths=')]
        if len(matching) != 1 or lines[matching[0]] != old_line:
            raise ValueError()
        for required in ('User=hermes-commander-personal', 'Group=hermes-commander-personal',
                         'NoNewPrivileges=yes', 'ProtectSystem=strict',
                         'ExecStart=/usr/bin/python3 -B -m scripts.h454_linux_personal_service --target ' + target):
            if lines.count(required) != 1:
                raise ValueError()
        if unchanged:
            return raw, unit
        lines[matching[0]] = new_line
        data = json.loads(raw.decode('ascii'))
        data['schema'] = config.MULTI_SCHEMA
        data['projects'] = [{'name': item_name, 'path': path} for item_name, path in projects]
        result = _canonical(data)
        parsed = config.parse(result, target=target)
        if parsed.additional_projects != projects:
            raise ValueError()
        return result, ('\n'.join(lines) + '\n').encode('utf-8')
    except Exception:
        raise ProjectRegistrationDenied('linux_project_registration_denied') from None


def apply(old_config: bytes, old_unit: bytes, new_config: bytes, new_unit: bytes, *,
          backup: Callable[[bytes, bytes, bytes, bytes], None],
          read: Callable[[], tuple[bytes, bytes]],
          replace_config: Callable[[bytes, bytes], None], replace_unit: Callable[[bytes, bytes], None],
          stop: Callable[[], None], reload: Callable[[], None], start: Callable[[], None],
          healthy: Callable[[], bool]) -> None:
    """Apply both validated files with checked restoration after a detected failure."""
    callbacks = (backup, read, replace_config, replace_unit, stop, reload, start, healthy)
    if (not all(callable(fn) for fn in callbacks) or
        not all(type(value) is bytes and value for value in (old_config, old_unit, new_config, new_unit)) or
        old_config == new_config or old_unit == new_unit or read() != (old_config, old_unit)):
        raise ProjectRegistrationDenied('linux_registration_precondition')
    backup(old_config, old_unit, new_config, new_unit)
    try:
        stop()
        replace_unit(old_unit, new_unit)
        replace_config(old_config, new_config)
        reload()
        start()
        if healthy() is not True:
            raise ValueError()
    except BaseException:
        try:
            stop()
            current_config, current_unit = read()
            if current_config == new_config:
                replace_config(new_config, old_config)
            elif current_config != old_config:
                raise ValueError()
            if current_unit == new_unit:
                replace_unit(new_unit, old_unit)
            elif current_unit != old_unit:
                raise ValueError()
            reload()
            start()
            if healthy() is not True:
                raise ValueError()
        except BaseException:
            raise ProjectRollbackFailed('linux_registration_rollback_failed') from None
        raise ProjectRegistrationDenied('linux_registration_rolled_back') from None
