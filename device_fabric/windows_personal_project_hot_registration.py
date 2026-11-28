"""Prepare one owner-selected Windows project for a local worker reload.

The trusted host supplies the configuration, project validation and durable
transaction callbacks. This module never starts a task or handles a credential.
An unconfirmed commit must not be retried automatically.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import threading
from typing import Callable
import uuid

NAME = 'connect_original_windows_project'
BACKUP = re.compile(r'project-registration-[a-f0-9]{32}\Z')
SCHEMA = {'name': NAME, 'description': 'Plan or register one original Windows project; execution reconnects the device.',
          'inputSchema': {'type': 'object', 'properties': {
              'path': {'type': 'string'}, 'mode': {'type': 'string', 'enum': ['plan', 'execute']}},
              'required': ['path', 'mode'], 'additionalProperties': False}}


def _reply(status: str, *, error: bool = False, **fields) -> dict:
    return {'content': [{'type': 'text', 'text': json.dumps({'status': status, **fields},
               sort_keys=True, separators=(',', ':'))}], 'isError': error}


def commit_config(private: Path, owner_sid: str, old: bytes, new: bytes) -> str:
    """Store both sealed configurations privately before one checked swap."""
    from device_fabric import windows_personal_project_registration as transaction
    from device_fabric.windows_personal_yfc_psec import _real_directory
    from scripts.h454_windows_personal_state import _create_private_directory
    if (not isinstance(private, Path) or not private.is_absolute() or type(owner_sid) is not str
        or type(old) is not bytes or not old or type(new) is not bytes or not new or old == new):
        raise ValueError('registration_denied')
    _real_directory(private)
    lock = private / 'project-registration.lock'
    _create_private_directory(lock, owner_sid)
    identity = lock.lstat()
    try:
        config_path = private / 'device.json'
        if config_path.is_symlink() or config_path.read_bytes() != old:
            raise ValueError('configuration_changed')
        backup = private / ('project-registration-' + uuid.uuid4().hex)
        _create_private_directory(backup, owner_sid)
        transaction._write_once(backup / 'old-device.json', old)
        transaction._write_once(backup / 'new-device.json', new)
        transaction._replace(config_path, old, new, config_path.with_name('device.json.h454-add.tmp'))
        return backup.name
    finally:
        try:
            actual = lock.lstat()
            if (actual.st_dev, actual.st_ino) == (identity.st_dev, identity.st_ino):
                os.rmdir(lock)
        except Exception:
            pass


class WindowsProjectRegistration:
    """Serialize a plan/commit, and request a fresh worker after a commit."""

    def __init__(self, original: bytes, *, prepare: Callable, validate: Callable,
                 commit: Callable, read_current: Callable, has_sessions: Callable):
        if (type(original) is not bytes or not original
            or not all(callable(value) for value in (prepare, validate, commit, read_current, has_sessions))):
            raise ValueError('registration_denied')
        self._original = original
        self._prepare, self._validate, self._commit = prepare, validate, commit
        self._read_current, self._has_sessions = read_current, has_sessions
        self._lock = threading.Lock()
        self._pending = False

    def reload_pending(self) -> bool:
        return self._pending

    def dispatch(self, args: dict) -> dict:
        if not self._lock.acquire(blocking=False):
            return _reply('refused', error=True, reason='registration_busy')
        try:
            if (self._pending or type(args) is not dict or set(args) != {'path', 'mode'}
                or type(args['path']) is not str or not 0 < len(args['path']) <= 2048
                or args['mode'] not in ('plan', 'execute')):
                return _reply('refused', error=True, reason='invalid_request')
            if self._read_current() != self._original:
                return _reply('refused', error=True, reason='configuration_changed')
            candidate = self._prepare(self._original, args['path'])
            if type(candidate) is not bytes or not candidate:
                raise ValueError()
            if candidate == self._original:
                return _reply('already_configured')
            self._validate(candidate)
            if args['mode'] == 'plan':
                return _reply('plan_pass')
            if self._has_sessions() is not False:
                return _reply('refused', error=True, reason='active_sessions')
            try:
                backup = self._commit(self._original, candidate)
                if type(backup) is not str or BACKUP.fullmatch(backup) is None:
                    raise ValueError()
                self._pending = True
                return _reply('applied', backup=backup, verification_required=True)
            except Exception:
                # A write or response failure cannot be assumed to have had no effect.
                try:
                    current = self._read_current()
                    if current == candidate:
                        self._pending = True
                    elif current != self._original:
                        self._pending = True
                except Exception:
                    self._pending = True
                return _reply('unknown', error=True, reason='operation_unconfirmed_do_not_retry')
        except Exception:
            return _reply('refused', error=True, reason='registration_denied')
        finally:
            self._lock.release()

    def close(self) -> None:
        pass
