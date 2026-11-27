"""Transactional update of an already verified personal-device config.

The caller supplies the trusted directory, a verified new config, exclusive
operation lock, and task controls. No token is logged or returned.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Callable


class RegistrationDenied(ValueError):
    """Do not include project paths, credentials or platform diagnostics."""


class RegistrationRollbackFailed(RegistrationDenied):
    """Automatic recovery failed and requires the preserved backup."""


def _write_once(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _replace(path: Path, expected: bytes, updated: bytes, temporary: Path) -> None:
    if path.is_symlink() or path.read_bytes() != expected:
        raise RegistrationDenied('registration_state_drift')
    _write_once(temporary, updated)
    if path.is_symlink() or path.read_bytes() != expected:
        raise RegistrationDenied('registration_state_drift')
    os.replace(temporary, path)


def apply(config_path: Path, backup_dir: Path, old: bytes, new: bytes, *,
          stop: Callable[[], None], start: Callable[[], None],
          verify: Callable[[], bool]) -> None:
    """Back up and replace config once; restore and restart on any failure.

    The backup directory is newly created and private before this call.
    A sudden process or host failure leaves both configs for explicit recovery.
    """
    if (not isinstance(config_path, Path) or not isinstance(backup_dir, Path)
        or type(old) is not bytes or not old or type(new) is not bytes or not new or old == new
        or not all(callable(fn) for fn in (stop, start, verify))
        or config_path.is_symlink() or config_path.read_bytes() != old):
        raise RegistrationDenied('registration_precondition')
    _write_once(backup_dir / 'old-device.json', old)
    _write_once(backup_dir / 'new-device.json', new)
    touched = False
    try:
        touched = True
        stop()
        _replace(config_path, old, new, config_path.with_name('device.json.h454-add.tmp'))
        start()
        if verify() is not True:
            raise RegistrationDenied('registration_not_online')
    except BaseException:
        if touched:
            try:
                stop()
                current = config_path.read_bytes()
                if current == new:
                    _replace(config_path, new, old, config_path.with_name('device.json.h454-restore.tmp'))
                elif current != old:
                    raise RegistrationDenied('registration_state_drift')
                start()
                if verify() is not True:
                    raise RegistrationDenied('registration_restore_not_online')
            except BaseException:
                raise RegistrationRollbackFailed('registration_rollback_failed') from None
        raise RegistrationDenied('registration_rolled_back') from None
