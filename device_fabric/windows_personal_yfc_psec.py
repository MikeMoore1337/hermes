"""Owner-selected YFC dev PSEC scope; no enrollment or activation.

The scan is a point-in-time preflight. It does not lock the project tree or
prevent another host process from introducing a hardlink afterward.
"""
from __future__ import annotations

import os
import ntpath
from pathlib import Path
import re
import stat

from device_fabric.windows_personal_project_scan import scan
from device_fabric.windows_personal_psec_terminal import SyntheticPsecTerminal

YFC_DEV = Path(r"D:\Pet-projects\yfc-dev")
GIT_ROOT = Path(r"C:\Program Files\Git")
APP_NAME = "HermesCommanderPersonalPsec"
REPARSE = 0x400
_SIMPLE_DELETE = re.compile(r'^\s*(?:del|erase)\s+(?:/q\s+)?(?:"([^"\r\n]+)"|([^\s"\r\n]+))\s*$', re.I)
_DELETE_JS = ("const f=require('node:fs'),p=process.argv[1],s=f.lstatSync(p);"
              "if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1)process.exit(1);f.unlinkSync(p)")


def _single_file_delete(command: str | None, root: str) -> str | None:
    """Translate only simple single-file cmd deletion for the PSEC terminal.

    cmd.exe's built-in del cannot remove files in this PSEC on the owner host,
    while a direct unlink can. Complex command lines keep their normal shell
    semantics; no wildcard, directory, shell expansion or outside path is
    interpreted by this adapter.
    """
    if type(command) is not str or type(root) is not str or '\r' in command or '\n' in command:
        return command
    match = _SIMPLE_DELETE.fullmatch(command)
    if not match:
        return command
    value = match.group(1) or match.group(2)
    if (not value or any(ch in value for ch in '\x00\r\n"*?<>|&^%!')
        or any(part in ('', '.', '..') or part.endswith((' ', '.'))
               for part in value.replace('/', '\\').split('\\') if part != '')):
        return command
    drive, tail = ntpath.splitdrive(value)
    if ':' in tail:
        return command
    if (drive and not ntpath.isabs(value)) or (ntpath.isabs(value) and not drive):
        return command
    target = ntpath.normpath(value if drive else ntpath.join(root, value))
    normalized_root = ntpath.normcase(ntpath.normpath(root))
    if (any(ch in target for ch in '\x00\r\n"*?<>|&^%!')
        or not ntpath.normcase(target).startswith(normalized_root + '\\')):
        return command
    return f'node -e "{_DELETE_JS}" "{target}"'


def _real_directory(path: Path) -> None:
    if not path.is_absolute() or os.path.normcase(str(path.resolve(strict=True))) != os.path.normcase(str(path)):
        raise ValueError()
    for part in (path, *path.parents):
        info = part.lstat()
        if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & REPARSE:
            raise ValueError()


class YfcDevPsecTerminal(SyntheticPsecTerminal):
    """Limit PSEC paths to YFC dev and dedicated personal runtime folders.

    The caller must independently verify the exact runtime bundle and its owner
    before launch. A metadata scan alone does not establish ongoing isolation.
    """

    def __init__(self, root: str, *, command: str | None = None,
                 writable: tuple[str, ...] = (), readonly: tuple[str, ...] = (),
                 project_roots: tuple[str, ...] | None = None):
        if project_roots is None:
            self._project_roots = (str(YFC_DEV),)
        else:
            from device_fabric.windows_personal_commander_config import roots_for
            self._project_roots = roots_for('owner-projects', roots=project_roots)
        self._denied_paths = (() if project_roots is None else
                              tuple(str(Path(value) / '.artifacts') for value in self._project_roots))
        translated = _single_file_delete(command, root)
        if translated == command:
            for extra in self._project_roots[1:]:
                translated = _single_file_delete(command, extra)
                if translated != command:
                    break
        options = {'denied': self._denied_paths} if self._denied_paths else {}
        super().__init__(root, command=translated,
                         writable=writable, readonly=readonly, **options)

    def _environment_variables(self) -> dict[str, str]:
        env = super()._environment_variables()
        system_root = env.get("SYSTEMROOT", "")
        app_data = env.get("LOCALAPPDATA", "")
        if not os.path.isabs(system_root) or not os.path.isabs(app_data):
            raise ValueError()
        node = Path(app_data) / APP_NAME / "release" / "runner"
        env.update({
            "PATH": os.pathsep.join((str(Path(system_root) / "System32"), str(GIT_ROOT / "cmd"), str(node))),
            "GIT_CONFIG_GLOBAL": "NUL",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": str(len(getattr(self, '_project_roots', (str(YFC_DEV),)))),
        })
        for index, root in enumerate(getattr(self, '_project_roots', (str(YFC_DEV),))):
            env['GIT_CONFIG_KEY_' + str(index)] = 'safe.directory'
            env['GIT_CONFIG_VALUE_' + str(index)] = root.replace('\\', '/')
        return env

    def _validate_paths(self, root: str, writable: tuple[str, ...], readonly: tuple[str, ...]) -> None:
        app_data = os.environ.get("LOCALAPPDATA", "")
        if os.name != "nt" or not os.path.isabs(app_data):
            raise ValueError()
        base = Path(app_data) / APP_NAME
        state = base / "adapter-state"
        release = base / "release"
        roots = getattr(self, '_project_roots', (str(YFC_DEV),))
        if (os.path.normcase(root) != os.path.normcase(roots[0])
            or writable != (str(state), *roots[1:]) or readonly != (str(release), str(GIT_ROOT))):
            raise ValueError()
        for path in (*(Path(value) for value in roots), state, release, GIT_ROOT):
            _real_directory(path)
        denied = getattr(self, '_denied_paths', ())
        snapshots = tuple(scan(Path(value), excluded=(Path(value) / '.artifacts',)) if denied
                          else scan(Path(value)) for value in roots)
        self.project_snapshot = snapshots[0]
        self.project_snapshots = snapshots

    def _validate_denied_paths(self, root: str, denied: tuple[str, ...]) -> None:
        roots = getattr(self, '_project_roots', (str(YFC_DEV),))
        expected = tuple(str(Path(value) / '.artifacts') for value in roots)
        if denied not in ((), expected):
            raise ValueError()
        for value in denied:
            path = Path(value)
            try:
                _real_directory(path)
            except FileNotFoundError:
                pass
