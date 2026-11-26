"""Owner-selected YFC dev PSEC scope; no enrollment or activation.

The scan is a point-in-time preflight. It does not lock the project tree or
prevent another host process from introducing a hardlink afterward.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat

from device_fabric.windows_personal_project_scan import scan
from device_fabric.windows_personal_psec_terminal import SyntheticPsecTerminal

YFC_DEV = Path(r"D:\Pet-projects\yfc-dev")
GIT_ROOT = Path(r"C:\Program Files\Git")
APP_NAME = "HermesCommanderPersonalPsec"
REPARSE = 0x400


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
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": str(YFC_DEV).replace("\\", "/"),
        })
        return env

    def _validate_paths(self, root: str, writable: tuple[str, ...], readonly: tuple[str, ...]) -> None:
        app_data = os.environ.get("LOCALAPPDATA", "")
        if os.name != "nt" or not os.path.isabs(app_data):
            raise ValueError()
        base = Path(app_data) / APP_NAME
        state = base / "adapter-state"
        release = base / "release"
        if (os.path.normcase(root) != os.path.normcase(str(YFC_DEV))
            or writable != (str(state),) or readonly != (str(release), str(GIT_ROOT))):
            raise ValueError()
        for path in (YFC_DEV, state, release, GIT_ROOT):
            _real_directory(path)
        self.project_snapshot = scan(YFC_DEV)
