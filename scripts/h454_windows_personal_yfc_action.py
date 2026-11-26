"""Build a pinned, windowless action without registering or running a task."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import subprocess

from device_fabric.windows_personal_yfc_psec import APP_NAME, _real_directory
from scripts.h454_windows_personal_yfc_bootstrap import _digest, _read

BOOTSTRAP_NAME = "h454_windows_personal_yfc_bootstrap.py"
MAX_BOOTSTRAP = 128 * 1024
MAX_PYTHONW = 16 * 1024 * 1024
# Python runs with isolated mode and bytecode disabled. The task pins these
# bytes before executing them, so bootstrap imports happen only afterwards.
GATE = (
    "import hashlib,pathlib,sys\n"
    "p=pathlib.Path(sys.argv[1]); b=p.read_bytes()\n"
    "if hashlib.sha256(b).hexdigest()!=sys.argv[2]: raise SystemExit(2)\n"
    "sys.argv=[str(p),*sys.argv[3:]]\n"
    "exec(compile(b,str(p),'exec'),{'__name__':'__main__','__file__':str(p)})\n"
)


class YfcActionDenied(ValueError):
    """Constant denial without disclosing host paths."""


@dataclass(frozen=True, slots=True)
class Action:
    executable: str
    arguments: tuple[str, ...]

    @property
    def windows_arguments(self) -> str:
        return subprocess.list2cmdline(self.arguments)


def build_action(pythonw: Path, *, pythonw_sha256: str, bootstrap_sha256: str,
                 manifest_sha256: str, verifier_sha256: str) -> Action:
    """Return exact direct-execution arguments for a separately installed task."""
    try:
        if (os.name != "nt" or not isinstance(pythonw, Path) or not pythonw.is_absolute()
            or pythonw.name.lower() != "pythonw.exe" or not all(_digest(digest) for digest in
                (pythonw_sha256, bootstrap_sha256, manifest_sha256, verifier_sha256))):
            raise ValueError()
        app_data = os.environ.get("LOCALAPPDATA", "")
        if not os.path.isabs(app_data):
            raise ValueError()
        bootstrap_dir = Path(app_data) / APP_NAME / "bootstrap"
        _real_directory(bootstrap_dir)
        _real_directory(pythonw.parent)
        bootstrap = bootstrap_dir / BOOTSTRAP_NAME
        if hashlib.sha256(_read(pythonw, MAX_PYTHONW)).hexdigest() != pythonw_sha256:
            raise ValueError()
        if hashlib.sha256(_read(bootstrap, MAX_BOOTSTRAP)).hexdigest() != bootstrap_sha256:
            raise ValueError()
        return Action(str(pythonw), ("-I", "-B", "-c", GATE, str(bootstrap),
            bootstrap_sha256, manifest_sha256, verifier_sha256))
    except Exception:
        raise YfcActionDenied("yfc_action_denied") from None
