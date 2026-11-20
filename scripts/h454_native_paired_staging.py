"""Stage a paired-upgrade source and pinned wheel; never modify active files."""
from __future__ import annotations

import os
from pathlib import Path
import stat

from scripts import h454_native_paired_host as host
from scripts.h454_native_linux_wheel import stage_wheel
from scripts.h454_native_paired_rebind import RebindDenied
from scripts.h454_native_paired_source import stage as stage_source


def _normalize_dirs(root: Path) -> None:
    """Expose only newly created root-owned dependency directories for reads."""
    for path in (root, *root.rglob("*")):
        item = path.lstat()
        if stat.S_ISDIR(item.st_mode):
            if item.st_uid != 0 or item.st_mode & 0o022:
                raise RebindDenied()
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                pinned = os.fstat(fd)
                if (pinned.st_dev, pinned.st_ino) != (item.st_dev, item.st_ino):
                    raise RebindDenied()
                os.fchmod(fd, 0o755)
                os.fsync(fd)
            finally:
                os.close(fd)
        elif not stat.S_ISREG(item.st_mode) or item.st_uid != 0:
            raise RebindDenied()


def stage() -> host.HostPlan:
    """Stage once under a host lock; a failed source stage may remain."""
    try:
        plan = host.inspect()
        base = Path("/opt/hermes-commander-native")
        stage_source(base / "releases", plan.bundle, plan.receipt, release=host.NEW,
                     bundle_sha256=host.BUNDLE_SHA, trusted_uid=0)
        stage_wheel(plan.wheel, target="hermes-vps", release_sha=host.NEW,
                    root=base / "deps", owner_uid=0, check_ancestors=True)
        _normalize_dirs(base / "deps" / ("main-" + host.NEW))
        if host.inspect(staged=True) != plan:
            raise RebindDenied()
        return plan
    except Exception:
        raise RebindDenied("native_paired_stage_denied") from None
