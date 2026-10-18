"""Entrypoint for production split-root Cloudflare advisory collector.

Control Center is deployed under one immutable root; scripts/ lives in the
matching owner release. Trust the exact SHA and file owners before importing
one-shot collector. No inference, extra API call, or credentials here.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import sys

UI_ROOT = Path("/opt/hermes-control-center")
OWNER_ROOT = Path("/opt/hermes-agent-owner")


def trusted_owner_release(
    *, ui_root: Path = UI_ROOT, owner_root: Path = OWNER_ROOT,
    expected_uid: int = 0,
) -> Path:
    active = ui_root / "current"
    release = active.resolve(strict=True)
    expected_prefix = ui_root / "releases"
    try:
        relative = release.relative_to(expected_prefix)
    except ValueError as exc:
        raise ValueError("untrusted_release") from exc
    if len(relative.parts) != 1 or not re.fullmatch(r"main-[a-f0-9]{40}",relative.name):
        raise ValueError("untrusted_release")
    owner = owner_root / "releases" / relative.name
    if not owner.is_dir() or owner.is_symlink():
        raise ValueError("untrusted_owner_release")
    for path in (release, owner, owner / "scripts",
                 owner / "scripts" / "h15_cloudflare_analytics_collect.py",
                 owner / "scripts" / "h15_cloudflare_analytics_probe.py"):
        info = path.lstat()
        if (path.is_symlink() or info.st_uid != expected_uid or
                stat.S_IMODE(info.st_mode) & 0o022 or
                not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))):
            raise ValueError("untrusted_owner_release")
    return owner


def main() -> int:
    if os.geteuid() != 0:
        print("CLOUDFLARE_ADVISORY_ARCHIVE=ROOT_REQUIRED")
        return 2
    try:
        source = trusted_owner_release()
        # The existing control_center package is loaded from the production
        # active UI release. Append owner source for scripts/ without
        # replacing the already resolved control_center module.
        if str(source) not in sys.path:
            sys.path.append(str(source))
        from scripts.h15_cloudflare_analytics_collect import main as run_once
    except (OSError, ValueError, ImportError):
        print("CLOUDFLARE_ADVISORY_ARCHIVE=UNTRUSTED_RELEASE")
        return 2
    return run_once()


if __name__ == "__main__":
    raise SystemExit(main())
