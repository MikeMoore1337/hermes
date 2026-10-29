"""Prepare, never install/run, the exact owner's H454 launcher repair."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

SOURCE_SHA256 = "55ea1245671c8b656a3bba944945198350668b2920cd46e36ed7cba56637317e"
RUN = "if ($Mode -eq 'Run') {\n"
RUN_END = "\n}\n\ntry {\n    Write-Host '=== HERMES H-15 WINDOWS: PERSISTENT SANDBOX INSTALL ==='"
LOCK = """    $lockPath = Join-Path ([IO.Path]::GetDirectoryName($STATE_PATH)) 'runtime.lock'
    if (Test-Path -LiteralPath $lockPath) {
        Require (-not ((Get-Item -LiteralPath $lockPath -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint)) 'RUNTIME_LOCK_REPARSE_POINT'
    }
    $runtimeLock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
"""


class PatchRefused(ValueError):
    pass


def prepare(source: bytes) -> bytes:
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise PatchRefused("SOURCE_HASH_MISMATCH")
    text = source.decode("utf-8")
    newline = "\r\n" if "\r\n" in text else "\n"
    text = text.replace("\r\n", "\n")
    if (text.count("--pids-limit 96") != 2 or text.count(RUN) != 1
            or text.count(RUN_END) != 1 or "--init" in text):
        raise PatchRefused("SOURCE_STRUCTURE_MISMATCH")
    text = text.replace("--pids-limit 96", "--init --pids-limit 128 --oom-kill-disable=false")
    text = text.replace(RUN, RUN + LOCK)
    text = text.replace(RUN_END, "\n    } finally { $runtimeLock.Dispose() }" + RUN_END)
    return text.replace("\n", newline).encode("utf-8")


def write_candidate(source: Path, output: Path) -> None:
    for path in (source, output):
        for item in (path, *path.parents):
            if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
                raise PatchRefused("REPARSE_POINT")
    if source.resolve() == output.resolve() or output.suffix.casefold() != ".ps1":
        raise PatchRefused("OUTPUT_PATH")
    candidate = prepare(source.read_bytes())
    # Exclusive create keeps the private launcher and any existing output intact.
    with output.open("xb") as stream:
        stream.write(candidate)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        write_candidate(args.source, args.output)
    except (PatchRefused, OSError, UnicodeError) as exc:
        reason = str(exc) if isinstance(exc, PatchRefused) else "FILE_OPERATION_REFUSED"
        print("H454_LAUNCHER_PATCH=HOLD\nH454_REASON=" + reason)
        return 2
    print("H454_LAUNCHER_PATCH=PREPARED\nH454_LIVE_LAUNCHER_CHANGED=FALSE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
