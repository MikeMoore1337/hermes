"""Build a deterministic source-only device-agent ZIP for Windows/Linux.

The archive contains no tokens, certificates, credentials, deployment scripts or
server state. Owner transfers a separate 0600 enrollment bundle afterwards.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import os
import zipfile

FILES = (
    "device_fabric/__init__.py",
    "device_fabric/device_agent.py",
    "device_fabric/presence.py",
    "device_fabric/read_only_agent.py",
    "device_fabric/ssh_tunnel.py",
)


def build_archive(root: Path, output: Path) -> str:
    root = Path(root).resolve()
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("output_already_exists")
    paths = []
    for name in FILES:
        path = root / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64000:
            raise ValueError("invalid_client_source")
        paths.append((name, path.read_bytes()))
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(output, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, data in paths:
                    info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = 0o644 << 16
                    archive.writestr(info, data)
        return sha256(output.read_bytes()).hexdigest()
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Package read-only agent source, no credentials")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    digest = build_archive(Path(__file__).resolve().parents[1], args.output)
    print("DEVICE_CLIENT_PACKAGE=READY")
    print(f"DEVICE_CLIENT_SHA256={digest}")
    print("DEVICE_CLIENT_NO_SECRETS=YES")


if __name__ == "__main__":
    main()
