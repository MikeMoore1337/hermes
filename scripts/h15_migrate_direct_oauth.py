"""Migrate existing Hermes OAuth credentials to direct, Second Brain-style GitHub login.

No new secrets, no shell evaluation, no public listener changes. This is an
explicit root-only host operation, NOT part of every deploy.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

from control_center.auth import AuthConfig
from control_center.credentials import load_runtime_credentials
from control_center.oauth_broker import BrokerConfig

CREDENTIALS = Path("/etc/hermes-control-center/oauth")
DROPIN = Path("/etc/systemd/system/hermes-control-center.service.d/20-github-auth.conf")
BACKUP = CREDENTIALS / "web-service-dropin.before-direct-auth"
WEB = "hermes-control-center.service"
BROKER = "hermes-oauth-broker.service"

def _direct_dropin(current: str) -> str:
    """Reject unexpected systemd fragments before modifying the host."""
    old = (
        "[Unit]\nAfter=hermes-oauth-broker.service\n"
        "Requires=hermes-oauth-broker.service\n"
        "[Service]\nLoadCredential=web.env:" + str(CREDENTIALS / "web.env") + "\n"
    )
    new = (
        "[Service]\n"
        "LoadCredential=web.env:" + str(CREDENTIALS / "web.env") + "\n"
        "LoadCredential=broker.env:" + str(CREDENTIALS / "broker.env") + "\n"
        "# The web process itself calls fixed GitHub OAuth endpoints over TLS.\n"
        "IPAddressDeny=\n"
        "IPAddressAllow=\n"
    )
    if current not in (old, new):
        raise ValueError("Unexpected existing GitHub systemd drop-in")
    return new

def _cmd(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=20)

def _atomic(path: Path, content: str) -> None:
    temporary = path.with_name(path.name + ".direct-temporary")
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as writer:
            writer.write(content)
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)

def _credentials_checked() -> None:
    if CREDENTIALS.is_symlink() or not CREDENTIALS.is_dir():
        raise ValueError("Missing or unsafe credential directory")
    for filename in ("web.env", "broker.env"):
        path = CREDENTIALS / filename
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
            raise ValueError("Unsafe OAuth credential file")
    env = {"CREDENTIALS_DIRECTORY": str(CREDENTIALS)}
    web = load_runtime_credentials("web.env", env)
    identity = load_runtime_credentials("broker.env", env)
    if web is None or identity is None:
        raise ValueError("Missing OAuth credentials")
    config = AuthConfig.from_env(web)
    broker = BrokerConfig.from_env(identity)
    if config.mode != "github" or config.client_id != broker.client_id or config.owner_id != broker.owner_id:
        raise ValueError("OAuth credential mismatch")

def _run(mode: str) -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise PermissionError("Root on approved Linux host required")
    _credentials_checked()
    if mode == "stage":
        if DROPIN.is_symlink() or not DROPIN.is_file():
            raise ValueError("Invalid or missing web service drop-in")
        old = DROPIN.read_text(encoding="utf-8")
        new = _direct_dropin(old)
        if old != new:
            if BACKUP.exists() or BACKUP.is_symlink():
                raise FileExistsError("Existing migration backup: refusing overwrite")
            _atomic(BACKUP, old)
            _atomic(DROPIN, new)
        _cmd("systemctl", "daemon-reload")
        for key in ("IPAddressDeny", "IPAddressAllow"):
            prop = _cmd("systemctl", "show", WEB, "-p", key, "--value").stdout.strip()
            if prop:
                raise RuntimeError("Web egress reset unsuccessful")
        print("DIRECT_OAUTH_STAGE=READY (existing broker remains active for rollback)")
    elif mode == "finalize":
        if not BACKUP.is_file() or _direct_dropin(DROPIN.read_text()) != DROPIN.read_text():
            raise RuntimeError("Migration staging not verified")
        if _cmd("systemctl", "is-active", WEB).stdout.strip() != "active":
            raise RuntimeError("Web service not active")
        if _cmd("curl", "--fail", "--silent", "--show-error", "--max-time", "5",
                "http://127.0.0.1:9133/healthz").stdout.strip() != "ok":
            raise RuntimeError("Web service health check failed")
        _cmd("systemctl", "disable", "--now", BROKER)
        if _cmd("systemctl", "is-active", BROKER, check=False).stdout.strip() == "active":
            raise RuntimeError("Legacy broker did not stop")
        print("DIRECT_OAUTH_MIGRATION=COMPLETE")
    else:
        raise ValueError("Unknown migration action")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--stage", action="store_true")
    modes.add_argument("--finalize", action="store_true")
    args = parser.parse_args()
    _run("stage" if args.stage else "finalize")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
