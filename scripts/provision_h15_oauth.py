"""Interactive, root-only creation of isolated Hermes OAuth systemd credentials.

Run on the authorized VPS terminal, never in CI, GitHub Actions, chat or
shell command argv. No OAuth credentials are activated by this script.
"""
import getpass
import os
from pathlib import Path
import re
import secrets
import sys

BASE = Path("/etc/hermes-control-center/oauth")
ALLOWED_OWNER_ID = "42142321"
BROKER_SOCKET = "/run/hermes-oauth/broker.sock"


def _atomic_exclusive(path: Path, text: str) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(text.encode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> int:
    if os.name != "posix" or os.geteuid() != 0 or not sys.stdin.isatty():
        print("Run interactively as root on the approved VPS.", file=sys.stderr)
        return 2
    if BASE.exists() and (BASE.is_symlink() or not BASE.is_dir()):
        raise RuntimeError("Invalid credential directory")
    client_id = input("Hermes GitHub OAuth Client ID (not secret): ").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{10,100}", client_id):
        raise ValueError("Invalid GitHub Client ID")
    owner = input(f"Confirm owner numeric GitHub ID [{ALLOWED_OWNER_ID}]: ").strip() or ALLOWED_OWNER_ID
    if owner != ALLOWED_OWNER_ID:
        raise ValueError("Expected pinned GitHub owner numeric ID")
    client_secret = getpass.getpass("Hermes OAuth Client Secret (hidden): ")
    if not 20 <= len(client_secret) <= 256 or any(ord(c) < 33 for c in client_secret):
        raise ValueError("Missing or malformed secret")
    confirm = input("Type YES to create inactive, root-only files: ").strip()
    if confirm != "YES":
        print("Cancelled without changes.")
        return 1
    os.umask(0o077)
    if not BASE.exists():
        BASE.mkdir(mode=0o700, parents=True)
    os.chmod(BASE, 0o700)
    web = BASE / "web.env"
    broker = BASE / "broker.env"
    if web.exists() or broker.exists() or web.is_symlink() or broker.is_symlink():
        raise FileExistsError("Credentials already exist. Refusing overwrite/rotation")
    session = secrets.token_urlsafe(48)
    _atomic_exclusive(web, (
        "HERMES_CC_AUTH_MODE=github\n"
        "HERMES_CC_PUBLIC_ORIGIN=https://hermes.mikemoore.top\n"
        f"HERMES_CC_GITHUB_CLIENT_ID={client_id}\n"
        f"HERMES_CC_ALLOWED_GITHUB_ID={owner}\n"
        f"HERMES_CC_SESSION_SECRET={session}\n"
        f"HERMES_CC_OAUTH_BROKER_SOCKET={BROKER_SOCKET}\n"
    ))
    try:
        _atomic_exclusive(broker, (
            f"HERMES_OAUTH_CLIENT_ID={client_id}\n"
            f"HERMES_OAUTH_CLIENT_SECRET={client_secret}\n"
            f"HERMES_OAUTH_ALLOWED_GITHUB_ID={owner}\n"
            f"HERMES_OAUTH_SOCKET={BROKER_SOCKET}\n"
        ))
    except BaseException:
        web.unlink(missing_ok=True)
        raise
    print("CREATED: 2 root-only credential files, both 0600.")
    print("STATUS: INACTIVE. Services and Caddy were not changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
