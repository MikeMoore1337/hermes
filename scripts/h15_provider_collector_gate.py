"""#295 opt-in provider source gate: local metadata only until an owner smoke.

Never logs credentials, account IDs, raw quotas, HTTP bodies or filesystem
contents. Script exit statuses are suitable for an explicit root-console
rollout, not an automatic production deploy.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
from typing import Literal

PROVIDERS = ("github", "cloudflare")
TOKEN_PATHS = {
    "github": Path("/etc/hermes/github-rate-limit-read.token"),
    "cloudflare": Path("/etc/hermes/cloudflare-billing-read.token"),
}
CLOUDFLARE_ENV = Path("/etc/hermes/cloudflare-billing-read.env")
OBSERVATION_PATHS = {
    "github": Path("/var/lib/hermes-provider-quota/github-rate-limits.json"),
    "cloudflare": Path("/var/lib/hermes-provider-quota/cloudflare-billing.json"),
}


def safe_file(path: Path, *, user_id: int = 0,
              minimum: int = 1, maximum: int = 512) -> bool:
    """Only inspect metadata: regular root-owned 0600 file, never symlink."""
    try:
        info = path.lstat()
        return (stat.S_ISREG(info.st_mode)
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == user_id
                and info.st_nlink == 1
                and minimum <= info.st_size <= maximum)
    except OSError:
        return False


def safe_account_env(path: Path, *, user_id: int = 0) -> bool:
    if not safe_file(path, user_id=user_id, minimum=55, maximum=100):
        return False
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode)
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != user_id or info.st_nlink != 1
                    or not 55 <= info.st_size <= 100):
                return False
            value = os.read(fd, 101)
        finally:
            os.close(fd)
    except OSError:
        return False
    return re.fullmatch(
        rb"CLOUDFLARE_BILLING_ACCOUNT_ID=[0-9a-fA-F]{32}\n?",
        value,
    ) is not None


def credentials_ready(provider: str, *, paths: dict[str, Path] | None = None,
                      account_env: Path = CLOUDFLARE_ENV,
                      user_id: int = 0) -> bool:
    if provider not in PROVIDERS:
        raise ValueError("invalid_provider")
    token = (paths or TOKEN_PATHS)[provider]
    if not safe_file(token, user_id=user_id, minimum=20, maximum=512):
        return False
    return provider != "cloudflare" or safe_account_env(
        account_env, user_id=user_id,
    )


def observed(provider: str, *, path: Path | None = None) -> bool:
    """Validate a real, still-fresh collector snapshot, not only file presence."""
    if provider == "github":
        from control_center.github_rate_limit import snapshot
        data = snapshot(path or OBSERVATION_PATHS[provider])
        return data["status"] == "ok" and bool(data["resources"])
    if provider == "cloudflare":
        from control_center.cloudflare_billing import snapshot
        data = snapshot(path or OBSERVATION_PATHS[provider])
        return data["status"] == "ok" and bool(data["days"])
    raise ValueError("invalid_provider")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only #295 source gate")
    parser.add_argument("--provider", choices=PROVIDERS, required=True)
    parser.add_argument("--gate", choices=("status", "credentials", "observed"),
                        default="status")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print(json.dumps({"provider": args.provider,
                          "result": "ROOT_CONSOLE_REQUIRED"}))
        return 2
    ready = credentials_ready(args.provider)
    valid = observed(args.provider) if ready and args.gate != "credentials" else False
    result = {
        "provider": args.provider,
        "credentials": "READY_METADATA_ONLY" if ready else "MISSING_OR_UNSAFE",
        "source": "FRESH_OBSERVED" if valid else "NOT_VERIFIED",
    }
    print(json.dumps(result, sort_keys=True))
    if args.gate == "credentials":
        return 0 if ready else 2
    if args.gate == "observed":
        return 0 if ready and valid else 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
