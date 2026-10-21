"""Opt-in, fixed-command SSH pull of sanitized read-only YFC host metrics.

This collector is intentionally disabled until an owner verifies the YFC endpoint,
host key, restricted authorized_keys identity and egress. No HTTP ingest endpoint.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess

from control_center.infrastructure import ROOT, _validated, save

DEFAULT_CONFIG = Path("/etc/hermes/yfc-infrastructure-pull.json")
KEY = Path("/etc/hermes/yfc-infrastructure-readonly")
KNOWN_HOSTS = Path("/etc/hermes/yfc-infrastructure-known-hosts")
MAX_SNAPSHOT = 16384
USER = "hermes-infra-read"


class PullError(RuntimeError):
    pass


def require_file(path: Path, *, private: bool = False) -> None:
    if path.is_symlink() or not path.is_file():
        raise PullError("configuration_file_missing_or_symlink")
    stat = path.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o022:
        raise PullError("configuration_file_permissions")
    if private and stat.st_mode & 0o077:
        raise PullError("private_key_permissions")


def endpoint(config_path: Path = DEFAULT_CONFIG) -> tuple[str, int]:
    require_file(config_path, private=True)
    if config_path.stat().st_size > 1024:
        raise PullError("oversized_config")
    try:
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(cfg, dict) or set(cfg) != {"host", "port"}:
            raise ValueError("invalid fields")
        host, port = cfg["host"], cfg["port"]
        if not isinstance(host, str) or not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
            raise ValueError("invalid host")
        if ".." in host or not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("invalid port")
    except (ValueError, UnicodeError) as exc:
        raise PullError("invalid_endpoint_config") from exc
    return host, port


def command(host: str, port: int) -> list[str]:
    # No SSH defaults, forwarding, agent, password, proxy or host-key prompts.
    # Restricted remote authorized_keys additionally forces the fixed emit script.
    return [
        "/usr/bin/ssh", "-F", "/dev/null", "-T",
        "-i", str(KEY), "-p", str(port),
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=4",
        "-o", "ConnectionAttempts=1", "-o", "ProxyCommand=none",
        "-o", "PermitLocalCommand=no", "-o", "ForwardAgent=no",
        "-o", "ClearAllForwardings=yes",
        "--", f"{USER}@{host}", "snapshot",
    ]


def pull(*, config_path: Path = DEFAULT_CONFIG, directory: Path = ROOT,
         runner=subprocess.run) -> dict:
    host, port = endpoint(config_path)
    require_file(KEY, private=True)
    require_file(KNOWN_HOSTS)
    try:
        proc = runner(command(host, port), timeout=10, check=False,
                      capture_output=True, text=True, encoding="utf-8",
                      errors="strict")
    except UnicodeError as exc:
        # Malformed remote output is untrusted; never surface its bytes or stderr.
        raise PullError("ssh_invalid_encoding") from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PullError("ssh_unavailable") from exc
    if proc.returncode != 0:
        raise PullError("ssh_denied")
    if not isinstance(proc.stdout, str):
        raise PullError("ssh_payload_invalid")
    try:
        size = len(proc.stdout.encode("utf-8", errors="strict"))
    except UnicodeError as exc:
        raise PullError("ssh_invalid_encoding") from exc
    if size > MAX_SNAPSHOT:
        raise PullError("ssh_payload_oversized")
    try:
        raw = json.loads(proc.stdout)
        if not isinstance(raw, dict) or raw.get("source") != "linux_procfs_local":
            raise ValueError("unexpected source")
        now = dt.datetime.now(dt.timezone.utc)
        checked = _validated(raw, "yfc", now)
        if checked["status"] != "online":
            raise ValueError("remote sample expired")
        # Explicitly do not forward provider data, arbitrary keys or interface names.
        sanitized = {"schema": 1, "host": "yfc", "source": "linux_procfs_local",
                     "observed_at": checked["observed_at"], "metrics": checked["metrics"]}
        save(sanitized, directory, group="hermes-control")
        return {"host": "yfc", "status": "received", "observed_at": checked["observed_at"]}
    except (ValueError, TypeError, KeyError) as exc:
        raise PullError("invalid_or_out_of_order_remote_snapshot") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    try:
        result = pull(config_path=args.config)
    except PullError as exc:
        # No raw SSH stderr or remote payload is ever logged.
        print("YFC_PULL=" + str(exc))
        return 1
    print("YFC_PULL=received observed_at=" + result["observed_at"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
