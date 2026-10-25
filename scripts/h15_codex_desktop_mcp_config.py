"""Manage the existing Hermes MCP entry in Codex Desktop config, without Codex CLI.

Source-only until explicitly owner-approved to execute on a native Windows
user profile. NEVER reads OAuth tokens, launches Codex/model calls, or edits
other MCP entries. A rollback receipt stores only hashes, no TOML contents.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import tomllib

URL = "https://mcp.mikemoore.top/mcp"
RECEIPT = ".hermes-mcp-install.json"
MAX_BYTES = 1024 * 1024
SUFFIX = (
    '\n# BEGIN Hermes MCP owner-managed entry\n'
    '[mcp_servers.hermes]\n'
    f'url = "{URL}"\n'
    '# END Hermes MCP owner-managed entry\n'
).encode("utf-8")


class ConfigRefused(ValueError):
    pass


def _deny(reason: str):
    raise ConfigRefused(reason)


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _regular_or_absent(path: Path) -> bool:
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        _deny("untrusted_path")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        _deny("untrusted_path")
    if info.st_size > MAX_BYTES:
        _deny("config_too_large")
    return True


def _root(root: Path) -> None:
    if not root.is_absolute() or not root.exists() or not root.is_dir():
        _deny("codex_home_missing")
    if root.is_symlink() or (hasattr(root, "is_junction") and root.is_junction()):
        _deny("unsafe_codex_home")


def _read_config(path: Path) -> tuple[bytes, bool]:
    if not _regular_or_absent(path):
        return b"", False
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ConfigRefused("config_unreadable") from exc
    if len(data) > MAX_BYTES:
        _deny("config_too_large")
    try:
        parsed = tomllib.loads(data.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ConfigRefused("invalid_existing_toml") from exc
    if not isinstance(parsed, dict):
        _deny("invalid_existing_toml")
    return data, True


def _has_hermes(data: bytes) -> bool:
    if not data:
        return False
    parsed = tomllib.loads(data.decode("utf-8"))
    servers = parsed.get("mcp_servers", {})
    if not isinstance(servers, dict):
        _deny("invalid_mcp_servers")
    return "hermes" in servers


def _atomic_replace(path: Path, data: bytes, mode: int) -> None:
    descriptor, temp_name = tempfile.mkstemp(prefix=".hermes-config-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _regular_or_absent(path)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def _read_receipt(path: Path) -> dict | None:
    if not _regular_or_absent(path):
        return None
    raw = path.read_bytes()
    if len(raw) > 2048:
        _deny("receipt_invalid")
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ConfigRefused("receipt_invalid") from exc
    if (type(receipt) is not dict or set(receipt) != {
        "schema", "had_original", "before_sha", "installed_sha"
    } or receipt["schema"] != 1 or type(receipt["had_original"]) is not bool or
        not all(type(receipt[k]) is str and len(receipt[k]) == 64 and
                all(c in "0123456789abcdef" for c in receipt[k])
                for k in ("before_sha", "installed_sha"))):
        _deny("receipt_invalid")
    return receipt


def _write_receipt(path: Path, receipt: dict) -> None:
    # The receipt intentionally contains no URL secrets or raw config bytes.
    raw = json.dumps(receipt, separators=(",", ":"), sort_keys=True).encode("ascii")
    try:
        with path.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ConfigRefused("receipt_collision") from exc


def manage(root: Path, operation: str, *, enforce_windows: bool = True) -> dict:
    """No arbitrary config path: only the exact directory chosen by caller.

    The CLI always picks Path.home() / '.codex', never a request-supplied root.
    Fixture tests can bypass the OS gate without opening real Windows files.
    """
    if operation not in {"status", "install", "rollback"}:
        _deny("operation_denied")
    if enforce_windows and os.name != "nt" and operation != "status":
        _deny("native_windows_required")
    _root(root)
    config = root / "config.toml"
    record = root / RECEIPT
    original, had_original = _read_config(config)
    receipt = _read_receipt(record)
    if operation == "status":
        state = ("managed" if _sha(original) == receipt["installed_sha"] else
                 "pending_install" if _sha(original) == receipt["before_sha"] else
                 "conflict") if receipt else (
                 "preexisting" if _has_hermes(original) else "not_installed")
        return {
            "schema": 1, "status": state,
            "changes": 0, "config_present": had_original,
            "receipt_present": receipt is not None,
            "server_configured": _has_hermes(original),
            "oauth_verified": False, "desktop_mcp_e2e_verified": False,
        }
    if operation == "install":
        if receipt:
            if _sha(original) == receipt["installed_sha"]:
                return {"schema": 1, "status": "already_managed", "changes": 0}
            _deny("receipt_conflict")
        if _has_hermes(original):
            _deny("preexisting_hermes_mcp_no_takeover")
        after = original + SUFFIX
        # Validate resulting full TOML, including adjacent existing sections.
        try:
            tomllib.loads(after.decode("utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise ConfigRefused("combined_toml_invalid") from exc
        if len(after) > MAX_BYTES:
            _deny("config_too_large")
        candidate = {
            "schema": 1, "had_original": had_original,
            "before_sha": _sha(original), "installed_sha": _sha(after)
        }
        _write_receipt(record, candidate)
        mode = (config.stat().st_mode & 0o777) if had_original else 0o600
        _atomic_replace(config, after, mode)
        return {"schema": 1, "status": "installed", "changes": 1,
                "oauth_verified": False, "desktop_mcp_e2e_verified": False}
    if receipt is None:
        _deny("not_owned_by_hermes")
    # Compare exact owned append only; edits by other apps remain untouched.
    if _sha(original) == receipt["before_sha"]:
        record.unlink()
        return {"schema": 1, "status": "pending_receipt_cleared", "changes": 1}
    if _sha(original) != receipt["installed_sha"] or not original.endswith(SUFFIX):
        _deny("config_changed_refuse_rollback")
    before = original[:-len(SUFFIX)]
    if _sha(before) != receipt["before_sha"]:
        _deny("receipt_conflict")
    if receipt["had_original"]:
        mode = config.stat().st_mode & 0o777
        _atomic_replace(config, before, mode)
    else:
        _regular_or_absent(config)
        config.unlink()
    record.unlink()
    return {"schema": 1, "status": "rolled_back", "changes": 1,
            "oauth_verified": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Codex Desktop Hermes MCP config owner gate")
    parser.add_argument("--mode", choices=("status", "install", "rollback"),
                        default="status")
    args = parser.parse_args(argv)
    try:
        result = manage(Path.home() / ".codex", args.mode)
        rc = 0
    except (ConfigRefused, OSError, ValueError):
        # Never print real TOML, local paths or OAuth values.
        result = {"schema": 1, "status": "refused", "reason": "owner_gate_denied",
                  "changes": 0}
        rc = 2
    print(json.dumps(result, sort_keys=True))
    return rc


if __name__ == "__main__":
    sys.exit(main())
