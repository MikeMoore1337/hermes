#!/usr/bin/env python3
"""Fail-closed, read-only H-15 workspace routing (#454).

This is an offline resolver, not an exposed MCP tool or OS authorization gate.
Actual device discovery must come from the existing Hermes list_devices tool.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

REGISTRY = Path(__file__).resolve().parents[1] / "deploy/h15/workspace-registry.json"
MAX_INPUT = 16384
SAFE_NAME = re.compile(r"^[a-z][a-z0-9-]{1,79}$")
SAFE_BRANCH = re.compile(r"^(main|master)$")
SAFE_DEVICE_ID = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


class RouteDenied(Exception):
    """Report only short, non-sensitive reason codes."""


def _deny(reason: str) -> None:
    raise RouteDenied(reason)


def _normalize(value: str) -> str:
    if not isinstance(value, str) or len(value) > 100 or not value.strip():
        _deny("invalid_alias")
    return " ".join(value.strip().casefold().replace("_", " ").split())


def load_registry(path: Path = REGISTRY) -> dict[str, Any]:
    """Validate the catalog contract; catalog content never grants OS access."""
    try:
        if path.is_symlink() or path.stat().st_size > MAX_INPUT:
            _deny("invalid_registry_file")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise RouteDenied("invalid_registry_file") from exc
    if not isinstance(data, dict) or set(data) != {
        "schema", "workspace_root", "device_name", "workspaces"
    } or type(data["schema"]) is not int or data["schema"] != 1:
        _deny("invalid_registry_schema")
    if data["workspace_root"] != "/workspace/projects" or data["device_name"] != "H15 Windows permanent sandbox":
        _deny("invalid_registry_scope")
    entries = data["workspaces"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 16:
        _deny("invalid_registry_entries")
    names: set[str] = set()
    aliases: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"name", "aliases", "repository", "branch", "access"}:
            _deny("invalid_registry_entry")
        name, repo, branch, access = (entry[k] for k in ("name", "repository", "branch", "access"))
        if (not isinstance(name, str) or not SAFE_NAME.fullmatch(name)
            or repo != name or name in names or not isinstance(branch, str)
            or not SAFE_BRANCH.fullmatch(branch) or access != "sandbox"):
            _deny("invalid_registry_entry")
        names.add(name)
        values = entry["aliases"]
        if not isinstance(values, list) or not 1 <= len(values) <= 12:
            _deny("invalid_registry_alias")
        normalized = [_normalize(value) for value in values]
        if len(set(normalized)) != len(normalized) or any(a in aliases for a in normalized):
            _deny("duplicate_registry_alias")
        aliases.update(normalized)
    return data


def _select(alias: str, registry: dict[str, Any]) -> dict[str, Any]:
    needle = _normalize(alias)
    for item in registry["workspaces"]:
        if needle in [_normalize(s) for s in item["aliases"]]:
            return item
    _deny("unknown_workspace")


def _device(devices: Any, name: str) -> dict[str, Any]:
    if not isinstance(devices, dict) or set(devices) != {"devices"} or not isinstance(devices["devices"], list) or len(devices["devices"]) > 25:
        _deny("invalid_device_discovery")
    matching = [x for x in devices["devices"] if isinstance(x, dict) and x.get("name") == name]
    if len(matching) != 1:
        _deny("missing_or_ambiguous_device")
    item = matching[0]
    if item.get("online") is not True or item.get("paused") is not False:
        _deny("device_not_ready")
    device_id = item.get("deviceId")
    if not isinstance(device_id, str) or not SAFE_DEVICE_ID.fullmatch(device_id):
        _deny("invalid_device_id")
    return {"device_id": device_id, "device_status": "online"}


def _git(root: Path, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", "-c", f"safe.directory={root}", "-c", "core.fsmonitor=false",
             "-c", "core.hooksPath=/dev/null", "-C", str(root), *args],
            capture_output=True, text=True, timeout=8, check=False,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RouteDenied("git_unavailable") from exc
    if proc.returncode or len(proc.stdout) > 1024:
        _deny("repository_verification_failed")
    return proc.stdout.strip()


def resolve(alias: str, *, registry: dict[str, Any] | None = None,
            root: Path | None = None, devices: Any = None) -> dict[str, Any]:
    cfg = registry if registry is not None else load_registry()
    entry = _select(alias, cfg)
    parent = root if root is not None else Path(cfg["workspace_root"])
    if parent.is_symlink() or not parent.is_dir() or not parent.resolve().is_dir():
        _deny("workspace_root_missing_or_unsafe")
    target = parent / entry["name"]
    gitdir = target / ".git"
    if (target.is_symlink() or not target.is_dir()
        or gitdir.is_symlink() or not gitdir.is_dir()
        or target.resolve().parent != parent.resolve()):
        _deny("workspace_missing_or_unsafe")
    expected_origin = f"https://github.com/MikeMoore1337/{entry['repository']}.git"
    if _git(target, "remote", "get-url", "origin") != expected_origin:
        _deny("repository_origin_mismatch")
    if _git(target, "branch", "--show-current") != entry["branch"]:
        _deny("repository_branch_mismatch")
    sha = _git(target, "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        _deny("invalid_repository_head")
    response: dict[str, Any] = {
        "schema": 1, "status": "verified", "workspace": entry["name"],
        "root": str(target), "origin": expected_origin, "branch": entry["branch"],
        "head": sha, "access": "sandbox", "device_name": cfg["device_name"],
        "tracked_clean": "not_checked", "device_status": "not_checked",
    }
    if devices is not None:
        response.update(_device(devices, cfg["device_name"]))
    return response


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H-15 workspace name routing (no host access)")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list", action="store_true")
    mode.add_argument("--resolve", metavar="PROJECT")
    parser.add_argument("--devices-stdin", action="store_true", help="validated MCP list_devices JSON on stdin")
    args = parser.parse_args(argv)
    try:
        cfg = load_registry()
        devices = None
        if args.devices_stdin:
            payload = sys.stdin.read(MAX_INPUT + 1)
            if len(payload) > MAX_INPUT:
                _deny("invalid_device_discovery")
            try:
                devices = json.loads(payload)
            except ValueError as exc:
                raise RouteDenied("invalid_device_discovery") from exc
        if args.list:
            payload = {"schema": 1, "status": "catalog", "device_name": cfg["device_name"],
                       "workspaces": [{"name": e["name"], "aliases": e["aliases"],
                                       "branch": e["branch"], "access": e["access"]}
                                      for e in cfg["workspaces"]]}
        else:
            payload = resolve(args.resolve, registry=cfg, devices=devices)
    except RouteDenied as exc:
        print(json.dumps({"schema": 1, "status": "refused", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
