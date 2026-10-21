#!/usr/bin/env python3
"""Read-only H-15 workspace registry for approved sandbox clones (Issue #454).

No device calls or host paths are opened. MCP clients must independently
verify live device ownership/online state before routing commands.
"""
from __future__ import annotations

import argparse
import configparser
import json
import os
from pathlib import Path
import stat
import sys

REGISTRY = Path(__file__).resolve().parents[1] / "deploy/h15/workspace-registry.json"
SANDBOX = Path("/workspace/projects")
MAX_REGISTRY_BYTES = 32_768
MAX_CONFIG_BYTES = 131_072


class WorkspaceRefused(Exception):
    """A fixed, non-sensitive failure code."""


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise WorkspaceRefused("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _plain_directory(path: Path):
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise WorkspaceRefused("WORKSPACE_NOT_PRESENT") from exc
    if not stat.S_ISDIR(mode):
        raise WorkspaceRefused("WORKSPACE_NOT_PLAIN_DIRECTORY")


def _small_regular_file(path: Path, maximum: int) -> str:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise WorkspaceRefused("UNTRUSTED_WORKSPACE_METADATA")
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise WorkspaceRefused("UNTRUSTED_WORKSPACE_METADATA") from exc


def load_registry(path: Path = REGISTRY) -> dict:
    try:
        source = _small_regular_file(path, MAX_REGISTRY_BYTES)
        data = json.loads(source, object_pairs_hook=_pairs)
    except (ValueError, TypeError) as exc:
        raise WorkspaceRefused("REGISTRY_INVALID_JSON") from exc
    if not isinstance(data, dict) or set(data) != {
        "schema_version", "scope", "devices", "workspaces"
    } or data["schema_version"] != 1 or data["scope"] != "owner-approved-public-sandbox-clones":
        raise WorkspaceRefused("REGISTRY_SCHEMA_INVALID")

    devices, workspaces = data["devices"], data["workspaces"]
    if not isinstance(devices, list) or not isinstance(workspaces, list):
        raise WorkspaceRefused("REGISTRY_SCHEMA_INVALID")
    if len(devices) != 3 or len(workspaces) != 4:
        raise WorkspaceRefused("REGISTRY_UNEXPECTED_ENTRIES")

    device_keys, device_ids, names = set(), set(), set()
    for d in devices:
        if not isinstance(d, dict) or set(d) != {"key", "device_id", "display_name", "platform"}:
            raise WorkspaceRefused("REGISTRY_DEVICE_INVALID")
        if not all(isinstance(v, str) and 0 < len(v) <= 100 for v in d.values()):
            raise WorkspaceRefused("REGISTRY_DEVICE_INVALID")
        if d["platform"] != "linux/docker" or not d["device_id"].startswith("h15-"):
            raise WorkspaceRefused("REGISTRY_DEVICE_INVALID")
        if d["key"] in device_keys or d["device_id"] in device_ids or d["display_name"] in names:
            raise WorkspaceRefused("REGISTRY_DUPLICATE_DEVICE")
        device_keys.add(d["key"])
        device_ids.add(d["device_id"])
        names.add(d["display_name"])

    seen_aliases, seen_roots, seen_keys = set(), set(), set()
    for w in workspaces:
        if not isinstance(w, dict) or set(w) != {
            "key", "aliases", "device", "root", "origin", "branch", "access"
        }:
            raise WorkspaceRefused("REGISTRY_WORKSPACE_INVALID")
        if any(not isinstance(w[k], str) for k in ("key", "device", "root", "origin", "branch", "access")):
            raise WorkspaceRefused("REGISTRY_WORKSPACE_INVALID")
        if w["device"] != "windows-sandbox" or w["device"] not in device_keys:
            raise WorkspaceRefused("REGISTRY_UNAPPROVED_DEVICE")
        if w["access"] not in {"sandbox-clone", "public-source-only", "read-only-reference"}:
            raise WorkspaceRefused("REGISTRY_UNAPPROVED_ACCESS")
        if (not isinstance(w["aliases"], list) or not w["aliases"] or
            any(not isinstance(a, str) or a != a.strip() or not 0 < len(a) <= 60 for a in w["aliases"])):
            raise WorkspaceRefused("REGISTRY_ALIAS_INVALID")
        root = Path(w["root"])
        # Exactly one direct child of the fixed sandbox root. Never grant host filesystem.
        if root.parent != SANDBOX or root.name in {"", ".", ".."}:
            raise WorkspaceRefused("REGISTRY_ROOT_OUTSIDE_SANDBOX")
        expected_origin = "https://github.com/MikeMoore1337/" + root.name + ".git"
        if w["origin"] != expected_origin or w["branch"] not in {"main", "master"}:
            raise WorkspaceRefused("REGISTRY_ORIGIN_OR_BRANCH_INVALID")
        if w["key"] in seen_keys or w["root"] in seen_roots:
            raise WorkspaceRefused("REGISTRY_DUPLICATE_WORKSPACE")
        seen_keys.add(w["key"])
        seen_roots.add(w["root"])
        for alias in [w["key"], *w["aliases"]]:
            normalized = alias.casefold()
            if normalized in seen_aliases:
                raise WorkspaceRefused("REGISTRY_DUPLICATE_ALIAS")
            seen_aliases.add(normalized)
    return data


def find_workspace(registry: dict, name: str) -> dict:
    if not isinstance(name, str):
        raise WorkspaceRefused("WORKSPACE_ALIAS_REQUIRED")
    needle = name.strip().casefold()
    for workspace in registry["workspaces"]:
        if needle in {v.casefold() for v in [workspace["key"], *workspace["aliases"]]}:
            return workspace
    raise WorkspaceRefused("WORKSPACE_ALIAS_UNKNOWN")


def verify_clone(workspace: dict, sandbox: Path = SANDBOX) -> None:
    expected = sandbox / Path(workspace["root"]).name
    # The caller cannot choose any other root in the CLI.
    if str(expected) != workspace["root"] and sandbox == SANDBOX:
        raise WorkspaceRefused("WORKSPACE_ROOT_MISMATCH")
    for target in (sandbox.parent, sandbox, expected, expected / ".git"):
        _plain_directory(target)
    head = _small_regular_file(expected / ".git" / "HEAD", 256).strip()
    if head != "ref: refs/heads/" + workspace["branch"]:
        raise WorkspaceRefused("WORKSPACE_BRANCH_MISMATCH")
    raw = _small_regular_file(expected / ".git" / "config", MAX_CONFIG_BYTES)
    parser = configparser.RawConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(raw)
        origin = parser.get('remote "origin"', "url")
    except (configparser.Error, ValueError) as exc:
        raise WorkspaceRefused("WORKSPACE_GIT_CONFIG_INVALID") from exc
    if origin != workspace["origin"]:
        raise WorkspaceRefused("WORKSPACE_ORIGIN_MISMATCH")


def resolve(name: str, registry: dict, sandbox: Path = SANDBOX) -> dict:
    workspace = find_workspace(registry, name)
    verify_clone(workspace, sandbox=sandbox)
    device = next(d for d in registry["devices"] if d["key"] == workspace["device"])
    return {
        "key": workspace["key"],
        "deviceId": device["device_id"],
        "deviceName": device["display_name"],
        "deviceOnline": "NOT_CHECKED",
        "root": workspace["root"],
        "origin": workspace["origin"],
        "branch": workspace["branch"],
        "access": workspace["access"],
        "cloneMetadata": "VERIFIED",
        "gitSafeDirectory": workspace["root"],
        "gitTrackedClean": "NOT_CHECKED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("list", "resolve"))
    parser.add_argument("name", nargs="?")
    args = parser.parse_args(argv)
    try:
        registry = load_registry()
        if args.action == "list" and args.name is None:
            result = [resolve(w["key"], registry) for w in registry["workspaces"]]
        elif args.action == "resolve" and args.name is not None:
            result = resolve(args.name, registry)
        else:
            raise WorkspaceRefused("INVALID_REQUEST")
    except WorkspaceRefused as exc:
        print(json.dumps({"status": "DENIED", "reason": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps({"status": "PASS", "workspaces": result} if isinstance(result, list)
                     else {"status": "PASS", "workspace": result}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
