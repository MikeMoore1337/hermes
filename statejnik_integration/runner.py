"""Explicit offline execution of the owner's fully vendored statejnik tools.

Default: inventory only. --execute runs a named upstream script in a pinned,
no-network, non-root, read-only Docker process. It does not grant publication,
Wordstat credentials, model execution, integrations or private-vault access.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from .provenance import ROOT, ProvenanceDenied, verify

IMAGE = ("nousresearch/hermes-agent@sha256:"
         "a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05")
PYTHON = "/opt/hermes/.venv/bin/python"
WORKSPACE_MARKER = ".hermes-statejnik-offline"
WORKSPACE_MARKER_CONTENT = "offline-only\\n"

# This includes every upstream *entrypoint*; the five private helper modules
# are deployed next to these scripts but are not executable as CLI tools.
OFFLINE_TOOLS = frozenset({
    "ai-cadence-check", "check-all", "claims-check", "originality-check",
    "prompt", "read-aloud-check", "status", "structure-check",
})
SOURCE_TOOLS = frozenset({"site", "keywords", "fetch-source"})
PUBLISH_TOOLS = frozenset({"publish"})
ALL_TOOLS = OFFLINE_TOOLS | SOURCE_TOOLS | PUBLISH_TOOLS
TOOL_CLASSES = {
    **dict.fromkeys(OFFLINE_TOOLS, "OFFLINE_MANUAL"),
    **dict.fromkeys(SOURCE_TOOLS, "NETWORK_REQUIRES_SEPARATE_GO"),
    **dict.fromkeys(PUBLISH_TOOLS, "PUBLISH_REQUIRES_SEPARATE_GO"),
}


class StatejnikDenied(ValueError):
    """Fixed reason codes. Never echo arguments, secrets or working files."""


def catalog() -> dict[str, object]:
    return {
        "status": "FULL_SOURCE_INSTALLED_RUNTIME_DISABLED",
        "upstream_commit": "4de2944a31eaffdba4463cdbea115191cb551300",
        "features": dict(sorted(TOOL_CLASSES.items())),
        "registered_entrypoints": len(ALL_TOOLS),
        "upstream_helper_modules": 5,
        "network_enabled": False,
        "paid_providers_enabled": False,
        "automatic_publication_enabled": False,
        "yfc_write_enabled": False,
        "resident_agent_allowed": False,
    }


def docker_command(tool: str, workspace: Path, arguments: list[str]) -> list[str]:
    """Build an argv-only Docker command; does not start any subprocess."""
    if type(tool) is not str or tool not in OFFLINE_TOOLS:
        raise StatejnikDenied("tool_requires_separate_permission")
    if type(arguments) is not list or len(arguments) > 32 or any(
        type(arg) is not str or len(arg) > 512 or "\x00" in arg for arg in arguments
    ):
        raise StatejnikDenied("arguments_invalid")
    if (not workspace.is_dir() or workspace.is_symlink()
            or workspace.resolve() == ROOT.resolve()
            or workspace.resolve() == ROOT.parents[1].resolve()):
        raise StatejnikDenied("workspace_invalid")
    marker = workspace / WORKSPACE_MARKER
    if marker.is_symlink() or not marker.is_file():
        raise StatejnikDenied("workspace_not_admitted")
    try:
        if marker.read_text(encoding="utf-8") != WORKSPACE_MARKER_CONTENT:
            raise StatejnikDenied("workspace_not_admitted")
    except OSError:
        raise StatejnikDenied("workspace_not_admitted") from None
    scripts = ROOT / "skills" / "statejnik" / "scripts"
    if not (scripts / f"{tool}.py").is_file():
        raise StatejnikDenied("script_missing")
    vendor = str(ROOT.resolve())
    workdir = str(workspace.resolve())
    if "," in vendor or "," in workdir or "\n" in vendor or "\n" in workdir:
        raise StatejnikDenied("unsafe_mount_path")
    return [
        "docker", "run", "--rm", "--pull=never", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--cpus", "1", "--memory", "768m", "--memory-swap", "768m",
        "--pids-limit", "64",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--mount", f"type=bind,source={vendor},target=/statejnik,readonly",
        "--mount", f"type=bind,source={workdir},target=/work",
        "--workdir", "/work", "--env", "HOME=/tmp",
        "--env", "PYTHONDONTWRITEBYTECODE=1",
        "--entrypoint", PYTHON, IMAGE, "-B",
        f"/statejnik/skills/statejnik/scripts/{tool}.py", *arguments,
    ]


def run(tool: str, workspace: Path, arguments: list[str]) -> int:
    # The source is checked *before* Docker receives a command.
    try:
        verify()
        command = docker_command(tool, workspace, arguments)
    except (ProvenanceDenied, StatejnikDenied, OSError) as exc:
        raise StatejnikDenied("offline_admission_denied") from exc
    # Shell-free and no host env/credentials forwarded. Execution timeout is
    # a bound on the single process; no retry or network fallback exists.
    try:
        completed = subprocess.run(command, check=False, timeout=120,
                                   env={"PATH": os.environ.get("PATH", "")},
                                   capture_output=True, text=True)
    except (subprocess.TimeoutExpired, OSError):
        raise StatejnikDenied("offline_sandbox_unavailable") from None
    # Vendor output may include user-authored work text. Never copy it into
    # public CI logs or the Hermes status stream.
    return int(completed.returncode)


def initialize_workspace(workspace: Path) -> None:
    """Admit only an existing, empty operator-chosen directory."""
    if workspace.is_symlink() or not workspace.is_dir():
        raise StatejnikDenied("workspace_invalid")
    if workspace.resolve() in (ROOT.resolve(), ROOT.parents[1].resolve()):
        raise StatejnikDenied("workspace_invalid")
    try:
        if any(workspace.iterdir()):
            raise StatejnikDenied("workspace_not_empty")
        marker = workspace / WORKSPACE_MARKER
        with marker.open("x", encoding="utf-8") as stream:
            stream.write(WORKSPACE_MARKER_CONTENT)
    except OSError:
        raise StatejnikDenied("workspace_not_admitted") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hermes-approved statejnik offline gate")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--init-workspace", action="store_true")
    parser.add_argument("--tool", choices=sorted(ALL_TOOLS))
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("tool_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.init_workspace:
        try:
            if args.execute or args.tool is not None or args.workspace is None:
                raise StatejnikDenied("operator_scope_invalid")
            initialize_workspace(args.workspace)
        except StatejnikDenied as exc:
            print(json.dumps({"status": "REJECTED", "reason": str(exc)}))
            return 2
        print(json.dumps({"status": "OFFLINE_WORKSPACE_ADMITTED"}))
        return 0
    if not args.execute:
        print(json.dumps(catalog(), sort_keys=True))
        return 0
    try:
        if args.tool is None or args.workspace is None:
            raise StatejnikDenied("operator_scope_missing")
        arguments = args.tool_args[1:] if args.tool_args[:1] == ["--"] else args.tool_args
        status = run(args.tool, args.workspace, arguments)
    except StatejnikDenied as exc:
        print(json.dumps({"status": "REJECTED", "reason": str(exc),
                          "network_enabled": False, "resident_agent_allowed": False}))
        return 2
    result = {"status": "OFFLINE_TOOL_COMPLETED" if status == 0 else "OFFLINE_TOOL_FAILED",
              "exit_code": status, "network_enabled": False,
              "publication_enabled": False, "resident_agent_allowed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if status == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
