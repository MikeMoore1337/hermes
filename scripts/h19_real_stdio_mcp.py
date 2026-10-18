"""H-19 opt-in real MCP stdio protocol/dispatcher probe inside pinned disposable Docker.

This calls the REAL upstream Hermes MCP client and a local MCP SDK server, when
the optional SDK is installed in the immutable image. No providers, external
MCP servers, credentials, host mounts or production agent are used.
Missing MCP SDK is INCONCLUSIVE, never treated as a successful MCP test.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from .bounded_subprocess import BoundedProcessError, run_bounded
from .verify_v0222_immutable import IMAGE, EXPECTED_SOURCE, commands, image_identity, stamp_details

SCHEMA = "h19-real-mcp-stdio-v1"
PROBE = r"""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

SCHEMA = "h19-real-mcp-stdio-v1"
report = {
    "schema": SCHEMA,
    "sdk": "UNAVAILABLE",
    "registration": "NOT_RUN",
    "read_result": "NOT_RUN",
    "write_denied_result": "NOT_RUN",
    "write_approved_result": "NOT_RUN",
    "server_write_after_denial": None,
    "server_write_after_approval": None,
    "real_protocol": False,
    "agent_dispatch": False,
    "actual_external_mcp": False,
    "real_provider": False,
    "real_agent_resident": False,
    "sdk_server_import": "NOT_RUN",
    "registered_tool_count": 0,
    "discovery_errors_observed": False,
    "wire_read_after_read": None,
    "wire_write_after_denial": None,
    "wire_write_after_approval": None,
}
if importlib.util.find_spec("mcp") is None:
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0)

report["sdk"] = "AVAILABLE"
try:
    from mcp.server import MCPServer
    from mcp_types import ToolAnnotations
    report["sdk_server_import"] = "PASS"
except Exception:
    report["sdk_server_import"] = "FAILED"
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0)
# A real MCP SDK server. Stdio stays inside container, child uses this pinned
# venv interpreter and the only persistent effect is a private /tmp marker.
SERVER = '''
import os
import json
import threading
from pathlib import Path
from mcp.server import MCPServer
from mcp_types import ToolAnnotations

app = MCPServer("h19_local")
MARKER = Path(os.environ["H19_MCP_MARKER"])
WIRE_LOG = Path(os.environ["H19_MCP_WIRE_LOG"])

# Record only the public fixed tool NAME from the real MCP JSON-RPC stdin wire;
# do not store source text, arguments, ids, tokens, prompt data or responses.
def capture_wire():
    read_fd, write_fd = os.pipe()
    original_stdin = os.dup(0)
    os.dup2(read_fd, 0)
    os.close(read_fd)

    def pump():
        pending = b""
        with os.fdopen(original_stdin, "rb", buffering=0) as source:
            with os.fdopen(write_fd, "wb", buffering=0) as destination:
                while True:
                    chunk = os.read(source.fileno(), 65536)
                    if not chunk:
                        break
                    pending += chunk
                    *frames, pending = pending.split(b"\n")
                    for frame in frames:
                        try:
                            message = json.loads(frame)
                            method = message.get("method") if isinstance(message, dict) else None
                            params = message.get("params") if isinstance(message, dict) else None
                            name = params.get("name") if isinstance(params, dict) else None
                            if method == "tools/call" and name in ("peek", "mark"):
                                with WIRE_LOG.open("a", encoding="ascii") as evidence:
                                    evidence.write(name + "\n")
                        except (ValueError, OSError, TypeError):
                            pass
                    destination.write(chunk)
    threading.Thread(target=pump, daemon=True, name="h19-mcp-wire").start()

@app.tool(annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False))
def peek() -> str:
    # Read-only synthetic ping; no writes or external IO.
    return "H19_MCP_READ_OK"

@app.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True))
def mark() -> str:
    # Write only a harmless constant marker inside /tmp.
    MARKER.write_text("H19_MCP_WRITE_OK", encoding="ascii")
    return "H19_MCP_WRITE_OK"

if __name__ == "__main__":
    capture_wire()
    app.run(transport="stdio")
'''
with tempfile.TemporaryDirectory(prefix="h19-mcp-", dir="/tmp") as tmp:
    root = Path(tmp)
    source = root / "stdio_server.py"
    source.write_text(SERVER, encoding="utf-8")
    marker = root / "server-marker"
    wire_log = root / "inbound-wire"
    def wire():
        if not wire_log.exists():
            return []
        return wire_log.read_text(encoding="ascii").splitlines()
    from tools.mcp_tool_discovery import register_mcp_servers
    from tools.mcp_tool_lifecycle import shutdown_mcp_servers
    import model_tools

    name = "h19local"
    config = {
        "command": sys.executable,
        "args": ["-B", "-u", str(source)],
        "env": {"H19_MCP_MARKER": str(marker), "H19_MCP_WIRE_LOG": str(wire_log)},
        "trust": "untrusted",
        "connect_timeout": 13,
        "tool_timeout": 12,
        "tools": {"resources": False, "prompts": False},
    }
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            names = register_mcp_servers({name: config})
        expected = {"mcp__h19local__peek", "mcp__h19local__mark"}
        report["registration"] = "OK" if expected <= set(names) else "MISSING_TOOLS"
        report["registered_tool_count"] = len(names)
        if report["registration"] != "OK":
            from tools import mcp_tool as core
            report["discovery_errors_observed"] = bool(core._server_connect_errors)
        if report["registration"] == "OK":
            report["real_protocol"] = True
            report["agent_dispatch"] = True
            def dispatch(tool, answer):
                with patch("tools.approval_prompt.request_elicitation_consent", return_value=answer):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        return model_tools.handle_function_call(
                            tool, {}, enabled_toolsets=["mcp-h19local"],
                            disabled_toolsets=[], skip_tool_execution_middleware=True,
                            skip_tool_request_middleware=True, skip_pre_tool_call_hook=True,
                        )

            read = dispatch("mcp__h19local__peek", "deny")
            report["wire_read_after_read"] = wire().count("peek")
            report["read_result"] = "OK" if "H19_MCP_READ_OK" in str(read) else "FAILED"
            denied = dispatch("mcp__h19local__mark", "deny")
            report["server_write_after_denial"] = marker.exists()
            report["wire_write_after_denial"] = wire().count("mark")
            report["write_denied_result"] = ("OK" if not marker.exists() and
                ("approve" in str(denied).lower() or "not run" in str(denied).lower()
                 or "did not" in str(denied).lower() or "blocked" in str(denied).lower())
                else "FAILED")
            allowed = dispatch("mcp__h19local__mark", "accept")
            report["server_write_after_approval"] = marker.read_text(encoding="ascii") if marker.exists() else None
            report["wire_write_after_approval"] = wire().count("mark")
            report["write_approved_result"] = ("OK" if
                report["server_write_after_approval"] == "H19_MCP_WRITE_OK"
                and "H19_MCP_WRITE_OK" in str(allowed) else "FAILED")
    finally:
        try:
            shutdown_mcp_servers()
        except Exception:
            pass

print(json.dumps(report, sort_keys=True))
"""


class EvidenceDenied(ValueError):
    """Invalid or incomplete real MCP evidence, with no user data in errors."""


def validate(data: Any) -> dict[str, Any]:
    required = {
        "schema", "sdk", "registration", "read_result",
        "write_denied_result", "write_approved_result",
        "server_write_after_denial", "server_write_after_approval",
        "real_protocol", "agent_dispatch", "actual_external_mcp",
        "real_provider", "real_agent_resident",
        "sdk_server_import", "registered_tool_count", "discovery_errors_observed",
        "wire_read_after_read", "wire_write_after_denial", "wire_write_after_approval",
    }
    if (type(data) is not dict or set(data) != required or data["schema"] != SCHEMA
            or data["sdk"] not in ("AVAILABLE", "UNAVAILABLE")
            or type(data["registered_tool_count"]) is not int
            or type(data["discovery_errors_observed"]) is not bool
            or data["sdk_server_import"] not in ("PASS", "FAILED", "NOT_RUN")
            or any(data[k] is not False for k in (
                "actual_external_mcp", "real_provider", "real_agent_resident"))):
        raise EvidenceDenied("MCP_REPORT_SCHEMA_INVALID")
    if data["sdk"] == "UNAVAILABLE":
        if (data["registration"] != "NOT_RUN"
                or data["sdk_server_import"] != "NOT_RUN"
                or data["registered_tool_count"] != 0
                or data["real_protocol"] is not False
                or data["agent_dispatch"] is not False
                or data["server_write_after_denial"] is not None
                or any(data[k] is not None for k in (
                    "wire_read_after_read", "wire_write_after_denial",
                    "wire_write_after_approval"))):
            raise EvidenceDenied("MCP_SDK_ABSENCE_OVERCLAIM")
        status = "NOT_RUN"
    else:
        status = ("PASS" if (
            data["sdk_server_import"] == "PASS"
            and data["registered_tool_count"] >= 2
            and data["registration"] == "OK"
            and type(data["wire_read_after_read"]) is int
            and data["wire_read_after_read"] == 1
            and type(data["wire_write_after_denial"]) is int
            and data["wire_write_after_denial"] == 0
            and type(data["wire_write_after_approval"]) is int
            and data["wire_write_after_approval"] == 1
            and data["read_result"] == "OK"
            and data["write_denied_result"] == "OK"
            and data["write_approved_result"] == "OK"
            and data["server_write_after_denial"] is False
            and data["server_write_after_approval"] == "H19_MCP_WRITE_OK"
            and data["real_protocol"] is True
            and data["agent_dispatch"] is True) else "FAIL")
    return {
        "schema": SCHEMA, "status": status, "mode": "isolated_real_mcp_stdio_with_local_server",
        "image": IMAGE, "upstream_source_stamp": EXPECTED_SOURCE,
        "observations": data,
        "full_mcp_permission_enforcement_verified": False,
        "external_mcp_effects_verified": False,
        "real_model_evaluation": "NOT_RUN",
        "resident_agent_allowed": False,
    }


def capture(*, runner=run_bounded) -> tuple[int, dict[str, Any]]:
    inspect, stamp_cmd, docker = commands()
    try:
        im = runner(inspect, timeout=20, stdout_limit=8192, stderr_limit=8192)
        if im.returncode or not image_identity(im.stdout):
            raise EvidenceDenied("MCP_IMAGE_IDENTITY_DENIED")
        stamp = runner(stamp_cmd, timeout=35, stdout_limit=4096, stderr_limit=4096)
        if stamp.returncode or stamp_details(stamp.stdout).get("matches_source") is not True:
            raise EvidenceDenied("MCP_STAMP_IDENTITY_DENIED")
        cmd = list(docker)
        cmd[-1] = PROBE
        x = runner(cmd, timeout=90, stdout_limit=12_000, stderr_limit=8192)
        if x.returncode:
            raise EvidenceDenied("MCP_SANDBOX_EXECUTION_FAILED")
        report = validate(json.loads(x.stdout))
        return (0 if report["status"] == "PASS" else
                1 if report["status"] == "FAIL" else 3), report
    except (EvidenceDenied, OSError, BoundedProcessError, ValueError, TypeError, KeyError):
        return 2, {"schema": SCHEMA, "status": "INFRA_FAILURE",
                   "real_model_evaluation": "NOT_RUN", "resident_agent_allowed": False,
                   "full_mcp_permission_enforcement_verified": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"schema": SCHEMA, "status": "NOT_RUN", "resident_agent_allowed": False}))
        return 0
    code, report = capture()
    if args.out:
        try:
            args.out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        except OSError:
            return 2
    print("H-19 real local MCP stdio:", report["status"], "(provider NOT_RUN; resident NO_GO)")
    return code


if __name__ == "__main__":
    sys.exit(main())
