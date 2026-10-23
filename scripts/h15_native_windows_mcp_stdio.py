"""Hermes #454: dormant, local-only MCP stdio facade for ORIGINAL Windows files.

ONLY native_file_stat/native_file_read, backed by Win32 handle-bound reader.
No remote agent, TCP listener, arbitrary subprocess, filesystem write, policy
mutation or shell. No host activation occurs when this file is committed.

The owner must separately approve the concrete native Windows process launch.
STDIO process isolation is NOT an OS sandbox; deploy only with constrained OS
identity and verified Windows ACLs. ChatGPT cloud cannot reach this stdio
process until a separately approved authenticated transport is implemented.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, BinaryIO

from scripts import h15_native_windows_read as native

PROTOCOL = "2025-06-18"
SERVER = {"name": "hermes-original-windows-readonly", "version": "0.1.0"}
MAX_REQUEST_BYTES = 4096
MAX_REQUESTS = 64
MAX_READS = 16
TOOLS = (
    {
        "name": "native_file_stat",
        "description": "Read file/directory metadata in an owner-approved ORIGINAL Windows project. Does not list directories or execute commands.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "enum": sorted(native.READ_ROOTS)},
                "relative": {"type": "string", "maxLength": native.MAX_PATH_LENGTH},
            },
            "required": ["project", "relative"],
            "additionalProperties": False,
        },
        "annotations": {"title": "Windows original file metadata",
                        "readOnlyHint": True, "destructiveHint": False,
                        "openWorldHint": False},
    },
    {
        "name": "native_file_read",
        "description": "Read at most 256 KiB of one allowlisted source file on ORIGINAL Windows. Contents returned as base64; no shell or writes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string", "enum": sorted(native.READ_ROOTS)},
                "relative": {"type": "string", "minLength": 1, "maxLength": native.MAX_PATH_LENGTH},
            },
            "required": ["project", "relative"],
            "additionalProperties": False,
        },
        "annotations": {"title": "Windows original file read",
                        "readOnlyHint": True, "destructiveHint": False,
                        "openWorldHint": False},
    },
)


class ProtocolRefused(Exception):
    """Never include untrusted request content in outward error messages."""


def _unique_object(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ProtocolRefused("duplicate_field")
        result[key] = value
    return result


def parse_request(line: bytes) -> dict[str, Any]:
    if not isinstance(line, bytes) or not line or len(line) > MAX_REQUEST_BYTES:
        raise ProtocolRefused("invalid_input_length")
    try:
        result = json.loads(line.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError, RecursionError, ProtocolRefused) as exc:
        raise ProtocolRefused("invalid_json") from exc
    if not isinstance(result, dict) or result.get("jsonrpc") != "2.0":
        raise ProtocolRefused("invalid_rpc_envelope")
    if set(result) - {"jsonrpc", "method", "params", "id"}:
        raise ProtocolRefused("unexpected_rpc_fields")
    if not isinstance(result.get("method"), str) or len(result["method"]) > 128:
        raise ProtocolRefused("invalid_rpc_method")
    if "id" in result:
        identifier = result["id"]
        if (type(identifier) not in (str, int) or
            isinstance(identifier, str) and (not identifier or len(identifier) > 128)):
            raise ProtocolRefused("invalid_rpc_id")
    if "params" in result and not isinstance(result["params"], dict):
        raise ProtocolRefused("invalid_rpc_parameters")
    return result


def _ok(identifier: str | int, payload: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": identifier, "result": payload}


def _error(identifier: str | int | None, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": identifier,
            "error": {"code": code, "message": message}}


def _tool_error(identifier: str | int) -> dict[str, Any]:
    return _ok(identifier, {
        "isError": True,
        "content": [{"type": "text", "text": '{"status":"refused","reason":"native_read_denied"}'}]
    })


def _params_exact(params: dict[str, Any], *keys: str) -> bool:
    return set(params) == set(keys)


class McpSession:
    """Connection-local handshake, rate budget and dispatch. No state on disk."""

    def __init__(self):
        self.initialized = False
        self.read_calls = 0

    def handle(self, request: dict[str, Any]) -> dict[str, Any] | None:
        identifier = request.get("id")
        method = request["method"]
        params = request.get("params", {})
        if "id" not in request:
            if method == "notifications/initialized" and self.initialized:
                return None
            # Unknown notifications never invoke read tools or return data.
            return None
        if method == "initialize":
            if self.initialized or not _params_exact(params, "protocolVersion", "capabilities", "clientInfo"):
                return _error(identifier, -32602, "Invalid params")
            if params["protocolVersion"] != PROTOCOL:
                return _error(identifier, -32602, "Unsupported protocol")
            if (not isinstance(params["capabilities"], dict) or
                not isinstance(params["clientInfo"], dict)):
                return _error(identifier, -32602, "Invalid client")
            self.initialized = True
            return _ok(identifier, {"protocolVersion": PROTOCOL,
                                    "capabilities": {"tools": {"listChanged": False}},
                                    "serverInfo": SERVER})
        if not self.initialized:
            return _error(identifier, -32000, "Not initialized")
        if method == "ping":
            return _ok(identifier, {})
        if method == "tools/list":
            if params:
                return _error(identifier, -32602, "Invalid params")
            return _ok(identifier, {"tools": list(TOOLS)})
        if method != "tools/call":
            return _error(identifier, -32601, "Method not found")
        if not _params_exact(params, "name", "arguments"):
            return _error(identifier, -32602, "Invalid params")
        name, args = params["name"], params["arguments"]
        if name not in ("native_file_stat", "native_file_read") or not isinstance(args, dict):
            return _tool_error(identifier)
        if not _params_exact(args, "project", "relative"):
            return _tool_error(identifier)
        project, relative = args["project"], args["relative"]
        if type(project) is not str or type(relative) is not str:
            return _tool_error(identifier)
        if self.read_calls >= MAX_READS:
            return _tool_error(identifier)
        self.read_calls += 1
        operation = "stat" if name == "native_file_stat" else "read"
        try:
            # The Win32 helper is the actual per-handle scope check. No
            # ProcessRunner, shell, pathlib.read_bytes or native path fallback.
            result = native.handle_native_request(project, relative, operation)
        except (native.NativeReadRefused, OSError, ValueError):
            return _tool_error(identifier)
        return _ok(identifier, {
            "content": [{"type": "text",
                         "text": json.dumps(result, separators=(",", ":"),
                                            ensure_ascii=True)}],
            "isError": False,
        })


def serve(source: BinaryIO, sink: BinaryIO) -> int:
    """Line-delimited MCP JSON-RPC; no network, logging or filesystem writes."""
    session = McpSession()
    for _ in range(MAX_REQUESTS):
        line = source.readline(MAX_REQUEST_BYTES + 1)
        if not line:
            return 0
        if len(line) > MAX_REQUEST_BYTES or not line.endswith(b"\n"):
            # Do not resynchronize attacker-controlled oversized JSON.
            return 2
        try:
            obj = parse_request(line)
        except ProtocolRefused:
            response = _error(None, -32700, "Invalid request")
        else:
            response = session.handle(obj)
        if response is not None:
            encoded = json.dumps(response, ensure_ascii=True,
                                 separators=(",", ":")).encode("utf-8")
            sink.write(encoded + b"\n")
            sink.flush()
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dormant owner-scoped Win32 MCP stdio")
    parser.add_argument("--serve-stdio", action="store_true",
                        help="Requires separately approved Windows process launch")
    args = parser.parse_args(argv)
    if not args.serve_stdio or os.name != "nt":
        return 2
    return serve(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(main())
