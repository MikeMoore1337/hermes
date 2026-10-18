"""Issue #297: isolated loopback simulator; no executable device operations.

This is a testable transport/protocol spike, NOT a deployable WSS/TLS relay.
No systemd unit, production route, background worker, SSH or Desktop Commander
credential is used. MCP tools are deliberately limited to read-only status.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

MAX_FRAME = 4096
DEVICE_RE = re.compile(r"^[a-z][a-z0-9_-]{1,39}$")


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _digest(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


class Denied(ValueError):
    """No untrusted tool payload is included in errors."""


@dataclass
class DeviceState:
    name: str
    online: bool = False
    last_seen: str | None = None
    connection: asyncio.StreamWriter | None = None
    # No capabilities can execute during the offline pilot.


class LoopbackRelay:
    """Only 127.0.0.1 and RAM state. No command dispatch or replay queue."""

    def __init__(self, *, heartbeat_timeout: float = 2.0):
        if not 0.05 <= heartbeat_timeout <= 60:
            raise ValueError("invalid_timeout")
        self.timeout = heartbeat_timeout
        self._pending: dict[str, tuple[str, str]] = {}
        self._keys: dict[str, bytes] = {}
        self._states: dict[str, DeviceState] = {}
        self._server: asyncio.AbstractServer | None = None
        self.port: int | None = None

    def request_pair(self, device_id: str, name: str) -> str:
        if not isinstance(device_id, str) or not DEVICE_RE.fullmatch(device_id):
            raise Denied("invalid_device")
        if not isinstance(name, str) or not 1 <= len(name) <= 60:
            raise Denied("invalid_name")
        if device_id in self._keys or any(key == device_id for key, _ in self._pending.values()):
            raise Denied("already_registered")
        code = secrets.token_urlsafe(18)
        self._pending[code] = (device_id, name)
        return code

    def approve_pair(self, code: str) -> str:
        if not isinstance(code, str) or code not in self._pending:
            raise Denied("not_pending")
        device_id, name = self._pending.pop(code)
        token = secrets.token_urlsafe(32)
        self._keys[device_id] = _digest(token)
        self._states[device_id] = DeviceState(name=name)
        return token

    def revoke(self, device_id: str) -> None:
        self._keys.pop(device_id, None)
        self._pending = {code: value for code, value in self._pending.items() if value[0] != device_id}
        state = self._states.pop(device_id, None)
        if state and state.connection:
            state.connection.close()

    async def start(self) -> None:
        if self._server:
            raise RuntimeError("already_started")
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0, limit=MAX_FRAME)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        for state in self._states.values():
            if state.connection:
                state.connection.close()
                state.connection = None
                state.online = False

    def list_devices(self) -> list[dict]:
        return [self.device_status(key) for key in sorted(self._states)]

    def device_status(self, device_id: str) -> dict:
        state = self._states.get(device_id)
        if not state:
            raise Denied("unknown_device")
        return {"device_id": device_id, "name": state.name,
                "status": "online" if state.online else "offline",
                "last_seen": state.last_seen, "capabilities": ["device_status"],
                "execution": "disabled"}

    async def _frame(self, reader: asyncio.StreamReader) -> dict:
        try:
            packet = await asyncio.wait_for(reader.readuntil(b"\n"), self.timeout)
        except (asyncio.LimitOverrunError, ValueError) as exc:
            raise Denied("frame_too_large") from exc
        if len(packet) > MAX_FRAME:
            raise Denied("frame_too_large")
        try:
            value = json.loads(packet)
        except (UnicodeError, ValueError) as exc:
            raise Denied("invalid_json") from exc
        if not isinstance(value, dict):
            raise Denied("invalid_packet")
        return value

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, payload: dict) -> None:
        writer.write(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
        await writer.drain()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        device_id = None
        try:
            hello = await self._frame(reader)
            ident, token = hello.get("device_id"), hello.get("token")
            if hello.get("type") != "hello" or not isinstance(ident, str) or not isinstance(token, str):
                raise Denied("unauthorized")
            expected = self._keys.get(ident)
            if expected is None or not hmac.compare_digest(expected, _digest(token)):
                raise Denied("unauthorized")
            state = self._states[ident]
            if state.online:
                raise Denied("already_online")
            device_id = ident
            state.online, state.connection, state.last_seen = True, writer, _stamp()
            await self._reply(writer, {"type": "welcome"})
            while True:
                message = await self._frame(reader)
                if message.get("type") == "heartbeat":
                    state.last_seen = _stamp()
                    await self._reply(writer, {"type": "alive"})
                else:
                    # Never dispatch file/process/command requests, not even to emulators.
                    await self._reply(writer, {"type": "error", "code": "commands_disabled"})
        except (Denied, asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError) as exc:
            code = str(exc) if isinstance(exc, Denied) else "connection_closed"
            try:
                await self._reply(writer, {"type": "error", "code": code})
            except (ConnectionError, OSError):
                pass
        finally:
            if device_id:
                state = self._states.get(device_id)
                if state and state.connection is writer:
                    state.online, state.connection = False, None
                    state.last_seen = _stamp()
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


class ReadOnlyMCP:
    """Offline JSON-RPC handler; no stdio/service adapter is activated."""

    def __init__(self, relay: LoopbackRelay):
        self.relay = relay

    def handle(self, request: dict) -> dict | None:
        if request.get("method") == "notifications/initialized":
            return None
        rid = request.get("id")
        method = request.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "hermes-device-fabric-offline-poc", "version": "0.0.1"}}
        elif method == "tools/list":
            result = {"tools": [
                {"name": "list_devices", "description": "Read-only paired device status",
                 "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
                 "annotations": {"readOnlyHint": True}},
                {"name": "get_device_status", "description": "Read-only status of one paired device",
                 "inputSchema": {"type": "object", "properties": {"device_id": {"type": "string"}},
                                 "required": ["device_id"], "additionalProperties": False},
                 "annotations": {"readOnlyHint": True}},
            ]}
        elif method == "tools/call":
            params = request.get("params")
            if not isinstance(params, dict) or params.get("name") not in ("list_devices", "get_device_status"):
                return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "not_allowed"}}
            arguments = params.get("arguments", {})
            if not isinstance(arguments, dict):
                return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "invalid_arguments"}}
            try:
                if params["name"] == "list_devices":
                    if arguments:
                        raise Denied("invalid_arguments")
                    value = self.relay.list_devices()
                else:
                    if set(arguments) != {"device_id"} or not isinstance(arguments["device_id"], str):
                        raise Denied("invalid_arguments")
                    value = self.relay.device_status(arguments["device_id"])
            except Denied:
                return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "invalid_arguments"}}
            result = {"content": [{"type": "text", "text": json.dumps(value)}]}
        else:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "not_allowed"}}
        return {"jsonrpc": "2.0", "id": rid, "result": result}
