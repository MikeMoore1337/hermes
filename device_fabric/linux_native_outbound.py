"""Dormant Linux original-host outbound READ bridge for Hermes #454 Stage 2A.

Uses the EXISTING authenticated owner BRC device/WSS transport protocol.
This is not a new MCP server, agent installer, host service or relay route.
The owner must separately approve the native Linux device, exact root/OS
identity, relay/WSS pairing, encrypted channel, host service and activation.
No services, sockets or native host access occur when imported.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import platform
import re
import time
from typing import Any, Callable, Protocol

from device_fabric.linux_native_read_dispatch import (
    LinuxOriginalReadDispatcher, NativeLinuxReadDenied,
    READ, STAT, LIST, SEARCH, parse_call,
)

# Existing BRC device protocol v1. Keep output compatible with the reviewed
# Windows original-file adapter; NEVER advertise generic BRC shell/write.
WIRE_PROTOCOL = 1
ENDPOINT = "wss://hermes.mikemoore.top/ws"
MAX_INBOUND = 8192
MAX_DISPATCH = 4096
MAX_RESPONSE = 512 * 1024
MAX_SESSION_SECONDS = 240
MAX_MESSAGES = 80
MAX_TOOL_CALLS = 16
MAX_SEEN_IDS = 64
MAX_PING_INTERVAL = 15.0
TOKEN = re.compile(r"[A-Za-z0-9_.~-]{40,256}\Z")
REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
NATIVE_IDS = {
    "hermes-vps": re.compile(r"h454-linux-hermes-[0-9a-f]{16,32}\Z"),
    "yfc-vps": re.compile(r"h454-linux-yfc-[0-9a-f]{16,32}\Z"),
}
NAMES = {
    "hermes-vps": "H454 Hermes VPS native read-only",
    "yfc-vps": "H454 YFC VPS native read-only",
}


class LinuxOutboundDenied(ValueError):
    """Generic transport error without token, host paths or source contents."""


@dataclass(frozen=True, slots=True, repr=False)
class LocalLinuxDeviceConfig:
    """Locally protected, owner-paired device; NOT a remote MCP argument."""

    target: str
    device_id: str
    token: str
    url: str

    def __repr__(self) -> str:
        # A default dataclass repr would disclose the live bearer in trace
        # logs. Even the local runtime must never stringify credentials.
        return "LocalLinuxDeviceConfig([REDACTED])"


class WebSocket(Protocol):
    def __enter__(self) -> "WebSocket": ...
    def __exit__(self, *args: Any) -> object: ...
    def send(self, message: str) -> None: ...
    def recv(self, timeout: float | None = None) -> str | bytes: ...


def local_config(*, target: str, device_id: str, token: str,
                 url: str = ENDPOINT) -> LocalLinuxDeviceConfig:
    """Accept only a future separately owner-enrolled native identity.

    This source cannot enroll a device. A syntactically valid ID/token is
    not proof of an authenticated pairing or authorization.
    """
    if (type(target) is not str or target not in NATIVE_IDS
        or type(device_id) is not str
        or NATIVE_IDS[target].fullmatch(device_id) is None
        or type(token) is not str or TOKEN.fullmatch(token) is None
        or type(url) is not str or url != ENDPOINT):
        raise LinuxOutboundDenied("native_linux_transport_denied")
    return LocalLinuxDeviceConfig(target, device_id, token, url)


def _tool(name: str, summary: str, fields: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "name": name,
        "description": summary,
        "inputSchema": {
            "type": "object",
            "properties": fields,
            "required": list(fields),
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True, "destructiveHint": False,
            "openWorldHint": False,
        },
    }


_PROJECT = {"type": "string"}
_RELATIVE = {"type": "string", "maxLength": 1024}
_QUERY = {"type": "string", "minLength": 1, "maxLength": 96}
_TOOL_CATALOG = (
    _tool(STAT, "Stat one approved original Linux source path.",
          {"project": _PROJECT, "relative": _RELATIVE}),
    _tool(READ, "Read at most 256 KiB from one approved original Linux source file.",
          {"project": _PROJECT, "relative": _RELATIVE}),
    _tool(LIST, "List at most 64 safe entries from an approved Linux directory.",
          {"project": _PROJECT, "relative": _RELATIVE}),
    _tool(SEARCH, "Bounded literal source search; relative paths/line numbers only.",
          {"project": _PROJECT, "query": _QUERY,
           "mode": {"type": "string", "enum": ["names", "content"]},
           "relative_root": _RELATIVE}),
)
_CATALOG_NAMES = frozenset(x["name"] for x in _TOOL_CATALOG)


def advertised_tools() -> list[dict[str, Any]]:
    """Return a new JSON-owned tree; callers may not mutate the catalog."""
    return json.loads(json.dumps(_TOOL_CATALOG))


def hello(config: LocalLinuxDeviceConfig) -> dict[str, Any]:
    if (type(config) is not LocalLinuxDeviceConfig
        or config.target not in NATIVE_IDS
        or NATIVE_IDS[config.target].fullmatch(config.device_id) is None
        or config.url != ENDPOINT
        or TOKEN.fullmatch(config.token) is None):
        raise LinuxOutboundDenied("native_linux_transport_denied")
    arch = {
        "x86_64": "x64", "amd64": "x64", "aarch64": "arm64",
    }.get(platform.machine().lower())
    if arch is None:
        raise LinuxOutboundDenied("native_linux_transport_denied")
    return {
        "type": "hello", "protocol": WIRE_PROTOCOL,
        "device": {
            "deviceId": config.device_id,
            "name": NAMES[config.target],
            "platform": "linux",
            "arch": arch,
            "hostname": "hermes-native-readonly",
            "agentVersion": "0.1.0",
            "coreVersion": "h454-native-linux-read-v1",
        },
        "tools": advertised_tools(),
    }


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for name, value in pairs:
        if name in out:
            raise LinuxOutboundDenied("native_linux_transport_denied")
        out[name] = value
    return out


def decode_message(raw: str | bytes) -> dict[str, Any]:
    try:
        if (type(raw) not in (str, bytes) or
            len(raw if type(raw) is bytes else raw.encode("utf-8")) > MAX_INBOUND):
            raise LinuxOutboundDenied("native_linux_transport_denied")
        frame = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise LinuxOutboundDenied("native_linux_transport_denied") from None
    if type(frame) is not dict or type(frame.get("type")) is not str:
        raise LinuxOutboundDenied("native_linux_transport_denied")
    return frame


def _rpc_payload(msg: dict[str, Any]) -> tuple[str, bytes] | None:
    """Translate BRC's fixed call wire into the local bounded dispatcher."""
    if (set(msg) - {"type", "id", "tool", "args", "client", "timeoutMs"}
        or msg.get("type") != "call"
        or type(msg.get("id")) is not str
        or REQUEST_ID.fullmatch(msg["id"]) is None
        or type(msg.get("tool")) is not str
        or msg["tool"] not in _CATALOG_NAMES
        or type(msg.get("args")) is not dict):
        return None
    if "timeoutMs" in msg and (type(msg["timeoutMs"]) is not int
                               or not 1 <= msg["timeoutMs"] <= 30_000):
        return None
    if "client" in msg:
        # Existing reviewed BRC relay sends {client:{name:ctx.clientId},
        # timeoutMs:8000}; a bare client string would discard valid calls.
        client = msg["client"]
        if (type(client) is not dict or set(client) != {"name"}
            or type(client["name"]) is not str
            or not 1 <= len(client["name"]) <= 128
            or any(ord(ch) < 32 or ord(ch) == 127
                   for ch in client["name"])):
            return None
    try:
        raw = json.dumps(
            {"type": "call", "id": msg["id"],
             "tool": msg["tool"], "args": msg["args"]},
            ensure_ascii=True, separators=(",", ":")).encode("ascii")
        if len(raw) > MAX_DISPATCH:
            return None
        parse_call(raw)
        return msg["id"], raw
    except (ValueError, TypeError, OverflowError, UnicodeError):
        return None


def _result_frame(msg_id: str, result: dict[str, Any], *,
                  refused: bool = False) -> str:
    payload = (
        {"status": "refused", "reason": "native_linux_read_denied"}
        if refused else result
    )
    frame: dict[str, Any] = {
        "type": "result", "id": msg_id,
        "result": {
            "content": [
                {"type": "text", "text": json.dumps(
                    payload, sort_keys=True, ensure_ascii=True,
                    separators=(",", ":"))}
            ],
        },
    }
    if refused:
        frame["result"]["isError"] = True
    raw = json.dumps(frame, ensure_ascii=True, separators=(",", ":"))
    if len(raw.encode("utf-8")) > MAX_RESPONSE:
        if refused:
            raise LinuxOutboundDenied("native_linux_transport_denied")
        return _result_frame(msg_id, {}, refused=True)
    return raw


def run_session(config: LocalLinuxDeviceConfig,
                dispatcher: LinuxOriginalReadDispatcher,
                connector: Callable[..., WebSocket],
                *, monotonic: Callable[[], float] = time.monotonic) -> str:
    """One bounded outbound owner-paired WSS session, no reconnect or replay.

    External code must enforce OS isolation and supply an independently
    authenticated local device config. No automatic relay/pairing/host
    activation is offered by this source-only module.
    """
    if (type(config) is not LocalLinuxDeviceConfig
        or type(dispatcher) is not LinuxOriginalReadDispatcher
        or type(config.target) is not str or config.target not in NATIVE_IDS
        or type(config.device_id) is not str
        or NATIVE_IDS[config.target].fullmatch(config.device_id) is None
        or config.url != ENDPOINT
        or type(config.token) is not str or TOKEN.fullmatch(config.token) is None
        or dispatcher.device_id != config.device_id
        or not callable(connector) or not callable(monotonic)):
        raise LinuxOutboundDenied("native_linux_transport_denied")
    if _CATALOG_NAMES != frozenset({READ, STAT, LIST, SEARCH}):
        raise LinuxOutboundDenied("native_linux_transport_denied")

    seen: set[str] = set()
    welcome = False
    processed = 0
    deadline = monotonic() + MAX_SESSION_SECONDS
    try:
        conn = connector(
            config.url,
            additional_headers={
                "Authorization": "Bearer " + config.token,
                "X-BRC-Protocol": str(WIRE_PROTOCOL),
            },
            open_timeout=10, close_timeout=3,
            compression=None, proxy=None, max_size=MAX_INBOUND,
            ping_interval=20, ping_timeout=20,
        )
        with conn as ws:
            ws.send(json.dumps(hello(config), separators=(",", ":")))
            for _ in range(MAX_MESSAGES):
                remaining = deadline - monotonic()
                if remaining <= 0:
                    return "session_deadline"
                try:
                    raw = ws.recv(timeout=min(MAX_PING_INTERVAL, remaining))
                except TimeoutError:
                    return "idle_timeout"
                msg = decode_message(raw)
                typ = msg["type"]
                if typ == "welcome":
                    if (welcome or set(msg) !=
                        {"type", "protocol", "relayVersion", "serverTime"}
                        or type(msg["protocol"]) is not int
                        or msg["protocol"] != WIRE_PROTOCOL
                        or type(msg["relayVersion"]) is not str
                        or not 1 <= len(msg["relayVersion"]) <= 80
                        or type(msg["serverTime"]) is not int
                        or msg["serverTime"] < 0):
                        raise LinuxOutboundDenied("native_linux_transport_denied")
                    welcome = True
                    continue
                if not welcome:
                    raise LinuxOutboundDenied("native_linux_transport_denied")
                if typ == "ping":
                    if (set(msg) != {"type", "ts"}
                        or type(msg["ts"]) not in (int, float)
                        or not math.isfinite(msg["ts"])):
                        raise LinuxOutboundDenied("native_linux_transport_denied")
                    ws.send(json.dumps({"type": "pong", "ts": msg["ts"]},
                                       separators=(",", ":")))
                elif typ == "call":
                    parsed = _rpc_payload(msg)
                    if parsed is None:
                        continue
                    msg_id, frame = parsed
                    if msg_id in seen or len(seen) >= MAX_SEEN_IDS:
                        continue
                    seen.add(msg_id)
                    try:
                        out = dispatcher.call(frame)
                        # Dispatcher already verified native adapter result.
                        serialized = _result_frame(msg_id, out["result"])
                    except NativeLinuxReadDenied:
                        serialized = _result_frame(msg_id, {}, refused=True)
                    ws.send(serialized)
                    processed += 1
                    if processed >= MAX_TOOL_CALLS:
                        return "session_call_budget"
                elif typ == "error" and msg.get("fatal") is True:
                    raise LinuxOutboundDenied("native_linux_transport_denied")
                else:
                    # Unrecognized frames cannot trigger any host operation.
                    continue
            return "session_message_budget"
    except LinuxOutboundDenied:
        raise
    except Exception:
        # Network library/OS error strings may include tokens or private paths.
        raise LinuxOutboundDenied("native_linux_transport_denied") from None
