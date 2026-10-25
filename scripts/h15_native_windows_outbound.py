"""Dormant outbound BRC websocket bridge for ORIGINAL Windows read-only files (#454).

This file does not run during import. --single-session requires a separately
approved Windows host process launch, pinned local source, paired owner token,
and a restricted Windows OS identity. It does not install a service, pair an
agent, open a listener, run shell commands, or write files.

Optional free transport dependency (not installed by this repo):
  websockets==17.2 (sync API, Python 3.14)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

from scripts.h15_native_windows_mcp_stdio import (
    McpSession, PROTOCOL, SERVER, TOOLS,
)

HOST = "hermes.mikemoore.top"
LOOPBACK = "127.0.0.1"
DEVICE_NAME = "H15 Windows native read-only"
WIRE_VERSION = 1
MAX_INCOMING = 8192
MAX_CALLS = 16
MAX_SEEN_IDS = 64
MAX_RECONNECT_ATTEMPTS = 5
RECONNECT_DELAYS = (1, 2, 4, 8)
READONLY_NAMES = frozenset({'native_file_stat', 'native_file_read'})
DEVICE_ID = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
TOKEN = re.compile(r"^[A-Za-z0-9_.~-]{24,1024}$")


class NativeTransportDenied(Exception):
    """Bounded error without auth token, file contents or original paths."""


@dataclass(frozen=True)
class Settings:
    websocket_url: str
    device_id: str
    device_token: str


def parse_settings(relay_url: str, device_id: str, token: str,
                   *, tunneled_loopback: bool = False) -> Settings:
    """Pin the transport: public TLS or explicitly requested local SSH forward.

    Loopback is NOT evidence that the expected SSH tunnel exists. Never enable
    this mode without a separately approved, identity-verified local SSH
    forward and a short-lived owner-scoped device credential.
    """
    if (not isinstance(relay_url, str) or len(relay_url) > 256
        or any(ord(c) < 33 or ord(c) > 126 for c in relay_url)
        or "?" in relay_url or "#" in relay_url or "@" in relay_url):
        raise NativeTransportDenied("invalid_relay")
    try:
        uri = urlsplit(relay_url)
        port = uri.port
    except ValueError as exc:
        raise NativeTransportDenied("invalid_relay") from exc
    if tunneled_loopback:
        allowed = (uri.scheme == "ws" and uri.hostname == LOOPBACK
                   and port is not None and 1024 <= port <= 65535
                   and uri.netloc == f"{LOOPBACK}:{port}"
                   and uri.path == "/ws")
    else:
        allowed = (uri.scheme == "wss" and uri.hostname == HOST
                   and port in (None, 443)
                   and uri.netloc in (HOST, f"{HOST}:443")
                   and uri.path == "/ws")
    if not allowed:
        raise NativeTransportDenied("relay_not_allowlisted")
    if type(device_id) is not str or not DEVICE_ID.fullmatch(device_id):
        raise NativeTransportDenied("invalid_device")
    if type(token) is not str or not TOKEN.fullmatch(token):
        raise NativeTransportDenied("invalid_credentials")
    return Settings(relay_url, device_id, token)


def tools_advertised() -> list[dict[str, Any]]:
    """Never inherit generic BRC read/write/shell tool catalogs."""
    return list(TOOLS)


def hello(config: Settings) -> dict[str, Any]:
    return {"type": "hello", "protocol": WIRE_VERSION, "device": {
        "deviceId": config.device_id,
        "name": DEVICE_NAME,
        "platform": "win32",
        "arch": "x64",
        "hostname": "hermes-native-readonly",
        "agentVersion": SERVER["version"],
        "coreVersion": "hermes-readonly-1",
    }, "tools": tools_advertised()}


def decode_frame(raw: str | bytes) -> dict[str, Any]:
    if not isinstance(raw, (bytes, str)) or len(raw) > MAX_INCOMING:
        raise NativeTransportDenied("frame_size_invalid")
    try:
        def unique(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError("duplicate_key")
                result[key] = value
            return result
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_constant")))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise NativeTransportDenied("frame_json_invalid") from exc
    if not isinstance(value, dict) or type(value.get("type")) is not str:
        raise NativeTransportDenied("frame_invalid")
    return value


def safe_call(session: McpSession, message: dict[str, Any],
              seen: set[str]) -> dict[str, Any] | None:
    """Translate only two remote BRC operations into checked local MCP calls."""
    if set(message) - {"type", "id", "tool", "args", "client", "timeoutMs"}:
        return None
    if message.get("type") != "call":
        return None
    ident = message.get("id")
    name = message.get("tool")
    args = message.get("args")
    if (type(ident) is not str or not 1 <= len(ident) <= 128
        or type(name) is not str or name not in
            ("native_file_read", "native_file_stat")
        or not isinstance(args, dict) or set(args) != {"project", "relative"}
        or not all(type(v) is str for v in args.values())):
        return None
    if ident in seen or len(seen) >= MAX_SEEN_IDS:
        return None
    seen.add(ident)
    rpc = session.handle({
        "jsonrpc": "2.0", "id": ident, "method": "tools/call",
        "params": {"name": name, "arguments": args},
    })
    if (not isinstance(rpc, dict) or rpc.get("id") != ident
        or not isinstance(rpc.get("result"), dict)):
        return None
    return {"type": "result", "id": ident, "result": rpc["result"]}


def run_session(config: Settings, connector: Callable[..., Any],
                *, seen_ids: set[str] | None = None) -> str:
    """One authenticated outbound TLS socket, one bounded local tool session.

    The connector is injected for offline tests. Production uses the
    documented websockets.sync.client.connect; it does not auto-install.
    """
    session = McpSession()
    init = session.handle({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": PROTOCOL, "capabilities": {},
                   "clientInfo": {"name": "brc-readonly-adapter", "version": "1"}},
    })
    if not isinstance(init, dict) or "result" not in init:
        raise NativeTransportDenied("internal_mcp_init_failed")
    seen: set[str] = seen_ids if seen_ids is not None else set()
    sent = 0
    try:
        connection = connector(
            config.websocket_url,
            additional_headers={
                "Authorization": "Bearer " + config.device_token,
                "X-BRC-Protocol": str(WIRE_VERSION),
            },
            open_timeout=10,
            close_timeout=3,
            compression=None,
            proxy=None,
            max_size=MAX_INCOMING,
            ping_interval=20,
            ping_timeout=20,
        )
        with connection as ws:
            ws.send(json.dumps(hello(config), separators=(",", ":")))
            welcome = False
            # No unbounded reconnect/daemon behavior. Explicit owner action
            # required to launch a future new host process.
            for _ in range(MAX_SEEN_IDS + 16):
                try:
                    raw = ws.recv(timeout=50)
                except TimeoutError:
                    return "idle_timeout"
                msg = decode_frame(raw)
                kind = msg["type"]
                if kind == "welcome":
                    if welcome or set(msg) != {"type", "protocol", "relayVersion",
                                               "serverTime"} or msg["protocol"] != WIRE_VERSION:
                        raise NativeTransportDenied("invalid_welcome")
                    welcome = True
                elif kind == "ping":
                    if type(msg.get("ts")) not in (int, float):
                        raise NativeTransportDenied("invalid_ping")
                    ws.send(json.dumps({"type": "pong", "ts": msg["ts"]},
                                       separators=(",", ":")))
                elif kind == "call" and welcome:
                    out = safe_call(session, msg, seen)
                    if out is not None:
                        # Never include the auth token in tool responses.
                        ws.send(json.dumps(out, separators=(",", ":"),
                                           ensure_ascii=True))
                        sent += 1
                    if sent >= MAX_CALLS:
                        return "read_budget_exhausted"
                elif kind == "error" and msg.get("fatal") is True:
                    raise NativeTransportDenied("relay_rejected")
                elif not welcome:
                    raise NativeTransportDenied("welcome_required")
            return "session_budget_exhausted"
    except NativeTransportDenied:
        raise
    except Exception as exc:
        # Any OS/library exception can contain bearer tokens, file names or
        # connection headers. Never log or return it.
        raise NativeTransportDenied("transport_failed") from None


def run_bounded_reconnect(
    config: Settings, connector: Callable[..., Any],
    *, pause: Callable[[float], Any] = time.sleep,
) -> str:
    """At most five sequential *read-only* sessions, no queued call replay.

    Authentication stays with the existing paired device credential; there
    is no token refresh, new registration, daemon or background task.
    Nothing is persisted. On restart owner-scoped re-pair may be required.
    Fatal protocol/relay refusal does NOT get retried.
    """
    if {tool.get("name") for tool in TOOLS} != READONLY_NAMES or len(TOOLS) != 2:
        raise NativeTransportDenied("reconnect_requires_readonly_catalog")
    seen_ids: set[str] = set()
    for index in range(MAX_RECONNECT_ATTEMPTS):
        try:
            # Preserve prior in-process request IDs over a connection reset;
            # a relay redelivery must not dispatch the same ID twice.
            end = run_session(config, connector, seen_ids=seen_ids)
        except NativeTransportDenied as exc:
            if str(exc) != "transport_failed":
                raise
            end = "transport_failed"
        if end not in ("idle_timeout", "transport_failed"):
            return end
        if index == MAX_RECONNECT_ATTEMPTS - 1:
            return "reconnect_budget_exhausted"
        # Bound duration and prevent an uncontrolled tight connection loop.
        pause(RECONNECT_DELAYS[index])
    return "reconnect_budget_exhausted"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dormant outbound native read-only BRC device")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--single-session", action="store_true",
                      help="Native Windows launch requires specific owner approval")
    mode.add_argument("--bounded-reconnect", action="store_true",
                      help="Up to five read-only reconnects, explicit host owner approval")
    parser.add_argument("--tunneled-loopback", action="store_true",
                        help="Use only a previously owner-approved and verified SSH local forward")
    opts = parser.parse_args(argv)
    if not (opts.single_session or opts.bounded_reconnect) or os.name != "nt":
        return 2
    # Never allow an unpaired session, arbitrary public URLs or plaintext ws.
    try:
        if opts.tunneled_loopback and os.environ.get("HERMES_NATIVE_BRC_WSS"):
            raise NativeTransportDenied("ambiguous_transport")
        config = parse_settings(
            os.environ.get("HERMES_NATIVE_BRC_LOOPBACK", "") if opts.tunneled_loopback
            else os.environ.get("HERMES_NATIVE_BRC_WSS", ""),
            os.environ.get("HERMES_NATIVE_BRC_DEVICE_ID", ""),
            os.environ.get("HERMES_NATIVE_BRC_TOKEN", ""),
            tunneled_loopback=opts.tunneled_loopback,
        )
        # Deferred import permits offline protocol testing without installing
        # a package or opening any remote connection.
        from websockets.sync.client import connect
        outcome = (run_bounded_reconnect(config, connect) if opts.bounded_reconnect
                   else run_session(config, connect))
        if outcome == "reconnect_budget_exhausted":
            print("H454_NATIVE_READ_RECONNECT=EXHAUSTED", file=sys.stderr)
            return 2
    except (ImportError, NativeTransportDenied):
        print("H454_NATIVE_READ_BRIDGE=REFUSED", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
