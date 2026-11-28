"""Bounded BRC session for separately paired personal agents.

The connector and local dispatcher are supplied by a trusted worker. This
module does not launch a process, store a bearer, or install a service.
"""
from __future__ import annotations

import json
import platform
import re
from typing import Any, Callable

from device_fabric.native_brc_enrollment import TOKEN
from device_fabric.windows_personal_commander_enrollment import DEVICE, NAME

ENDPOINT = "wss://hermes.mikemoore.top/ws"
MAX_FRAME = 1024 * 1024
MAX_CALLS = 64
ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
ADAPTER_TOOLS = frozenset({"read_file", "read_multiple_files", "write_file", "edit_block",
    "create_directory", "list_directory", "move_file", "get_file_info", "start_search",
    "get_more_search_results", "stop_search", "list_searches", "start_process",
    "read_process_output", "interact_with_process", "force_terminate", "list_sessions"})
TOOLS = ADAPTER_TOOLS | {"import_public_project"}
ALIASED_TOOLS = ADAPTER_TOOLS | {"kill_process"}
ALIASED_IMPORT_TOOLS = TOOLS | {"kill_process"}
VPS_REGISTRATION_TOOL = "connect_original_vps_project"
WINDOWS_REGISTRATION_TOOL = "connect_original_windows_project"


class PersonalTransportDenied(ValueError):
    """Constant denial; never expose token, command, path or relay errors."""


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError()
        value[key] = item
    return value


def _decode(raw: str | bytes) -> dict[str, Any]:
    if type(raw) not in (str, bytes) or len(raw) > MAX_FRAME:
        raise PersonalTransportDenied("personal_transport_denied")
    try:
        if type(raw) is str and len(raw.encode("utf-8")) > MAX_FRAME:
            raise ValueError()
        frame = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(frame) is not dict or type(frame.get("type")) is not str:
            raise ValueError()
        return frame
    except Exception:
        raise PersonalTransportDenied("personal_transport_denied") from None


def _active(check: Callable[[], bool]) -> None:
    try:
        if check() is not True:
            raise ValueError()
    except Exception:
        raise PersonalTransportDenied("personal_transport_denied") from None


def run_session(*, device_id: str, bearer: str, tools: list[dict[str, Any]],
                connector: Callable[..., Any], dispatch: Callable[[str, dict], dict],
                is_active: Callable[[], bool], claim_call: Callable[[str], bool],
                target: str = 'windows', reload_pending: Callable[[], bool] | None = None) -> str:
    """Run one authenticated session with durable pre-dispatch call claims.

    The owner-status callback, local target and claim journal must be
    independently trusted; no network frame can supply them. An ambiguous
    effect is never retried. This transport does not provide OS isolation,
    implement file or process operations, or install a Linux service.
    """
    try:
        profiles = {
            'windows': (DEVICE, NAME, 'win32', 'x64', 'personal-windows'),
            'hermes-vps': (re.compile(r'h454-linux-personal-hermes-[0-9a-f]{32}\Z'),
                'H454 Hermes VPS personal Commander', 'linux', None, 'personal-hermes'),
            'yfc-vps': (re.compile(r'h454-linux-personal-yfc-[0-9a-f]{32}\Z'),
                'H454 YFC VPS personal Commander', 'linux', None, 'personal-yfc'),
        }
        if type(target) is not str or target not in profiles:
            raise ValueError()
        pattern, device_name, system, arch, hostname = profiles[target]
        if system == 'linux':
            arch = {'x86_64': 'x64', 'amd64': 'x64', 'aarch64': 'arm64',
                    'arm64': 'arm64'}.get(platform.machine().lower())
        allowed_tool_sets = (ADAPTER_TOOLS, TOOLS, ALIASED_TOOLS, ALIASED_IMPORT_TOOLS)
        if target == 'windows':
            base = allowed_tool_sets
            allowed_tool_sets += tuple(group | extra for group in base for extra in (
                {VPS_REGISTRATION_TOOL}, {WINDOWS_REGISTRATION_TOOL},
                {VPS_REGISTRATION_TOOL, WINDOWS_REGISTRATION_TOOL}))
        if (arch not in ('x64', 'arm64') or type(device_id) is not str or pattern.fullmatch(device_id) is None
            or type(bearer) is not str or TOKEN.fullmatch(bearer) is None
            or type(tools) is not list
            or any(type(tool) is not dict or type(tool.get("name")) is not str for tool in tools)
            or len({tool["name"] for tool in tools}) != len(tools)
            or {tool["name"] for tool in tools} not in allowed_tool_sets
            or len(json.dumps(tools, ensure_ascii=True).encode("ascii")) > MAX_FRAME
            or not all(callable(value) for value in (connector, dispatch, is_active, claim_call))
            or (reload_pending is not None and not callable(reload_pending))):
            raise ValueError()
        _active(is_active)
        greeting = {"type": "hello", "protocol": 1, "device": {"deviceId": device_id,
            "name": device_name, "platform": system, "arch": arch, "hostname": hostname,
            "agentVersion": "2.0.2", "coreVersion": "hermes-personal-1"}, "tools": tools}
        connection = connector(ENDPOINT, additional_headers={"Authorization": "Bearer " + bearer,
            "X-BRC-Protocol": "1"}, open_timeout=10, close_timeout=3, compression=None,
            proxy=None, max_size=MAX_FRAME, ping_interval=20, ping_timeout=20)
        with connection as ws:
            ws.send(json.dumps(greeting, separators=(",", ":"), ensure_ascii=True))
            welcomed = False
            seen: set[str] = set()
            while len(seen) < MAX_CALLS:
                try:
                    message = _decode(ws.recv(timeout=50))
                except TimeoutError:
                    return "idle_timeout"
                _active(is_active)
                kind = message["type"]
                if kind == "welcome":
                    if (welcomed or set(message) != {"type", "protocol", "relayVersion", "serverTime"}
                        or type(message["protocol"]) is not int or message["protocol"] != 1
                        or type(message["relayVersion"]) is not str
                        or not 1 <= len(message["relayVersion"]) <= 80
                        or type(message["serverTime"]) is not int or message["serverTime"] < 0):
                        raise ValueError()
                    welcomed = True
                    continue
                if not welcomed:
                    raise ValueError()
                if kind == "ping":
                    if set(message) != {"type", "ts"} or type(message["ts"]) not in (int, float):
                        raise ValueError()
                    ws.send(json.dumps({"type": "pong", "ts": message["ts"]}, separators=(",", ":")))
                    continue
                if kind != "call" or set(message) - {"type", "id", "tool", "args", "client", "timeoutMs"}:
                    raise ValueError()
                ident, name, args = message.get("id"), message.get("tool"), message.get("args")
                if (type(ident) is not str or ID.fullmatch(ident) is None
                    or type(name) is not str or name not in {tool['name'] for tool in tools} or type(args) is not dict):
                    raise ValueError()
                if ident in seen:
                    raise ValueError()
                # Reserve before any filesystem/process effect, including one
                # whose response is lost or whose worker is interrupted.
                if claim_call(ident) is not True:
                    raise ValueError()
                seen.add(ident)
                _active(is_active)
                result = dispatch(name, args)
                _active(is_active)
                if type(result) is not dict or type(result.get("content")) is not list:
                    raise ValueError()
                raw = json.dumps({"type": "result", "id": ident, "result": result},
                                 separators=(",", ":"), ensure_ascii=True, allow_nan=False)
                if len(raw.encode("ascii")) > MAX_FRAME or bearer in raw:
                    raise ValueError()
                ws.send(raw)
                # Emit the result of a committed local config change before
                # closing this worker and reloading the updated scope.
                if reload_pending is not None and reload_pending() is True:
                    return 'reload_requested'
            return "call_budget_exhausted"
    except PersonalTransportDenied:
        raise
    except Exception:
        raise PersonalTransportDenied("personal_transport_denied") from None
