"""Read-only Desktop Commander telemetry. No cloud quota bypass or device commands.

Remote authentication belongs to a separately provisioned mcp-remote client;
the ChatGPT connector's OAuth session is NEVER reusable by this process.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
from queue import Queue, Empty
import re
import subprocess
import tempfile
from threading import Thread
import time

SCHEMA = 1
SOURCE = "desktop_commander_remote_mcp"
DEFAULT_OUTPUT = Path("/var/lib/hermes-desktop-commander/status.json")
TTL_SECONDS = 900
MAX_BYTES = 16384
REMOTE_COMMAND = ("npx", "-y", "mcp-remote@0.13.5", "https://mcp.desktopcommander.app/mcp")
LOCAL_COMMAND = ("npx", "-y", "@wonderwhy-er/desktop-commander@0.2.52")
STATUSES = frozenset({"monitored", "exhausted", "unknown", "auth_required",
                      "unavailable", "not_configured", "stale"})
DEVICE_STATES = frozenset({"online", "offline", "unknown"})
_DEVICE = re.compile(r"^\s*\d+\.\s+([^\r\n]{1,100})\s*$")
_LAST_SEEN = re.compile(r"^\s*Last seen:\s*(.{1,70})\s*$", re.I)


class CommanderError(Exception):
    """Bounded generic error - never publish upstream raw errors or tokens."""


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def iso(value):
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def empty(status="not_configured", now=None):
    if status not in STATUSES:
        raise ValueError("invalid status")
    return {"schema": SCHEMA, "source": SOURCE, "status": status,
            "observed_at": iso(now or utc_now()) if status != "not_configured" else None,
            "quota_remaining_percent": None, "devices": [],
            "remote_execution": "blocked" if status == "exhausted" else "unverified"}


def _tool_text(value):
    if not isinstance(value, dict) or value.get("isError"):
        raise CommanderError("tool_unavailable")
    blocks = value.get("content", [])
    if not isinstance(blocks, list):
        raise CommanderError("invalid_response")
    parts = [b.get("text", "") for b in blocks if isinstance(b, dict) and
             b.get("type") == "text" and isinstance(b.get("text"), str)]
    data = "\n".join(parts)
    if len(data.encode("utf-8")) > MAX_BYTES:
        raise CommanderError("response_too_large")
    return data


def normalize(who, device_listing, now=None):
    """Accept only who_am_i's JSON and the documented list_devices plaintext."""
    if isinstance(who, str):
        try:
            who = json.loads(who)
        except ValueError as exc:
            raise CommanderError("invalid_account") from exc
    if not isinstance(who, dict) or not isinstance(device_listing, str):
        raise CommanderError("invalid_response")
    remaining = who.get("remote_calls_left_pct")
    if not isinstance(remaining, (int, float)) or isinstance(remaining, bool) or not 0 <= remaining <= 100:
        remaining = None
    elif int(remaining) != remaining:
        remaining = None
    else:
        remaining = int(remaining)
    devices = []
    current = None
    for line in device_listing.splitlines()[:100]:
        match = _DEVICE.match(line)
        if match:
            if current and len(devices) < 16:
                devices.append(current)
            current = {"name": match.group(1).strip(), "state": "unknown",
                       "last_seen": None}
        elif current:
            stripped = line.strip().lower()
            if stripped.startswith("status:"):
                state = stripped.split(":", 1)[1].strip()
                current["state"] = state if state in DEVICE_STATES else "unknown"
            else:
                seen = _LAST_SEEN.match(line)
                if seen:
                    current["last_seen"] = seen.group(1).strip()
    if current and len(devices) < 16:
        devices.append(current)
    status = "exhausted" if remaining == 0 else "monitored" if remaining is not None else "unknown"
    return {"schema": SCHEMA, "source": SOURCE, "status": status,
            "observed_at": iso(now or utc_now()), "quota_remaining_percent": remaining,
            "devices": devices, "remote_execution": "blocked" if remaining == 0 else "unverified"}


def read_snapshot(path=DEFAULT_OUTPUT, now=None):
    path = Path(path)
    if not path.exists():
        return empty("not_configured")
    try:
        with path.open("rb") as file:
            raw = file.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("large")
        value = json.loads(raw)
        expected = {"schema", "source", "status", "observed_at",
                    "quota_remaining_percent", "devices", "remote_execution"}
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("unknown fields")
        if value["schema"] != SCHEMA or value["source"] != SOURCE or value["status"] not in STATUSES:
            raise ValueError("schema")
        pct = value["quota_remaining_percent"]
        if pct is not None and (type(pct) is not int or not 0 <= pct <= 100):
            raise ValueError("percentage")
        if not isinstance(value["devices"], list) or len(value["devices"]) > 16:
            raise ValueError("devices")
        for device in value["devices"]:
            if (not isinstance(device, dict) or set(device) != {"name", "state", "last_seen"}
                    or not isinstance(device["name"], str) or not 1 <= len(device["name"]) <= 100
                    or device["state"] not in DEVICE_STATES
                    or device["last_seen"] is not None and (
                        not isinstance(device["last_seen"], str) or len(device["last_seen"]) > 70)):
                raise ValueError("invalid device")
        if value["remote_execution"] not in ("blocked", "unverified"):
            raise ValueError("execution")
        if (value["status"] == "exhausted") != (value["remote_execution"] == "blocked"):
            raise ValueError("inconsistent execution")
        when = value["observed_at"]
        if when is None:
            if value["status"] != "not_configured":
                raise ValueError("missing timestamp")
        else:
            parsed = dt.datetime.fromisoformat(when.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("timezone")
            age = ((now or utc_now()) - parsed.astimezone(dt.timezone.utc)).total_seconds()
            if age > TTL_SECONDS or age < -120:
                return {**value, "status": "stale", "remote_execution": "unverified"}
        return value
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as exc:
        raise CommanderError("invalid_snapshot") from exc


def save_snapshot(snapshot, output=DEFAULT_OUTPUT):
    """Atomic sanitized snapshot; secret-bearing response bodies never persisted."""
    output = Path(output)
    # Round-trip validation before committing a file.
    with tempfile.TemporaryDirectory() as scratch:
        check = Path(scratch) / "check.json"
        check.write_text(json.dumps(snapshot), encoding="utf-8")
        read_snapshot(check, now=dt.datetime.fromisoformat(
            snapshot["observed_at"].replace("Z", "+00:00")) if snapshot["observed_at"] else utc_now())
    output.parent.mkdir(parents=True, exist_ok=True)
    target = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent,
                                         prefix=".desktop-commander-", delete=False) as file:
            target = Path(file.name)
            json.dump(snapshot, file, ensure_ascii=False, separators=(",", ":"))
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.chmod(target, 0o640)
        os.replace(target, output)
    finally:
        if target is not None and target.exists():
            target.unlink()


def query_mcp(command=REMOTE_COMMAND, timeout=25):
    """MCP stdio RPC using a fixed argv; only metadata tools may be called."""
    if command not in (REMOTE_COMMAND, LOCAL_COMMAND) or not 1 <= timeout <= 60:
        raise ValueError("unsupported MCP command")
    try:
        proc = subprocess.Popen(list(command), stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, encoding="utf-8", bufsize=1)
    except OSError as exc:
        raise CommanderError("client_not_installed") from exc
    events = Queue()
    def reader():
        try:
            for line in proc.stdout:
                events.put(line[:MAX_BYTES + 1])
        finally:
            events.put(None)
    Thread(target=reader, daemon=True).start()
    deadline = time.monotonic() + timeout
    def send(packet):
        if proc.poll() is not None:
            raise CommanderError("client_stopped")
        try:
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", **packet}, separators=(",", ":")) + "\n")
            proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise CommanderError("client_stopped") from exc
    def receive(identifier):
        while True:
            try:
                line = events.get(timeout=max(0.001, deadline - time.monotonic()))
            except Empty as exc:
                raise CommanderError("mcp_timeout") from exc
            if line is None:
                raise CommanderError("client_stopped")
            if len(line.encode("utf-8")) > MAX_BYTES:
                raise CommanderError("response_too_large")
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if not isinstance(event, dict) or event.get("id") != identifier:
                continue
            if "error" in event or not isinstance(event.get("result"), dict):
                raise CommanderError("mcp_rejected")
            return event["result"]
    try:
        send({"id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "hermes-desktop-commander-status", "version": "0.1.0"}}})
        receive(1)
        send({"method": "notifications/initialized", "params": {}})
        if command == LOCAL_COMMAND:
            send({"id": 2, "method": "tools/list", "params": {}})
            tools = receive(2).get("tools", [])
            if not isinstance(tools, list):
                raise CommanderError("invalid_tools")
            # Local tool presence is NOT permission to execute them.
            return {"available_tools": [t["name"] for t in tools if isinstance(t, dict)
                                        and isinstance(t.get("name"), str)][:100]}
        send({"id": 2, "method": "tools/call",
              "params": {"name": "who_am_i", "arguments": {}}})
        who = _tool_text(receive(2))
        send({"id": 3, "method": "tools/call",
              "params": {"name": "list_devices", "arguments": {}}})
        devices = _tool_text(receive(3))
        return normalize(who, devices)
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()


def device_gate(snapshot, name, *, authorized=False, execution_verified=False):
    """Advisory only. Does NOT modify Codex #271 admission or issue an OS command."""
    if not authorized:
        return "DENY"
    if not isinstance(snapshot, dict) or snapshot.get("status") in (
            "not_configured", "unknown", "stale", "unavailable", "auth_required"):
        return "UNKNOWN"
    if snapshot.get("status") == "exhausted" or snapshot.get("quota_remaining_percent") == 0:
        return "DEFER"
    devices = snapshot.get("devices", [])
    device = next((item for item in devices if item.get("name") == name), None)
    if not device or device.get("state") != "online":
        return "DEFER"
    return "ALLOW" if execution_verified else "UNKNOWN"


def main():
    parser = argparse.ArgumentParser(description="Desktop Commander read-only snapshot")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--remote", action="store_true", help="Query Remote MCP metadata (requires separate OAuth)")
    parser.add_argument("--probe-local", action="store_true", help="List local tool names only")
    args = parser.parse_args()
    if args.remote == args.probe_local:
        parser.error("choose exactly one of --remote or --probe-local")
    if args.probe_local:
        print(json.dumps(query_mcp(LOCAL_COMMAND), ensure_ascii=False))
    else:
        # Explicit local-only enabling gate: no implicit login or collection on import.
        if os.environ.get("HERMES_DC_OWNER_AUTHORIZED") != "1":
            parser.error("HERMES_DC_OWNER_AUTHORIZED=1 required for remote polling")
        try:
            data = query_mcp()
        except CommanderError:
            data = empty("unavailable")
        save_snapshot(data, args.output)


if __name__ == "__main__":
    main()
