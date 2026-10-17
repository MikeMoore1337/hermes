"""Read-only Codex quota probe and sanitized snapshot contract.

No inference calls, credential export, account identifiers, or reset-credit actions.
The probe must run as a separate OS user with its own CODEX_HOME.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
from pathlib import Path
from queue import Empty, Queue
import subprocess
import tempfile
from threading import Thread
import time

DEFAULT_OUTPUT = Path("/var/lib/hermes-codex-usage/usage.json")
SOURCE = "codex-app-server"
SCHEMA = 1
MAX_BYTES = 65536
TTL_SECONDS = 600


class UsageError(Exception):
    """Expected acquisition or contract failure without provider detail."""


class AuthRequired(UsageError):
    """ChatGPT (not API key) login is required."""


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        raise ValueError("timezone required")
    return value.astimezone(dt.timezone.utc)


def iso(value: dt.datetime) -> str:
    return as_utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def window(raw: object) -> dict | None:
    if not isinstance(raw, dict):
        return None
    used = raw.get("usedPercent")
    if isinstance(used, bool) or not isinstance(used, (int, float)):
        return None
    if not math.isfinite(used) or not 0 <= used <= 100:
        return None
    duration = raw.get("windowDurationMins")
    if isinstance(duration, bool) or not isinstance(duration, int) or not 0 < duration <= 525600:
        duration = None
    reset = raw.get("resetsAt")
    if isinstance(reset, bool) or not isinstance(reset, (int, float)) or not math.isfinite(reset):
        reset = None
    elif reset < 0 or reset > 253402300799:
        reset = None
    else:
        reset = int(reset)
    return {
        "used_percent": round(float(used), 2),
        "remaining_percent": round(100 - float(used), 2),
        "duration_minutes": duration,
        "resets_at": reset,
    }


def normalize(result: object, now: dt.datetime | None = None) -> dict:
    if not isinstance(result, dict):
        raise UsageError("invalid_response")
    now = now or utc_now()
    groups = result.get("rateLimitsByLimitId")
    if not isinstance(groups, dict) or not groups:
        single = result.get("rateLimits")
        groups = {str(single.get("limitId") or "codex"): single} if isinstance(single, dict) else {}

    entries = []
    for key, raw in list(groups.items())[:24]:
        if not isinstance(key, str) or not isinstance(raw, dict):
            continue
        windows = []
        for field in ("primary", "secondary"):
            item = window(raw.get(field))
            if item is not None:
                windows.append(item)
        if not windows:
            continue
        reached = bool(raw.get("spendControlReached")) or bool(raw.get("rateLimitReachedType"))
        remaining = min(w["remaining_percent"] for w in windows)
        state = "exhausted" if reached or remaining == 0 else "low" if remaining <= 20 else "available"
        # Never expose provider account IDs, names, email, tokens, subscription secrets.
        entries.append({"limit_id": key[:64], "windows": windows, "status": state})

    allowed = result.get("ordinaryUsageAllowed")
    if not isinstance(allowed, bool):
        allowed = None
    if allowed is False:
        status = "exhausted"
    elif not entries:
        status = "unknown"
    elif all(e["status"] == "exhausted" for e in entries):
        status = "exhausted"
    elif any(e["status"] == "exhausted" for e in entries):
        status = "limited"
    elif any(e["status"] == "low" for e in entries):
        status = "low"
    else:
        status = "available"
    return {
        "schema": SCHEMA,
        "source": SOURCE,
        "status": status,
        "observed_at": iso(now),
        "ordinary_usage_allowed": allowed,
        "limits": entries,
    }


def error_snapshot(status: str, now: dt.datetime | None = None) -> dict:
    if status not in ("auth_required", "unavailable"):
        raise ValueError("unsupported probe status")
    return {
        "schema": SCHEMA, "source": SOURCE, "status": status,
        "observed_at": iso(now or utc_now()),
        "ordinary_usage_allowed": None, "limits": [],
    }


def query_app_server(binary: str = "codex", timeout: float = 15) -> dict:
    """Interact with JSONL stdio RPC; match ids instead of trusting notification order."""
    if not 1 <= timeout <= 60:
        raise ValueError("timeout out of range")
    try:
        proc = subprocess.Popen(
            [binary, "app-server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1,
        )
    except OSError as exc:
        raise UsageError("codex_not_installed") from exc
    queue: Queue[str | None] = Queue()

    def reader():
        try:
            for line in proc.stdout:
                queue.put(line)
        finally:
            queue.put(None)

    Thread(target=reader, daemon=True).start()
    deadline = time.monotonic() + timeout

    def send(value: dict):
        if proc.poll() is not None:
            raise UsageError("app_server_terminated")
        try:
            proc.stdin.write(json.dumps(value, separators=(",", ":")) + "\n")
            proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise UsageError("app_server_terminated") from exc

    def response(identifier: int) -> dict:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UsageError("app_server_timeout")
            try:
                line = queue.get(timeout=remaining)
            except Empty as exc:
                raise UsageError("app_server_timeout") from exc
            if line is None:
                raise UsageError("app_server_terminated")
            if len(line) > MAX_BYTES:
                raise UsageError("app_server_response_too_large")
            try:
                packet = json.loads(line)
            except ValueError:
                continue
            if not isinstance(packet, dict) or packet.get("id") != identifier:
                continue
            if "error" in packet:
                message = str(packet["error"].get("message", "") if isinstance(packet["error"], dict) else "")
                if "auth" in message.lower() or "login" in message.lower():
                    raise AuthRequired("chatgpt_login_required")
                raise UsageError("app_server_rejected_request")
            if not isinstance(packet.get("result"), dict):
                raise UsageError("invalid_response")
            return packet["result"]

    try:
        send({
            "id": 1, "method": "initialize",
            "params": {"clientInfo": {"name": "hermes_codex_usage",
                                      "title": "Hermes Codex Usage Monitor",
                                      "version": "0.1.0"}, "capabilities": {}},
        })
        response(1)
        send({"method": "initialized", "params": {}})
        send({"id": 2, "method": "account/rateLimits/read", "params": {}})
        return response(2)
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()


def save_snapshot(data: dict, output: Path = DEFAULT_OUTPUT) -> None:
    """Atomic snapshot; caller must own the directory and keep auth in a 0700 subdir."""
    output.parent.mkdir(parents=True, exist_ok=True)
    target = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8",
                                         dir=output.parent, prefix=".codex-", delete=False) as f:
            target = Path(f.name)
            json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(target, 0o640)
        os.replace(target, output)
    finally:
        if target is not None and target.exists():
            target.unlink()


def read_snapshot(path: Path = DEFAULT_OUTPUT, now: dt.datetime | None = None,
                  ttl_seconds: int = TTL_SECONDS) -> dict:
    """Return an explicit not-configured/stale status; never promote old quota to live."""
    if not path.exists():
        return {
            "schema": SCHEMA, "source": SOURCE, "status": "not_configured",
            "observed_at": None, "ordinary_usage_allowed": None, "limits": [],
        }
    try:
        with path.open("rb") as f:
            raw = f.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("snapshot too large")
        data = json.loads(raw)
        if (not isinstance(data, dict) or data.get("schema") != SCHEMA
                or data.get("source") != SOURCE
                or data.get("status") not in
                ("available", "limited", "low", "exhausted", "unknown", "auth_required", "unavailable")):
            raise ValueError("invalid status")
        allowed_fields = {"schema", "source", "status", "observed_at", "ordinary_usage_allowed", "limits"}
        if not set(data).issubset(allowed_fields):
            raise ValueError("unexpected sensitive fields")
        if data.get("ordinary_usage_allowed") not in (True, False, None):
            raise ValueError("invalid allowance")
        if not isinstance(data.get("limits"), list) or len(data["limits"]) > 24:
            raise ValueError("invalid limits")
        timestamp = data["observed_at"]
        if not isinstance(timestamp, str):
            raise ValueError("invalid timestamp")
        observed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        age = (as_utc(now or utc_now()) - as_utc(observed)).total_seconds()
        if not -120 <= age <= ttl_seconds:
            data["status"] = "stale"
        for entry in data["limits"]:
            if (not isinstance(entry, dict) or set(entry) != {"limit_id", "status", "windows"}
                    or not isinstance(entry.get("limit_id"), str)
                    or not 1 <= len(entry["limit_id"]) <= 64
                    or entry.get("status") not in ("available", "low", "exhausted")
                    or not isinstance(entry.get("windows"), list)
                    or len(entry["windows"]) > 2):
                raise ValueError("invalid entries")
            for w in entry["windows"]:
                if not isinstance(w, dict) or set(w) != {
                    "used_percent", "remaining_percent", "duration_minutes", "resets_at",
                }:
                    raise ValueError("invalid window")
                normalized = window({
                    "usedPercent": w.get("used_percent"),
                    "windowDurationMins": w.get("duration_minutes"),
                    "resetsAt": w.get("resets_at"),
                })
                if normalized is None or (isinstance(w.get("remaining_percent"), bool)
                        or not isinstance(w.get("remaining_percent"), (int, float))
                        or not math.isfinite(w["remaining_percent"])
                        or abs(normalized["remaining_percent"] - w["remaining_percent"]) > .01):
                    raise ValueError("invalid window")
        return data
    except (OSError, ValueError, TypeError, KeyError, OverflowError) as exc:
        raise UsageError("invalid_snapshot") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--codex-binary", default="codex")
    parser.add_argument("--timeout", type=float, default=15)
    args = parser.parse_args()
    try:
        result = normalize(query_app_server(args.codex_binary, args.timeout))
    except AuthRequired:
        result = error_snapshot("auth_required")
    except UsageError:
        result = error_snapshot("unavailable")
    save_snapshot(result, args.output)
    # The existing five-minute one-shot collector is the only history writer.
    # History errors cannot mask a valid live snapshot or damage old records.
    try:
        from control_center.codex_history import record
        record(result, args.output.with_name("history.sqlite3"))
    except (OSError, ValueError, __import__("sqlite3").Error):
        print("codex_history_unavailable")
    return 0 if result["status"] not in ("auth_required", "unavailable") else 1


if __name__ == "__main__":
    raise SystemExit(main())
