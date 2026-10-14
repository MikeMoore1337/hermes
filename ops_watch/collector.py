"""Read-only host collector for existing YFC Hermes news health.

Runs as a one-shot service, emits only sanitized incident codes, never messages
or tokens. Its ability to read the private news state must be OS-restricted.
"""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ops_watch.core import InputError, analyze, changes

SOURCE = Path("/var/lib/hermes/state.json")
TARGET = Path("/var/lib/hermes-agent/ops-watch")
SCHEMA = "hermes-ops-snapshot-v1"


def _state(name: str, command: str) -> bool:
    try:
        result = subprocess.run(
            ["systemctl", command, name],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InputError("systemd_status_unavailable") from exc
    if result.returncode not in (0, 1, 3):
        raise InputError("systemd_status_unavailable")
    value = result.stdout.strip()
    return value == ("active" if command == "is-active" else "enabled")


def _count(source: dict[str, Any], name: str) -> int:
    value = source.get(name)
    if type(value) is not int or not 0 <= value <= 1_000_000_000:
        raise InputError("invalid_" + name)
    return value


def normalized(news_health: dict[str, Any], observed: datetime, *, timer_enabled: bool, timer_active: bool) -> dict[str, Any]:
    """Project only allowlisted numeric/timestamp fields from untrusted state."""
    last = news_health.get("last_successful_discovery_at")
    if last is not None and not isinstance(last, str):
        raise InputError("invalid_last_discovery")
    return {
        "schema": SCHEMA,
        "observed_at": observed.isoformat(),
        "news": {
            "timer_enabled": timer_enabled,
            "timer_active": timer_active,
            "last_successful_discovery_at": last,
            "consecutive_discovery_failures": _count(news_health, "consecutive_discovery_failures"),
            "consecutive_drain_failures": _count(news_health, "consecutive_drain_failures"),
            "pending_jobs": _count(news_health, "pending_jobs"),
            "oldest_pending_age_seconds": _count(news_health, "oldest_pending_age_seconds"),
            # Cumulative 429 history is NOT a recent counter. Future collector
            # needs phase-scoped evidence before enabling this particular alarm.
            "recent_provider_rate_limits": 0,
        },
    }


def _read_state(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise InputError("missing_news_health")
    if path.stat().st_size > 16_000_000:
        raise InputError("news_health_oversize")
    try:
        with path.open("rb") as stream:
            data = json.load(stream)
    except (OSError, UnicodeError, ValueError) as exc:
        raise InputError("unreadable_news_health") from exc
    if not isinstance(data, dict) or not isinstance(data.get("health"), dict):
        raise InputError("missing_health_section")
    return data["health"]


def _read_previous(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise InputError("invalid_previous_state")
    try:
        items = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InputError("unreadable_previous_state") from exc
    if not isinstance(items, list):
        raise InputError("invalid_previous_state")
    return items


def _atomic_json(directory: Path, name: str, document: object) -> None:
    payload = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    temporary = directory / (name + ".tmp")
    destination = directory / name
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def once(source: Path = SOURCE, target: Path = TARGET, observed: datetime | None = None) -> dict[str, Any]:
    """Collect, deduplicate, and atomically store safe findings under a lock."""
    if target.is_symlink() or not target.is_dir() or (target.stat().st_mode & 0o077) != 0:
        raise InputError("unsafe_target_directory")
    now = observed or datetime.now(UTC)
    lock = target / ".collector.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        health = _read_state(source)
        snapshot = normalized(
            health, now,
            timer_enabled=_state("hermes-discovery.timer", "is-enabled"),
            timer_active=_state("hermes-discovery.timer", "is-active"),
        )
        findings = analyze(snapshot, now=now)
        old = _read_previous(target / "findings.json")
        delta = changes(old, findings)
        _atomic_json(target, "findings.json", findings)
        return {"status": "ok", "active_codes": [f["code"] for f in findings], "changes": delta}
    except BlockingIOError as exc:
        raise InputError("collector_already_running") from exc
    finally:
        os.close(fd)


def main() -> int:
    os.umask(0o077)
    try:
        result = once()
    except (InputError, OSError, ValueError) as exc:
        # Log only an allowlisted internal error CLASS; no paths or user text.
        reason = str(exc) if type(exc) is InputError else type(exc).__name__
        if reason not in {
            "missing_news_health", "news_health_oversize", "unreadable_news_health",
            "missing_health_section", "unsafe_target_directory", "collector_already_running",
            "invalid_previous_state", "unreadable_previous_state",
            "invalid_last_discovery", "systemd_status_unavailable",
            "invalid_consecutive_discovery_failures", "invalid_consecutive_drain_failures",
            "invalid_pending_jobs", "invalid_oldest_pending_age_seconds",
        }:
            reason = "invalid_evidence"
        print(json.dumps({"status": "rejected", "reason": reason}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
