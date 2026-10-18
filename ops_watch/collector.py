"""Read-only host collector for existing YFC Hermes news health.

Runs as a one-shot service, emits only sanitized incident codes, never messages
or tokens. Its ability to read the private news state must be OS-restricted.
"""

from __future__ import annotations

import fcntl
import json
import math
import os
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ops_watch.core import InputError, analyze, changes
from ops_watch.infrastructure_alerts import ROOT as INFRASTRUCTURE_ROOT
from ops_watch.device_fabric_alerts import DB as DEVICE_DB, OPT_IN as DEVICE_OPT_IN
from ops_watch.device_fabric_alerts import observe as device_fabric_observe
from ops_watch.infrastructure_alerts import observe as infrastructure_observe
from ops_watch.quota_alerts import observe as quota_observe
from ops_watch.quota_alerts import CODEX as Q_CODEX, DESKTOP as Q_DESKTOP, CLOUDFLARE as Q_CF, GITHUB as Q_GITHUB
from ops_watch.state_store import persist, read_current
from qa_advisor.signal_store import SignalError, observed_status

SOURCE = Path("/var/lib/hermes/state.json")
TARGET = Path("/var/lib/hermes-agent/ops-watch")
SCHEMA = "hermes-ops-snapshot-v1"
CODEX_OUTPUT = Path("/var/lib/hermes-codex-usage/usage.json")


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


def _agent_network_guard_status() -> dict[str, bool]:
    """Check only systemd metadata of our independent Hermes network guard.

    'not-found' is a genuine critical incident, not silently healthy.
    Invalid systemctl evidence fails closed without inventing any status.
    """
    try:
        process = subprocess.run(
            ["systemctl", "show", "hermes-cloudflare-network-guard.service",
             "-p", "LoadState", "-p", "ActiveState", "-p", "UnitFileState", "--no-pager"],
            capture_output=True, text=True, check=False, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InputError("agent_guard_status_unavailable") from exc
    if process.returncode != 0 or len(process.stdout) > 2048:
        raise InputError("agent_guard_status_unavailable")
    properties = {}
    for line in process.stdout.splitlines():
        if "=" not in line:
            raise InputError("agent_guard_status_unavailable")
        key, value = line.split("=", 1)
        if key not in {"LoadState", "ActiveState", "UnitFileState"} or key in properties:
            raise InputError("agent_guard_status_unavailable")
        properties[key] = value
    if set(properties) != {"LoadState", "ActiveState", "UnitFileState"}:
        raise InputError("agent_guard_status_unavailable")
    return {
        "loaded": properties["LoadState"] == "loaded",
        "enabled": properties["UnitFileState"] == "enabled",
        "active": properties["ActiveState"] == "active",
    }


def _ops_alert_timer_status() -> dict[str, bool]:
    """Read only one pinned timer; never start/disable sender or read token.

    An unavailable systemd observation must not be converted to a healthy
    sender. This self-check cannot deliver an event while sender is down;
    it persists the event for delivery after the sender is restored.
    """
    try:
        process = subprocess.run(
            ["systemctl", "show", "hermes-ops-alerts.timer",
             "-p", "LoadState", "-p", "ActiveState", "-p", "UnitFileState",
             "--no-pager"],
            capture_output=True, text=True, check=False, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InputError("alert_sender_status_unavailable") from exc
    if process.returncode != 0 or len(process.stdout) > 2048:
        raise InputError("alert_sender_status_unavailable")
    properties: dict[str, str] = {}
    for line in process.stdout.splitlines():
        if "=" not in line:
            raise InputError("alert_sender_status_unavailable")
        key, value = line.split("=", 1)
        if key not in {"LoadState", "ActiveState", "UnitFileState"} or key in properties:
            raise InputError("alert_sender_status_unavailable")
        properties[key] = value
    if set(properties) != {"LoadState", "ActiveState", "UnitFileState"}:
        raise InputError("alert_sender_status_unavailable")
    return {
        "loaded": properties["LoadState"] == "loaded",
        "enabled": properties["UnitFileState"] == "enabled",
        "active": properties["ActiveState"] == "active",
    }


def _ops_alert_service_status() -> dict[str, bool]:
    """Observe the actual sender exit result, not merely its active timer.

    systemd oneshot services normally report inactive after a successful
    dispatch. Inactivity alone is NOT a failure. Query only the fixed unit.
    """
    try:
        process = subprocess.run(
            ["systemctl", "show", "hermes-ops-alerts.service",
             "-p", "LoadState", "-p", "Result", "--no-pager"],
            capture_output=True, text=True, check=False, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InputError("alert_delivery_status_unavailable") from exc
    if process.returncode != 0 or len(process.stdout) > 2048:
        raise InputError("alert_delivery_status_unavailable")
    properties: dict[str, str] = {}
    for line in process.stdout.splitlines():
        if "=" not in line:
            raise InputError("alert_delivery_status_unavailable")
        key, value = line.split("=", 1)
        if key not in {"LoadState", "Result"} or key in properties:
            raise InputError("alert_delivery_status_unavailable")
        properties[key] = value
    if set(properties) != {"LoadState", "Result"}:
        raise InputError("alert_delivery_status_unavailable")
    allowed = {
        "success", "exit-code", "signal", "core-dump", "watchdog",
        "timeout", "resources", "start-limit-hit", "protocol",
        "oom-kill", "dependency", "assert", "condition",
    }
    if properties["Result"] not in allowed or properties["LoadState"] not in {
        "loaded", "not-found", "error", "masked", "bad-setting",
    }:
        raise InputError("alert_delivery_status_unavailable")
    return {"failed": (
        properties["LoadState"] != "loaded" or
        properties["Result"] != "success"
    )}


def _count(source: dict[str, Any], name: str) -> int:
    value = source.get(name)
    if type(value) is not int or not 0 <= value <= 1_000_000_000:
        raise InputError("invalid_" + name)
    return value


def normalized(news_health: dict[str, Any], observed: datetime, *, timer_enabled: bool, timer_active: bool, agent_guard: dict[str, bool] | None = None, alerts_timer: dict[str, bool] | None = None, alerts_service: dict[str, bool] | None = None) -> dict[str, Any]:
    """Project only allowlisted numeric/timestamp fields from untrusted state."""
    last = news_health.get("last_successful_discovery_at")
    if last is not None and not isinstance(last, str):
        raise InputError("invalid_last_discovery")
    result = {
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
    if agent_guard is not None:
        result["agent_guard"] = agent_guard
    if alerts_timer is not None:
        result["alerts_timer"] = alerts_timer
    if alerts_service is not None:
        result["alerts_service"] = alerts_service
    return result


def _codex_telemetry(path: Path = CODEX_OUTPUT, *, observed: datetime | None = None) -> dict[str, Any] | None:
    """Read an optional sanitized local file, independent of Control Center runtime."""
    # The source is optional. An isolated offline test or service with no
    # access to the private Codex directory must not fail collection merely
    # while checking whether that directory exists. Prior active alarms are
    # preserved when telemetry is absent (see once()).
    try:
        if not path.exists() and not path.is_symlink():
            return None
    except PermissionError:
        return None
    except OSError:
        return {"status": "unavailable", "ordinary_usage_allowed": None}
    unavailable = {"status": "unavailable", "ordinary_usage_allowed": None}
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            return unavailable
        data = json.loads(path.read_bytes())
        if (not isinstance(data, dict) or data.get("schema") != 1
                or data.get("source") != "codex-app-server"
                or data.get("status") not in (
                    "available", "low", "limited", "exhausted", "unknown",
                    "auth_required", "unavailable",
                )):
            return unavailable
        stamp = datetime.fromisoformat(data["observed_at"].replace("Z", "+00:00"))
        now = observed or datetime.now(UTC)
        if stamp.tzinfo is None or not -120 <= (now.astimezone(UTC) - stamp.astimezone(UTC)).total_seconds() <= 600:
            return {"status": "stale", "ordinary_usage_allowed": None}
        allowed = data.get("ordinary_usage_allowed")
        if allowed is not None and type(allowed) is not bool:
            return unavailable
        status = data["status"]
        if status in ("available", "low", "limited", "exhausted"):
            groups = data.get("limits")
            if not isinstance(groups, list) or not 1 <= len(groups) <= 24:
                return unavailable
            for group in groups:
                if not isinstance(group, dict) or group.get("status") not in ("available", "low", "exhausted"):
                    return unavailable
                windows = group.get("windows")
                if not isinstance(windows, list) or not 1 <= len(windows) <= 2:
                    return unavailable
                for window in windows:
                    if not isinstance(window, dict):
                        return unavailable
                    value = window.get("remaining_percent")
                    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 100:
                        return unavailable
                    if value == 0 and status not in ("exhausted", "limited"):
                        return unavailable
                if group["status"] == "exhausted" and status not in ("exhausted", "limited"):
                    return unavailable
        return {"status": status, "ordinary_usage_allowed": allowed}
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        return unavailable


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
    """Replace a derivative snapshot without a stale fixed temporary-file lock.

    A killed collector may leave .tmp behind. Using name+".tmp" with O_EXCL
    makes every later collector invocation fail indefinitely. SQLite remains
    authoritative; generate a fresh random 0600 staging file each time.
    """
    if name not in {"findings.json", "incident-preview.json"}:
        raise InputError("invalid_projection_name")
    payload = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    destination = directory / name
    fd, temporary_name = tempfile.mkstemp(prefix=f".{name}.", suffix=".tmp", dir=directory)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        # Make the rename durable on a sudden reboot; the SQLite transition
        # was already committed, so a projection can always be regenerated.
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def once(source: Path = SOURCE, target: Path = TARGET, observed: datetime | None = None, *, agent_guard: dict[str, bool] | None = None, alerts_timer: dict[str, bool] | None = None, alerts_service: dict[str, bool] | None = None, infrastructure_dir: Path | None = None, quota_paths: dict[str, Path] | None = None, device_fabric_db: Path | None = None, device_fabric_opt_in: Path | None = None) -> dict[str, Any]:
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
            agent_guard=agent_guard if agent_guard is not None else _agent_network_guard_status(),
            alerts_timer=alerts_timer,
            alerts_service=alerts_service,
        )
        snapshot["codex"] = _codex_telemetry(observed=now)
        # External host telemetry is an EXPLICIT input, not a global side
        # effect in offline tests or sandboxed collectors. Only the production
        # CLI wires the real bounded source. A test-provided target must never
        # silently inherit the VPS snapshot directory.
        if infrastructure_dir is not None:
            snapshot["infrastructure"] = infrastructure_observe(
                directory=infrastructure_dir, now=now)
        if quota_paths is not None:
            snapshot["quota_signals"] = quota_observe(now=now, paths=quota_paths)
        if device_fabric_db is not None and device_fabric_opt_in is not None:
            snapshot["device_fabric"] = device_fabric_observe(
                db=device_fabric_db, opt_in=device_fabric_opt_in, now=now)
        findings = analyze(snapshot, now=now)
        # Separate QA reader never has Telegram credentials or access to the
        # news source. Missing/stale/denied API observations must not falsely
        # clear a previously persisted CI incident.
        try:
            ci = observed_status(now=now)
        except (SignalError, OSError):
            ci = None
        previous = read_current(target)
        # Missing/error/auth/stale data cannot resolve a confirmed quota alarm.
        codex_unknown = snapshot["codex"] is None or snapshot["codex"]["status"] in (
            "stale", "unavailable", "auth_required", "unknown", "not_configured",
        )
        if codex_unknown:
            active = {item["code"] for item in findings}
            for item in previous:
                if item["code"] in ("codex_low", "codex_exhausted") and item["code"] not in active:
                    findings.append({"code": item["code"], "severity": "warning",
                                     "fingerprint": item["fingerprint"]})
        # A single low sample, a gap, or a disappearing telemetry source must
        # NOT clear a previously confirmed resource alarm. Clearing requires
        # three distinct recent values <=80% (hysteresis vs >=90% raise).
        active_codes = {item["code"] for item in findings}
        if infrastructure_dir is not None:
            for item in previous:
                code = item["code"]
                if code.startswith("infra_") and code.endswith((
                        "_cpu_high", "_ram_high", "_disk_high")):
                    host = "hermes" if code.startswith("infra_hermes_") else "yfc"
                    metric = code.rsplit("_", 2)[-2]
                    source = snapshot["infrastructure"][host]
                    levels = source.get("levels", {})
                    if levels.get(metric) != "normal" and code not in active_codes:
                        findings.append({"code": code, "severity": (
                            "critical" if metric == "disk" else "warning"),
                            "fingerprint": "ops:" + code})
                        active_codes.add(code)
        else:
            # Disabling the optional detector in an offline context must not
            # "resolve" a historically confirmed incident by omission.
            for item in previous:
                if item["code"].startswith("infra_") and item["code"] not in active_codes:
                    findings.append({"code": item["code"],
                                     "severity": "critical" if item["code"].endswith((
                                         "_unavailable", "_disk_high")) else "warning",
                                     "fingerprint": item["fingerprint"]})
                    active_codes.add(item["code"])
        # Missing/untrusted snapshots never prove recovery of a previously
        # measured quota threshold. Keep the old incident until a fresh,
        # explicitly confirmed good state or another measured threshold.
        active_quota = {item["code"] for item in findings}
        signals = snapshot.get("quota_signals", {})
        for previous_item in previous:
            code = previous_item["code"]
            if not code.startswith("quota_") or code in active_quota:
                continue
            provider = "desktop_commander" if code.startswith("quota_desktop_") else "github_api"
            state = signals.get(provider, "unknown")
            if state in ("unknown", "not_connected", "stale", "auth_required"):
                if code.endswith(("_80", "_95", "_exhausted")):
                    findings.append({"code": code,
                                     "severity": "critical" if code.endswith("_exhausted")
                                     else "warning",
                                     "fingerprint": previous_item["fingerprint"]})
                    active_quota.add(code)
        # Unreadable or missing presence observations do not prove recovery.
        # Only a fresh authenticated ONLINE signal may resolve a prior outage.
        for item in previous:
            code = item["code"]
            if code not in ("device_windows_pc_unavailable", "device_linux_vps_unavailable"):
                continue
            if any(current["code"] == code for current in findings):
                continue
            ident = "windows-pc" if code == "device_windows_pc_unavailable" else "linux-vps"
            signal = snapshot.get("device_fabric", {}).get(ident, {}).get("status")
            if signal != "online":
                findings.append({"code": code, "severity": item["severity"],
                                 "fingerprint": item["fingerprint"]})
        was_ci_failed = any(item["code"] == "ci_failed" for item in previous)
        if ci == "FAILURE" or (ci is None and was_ci_failed):
            findings.append({
                "code": "ci_failed", "severity": "warning",
                "fingerprint": "ops:ci_failed",
            })
        delta, previews, queued = persist(
            target, findings,
            lambda: _read_previous(target / "findings.json"),
            observed=now,
        )
        # Legacy JSON snapshots are recoverable derivatives of the DB.
        _atomic_json(target, "findings.json", findings)
        _atomic_json(target, "incident-preview.json", previews)
        return {
            "status": "ok", "active_codes": [f["code"] for f in findings],
            "changes": delta, "queued_incident_events": queued,
        }
    except BlockingIOError as exc:
        raise InputError("collector_already_running") from exc
    finally:
        os.close(fd)


def main() -> int:
    os.umask(0o077)
    try:
        result = once(
            alerts_timer=_ops_alert_timer_status(),
            alerts_service=_ops_alert_service_status(),
            infrastructure_dir=INFRASTRUCTURE_ROOT,
            device_fabric_db=DEVICE_DB, device_fabric_opt_in=DEVICE_OPT_IN,
            quota_paths={"codex": Q_CODEX, "desktop": Q_DESKTOP,
                         "cloudflare": Q_CF, "github": Q_GITHUB},
        )
    except (InputError, OSError, ValueError) as exc:
        # Log only an allowlisted internal error CLASS; no paths or user text.
        reason = str(exc) if type(exc) is InputError else type(exc).__name__
        if reason not in {
            "missing_news_health", "news_health_oversize", "unreadable_news_health",
            "missing_health_section", "unsafe_target_directory", "collector_already_running",
            "invalid_previous_state", "unreadable_previous_state",
            "invalid_last_discovery", "systemd_status_unavailable",
            "agent_guard_status_unavailable",
            "alert_sender_status_unavailable",
            "alert_delivery_status_unavailable",
            "invalid_consecutive_discovery_failures", "invalid_consecutive_drain_failures",
            "invalid_pending_jobs", "invalid_oldest_pending_age_seconds",
            "unsafe_outbox_db", "outbox_unavailable", "outbox_full",
            "corrupt_outbox_state", "legacy_state_oversize", "current_state_oversize",
        }:
            reason = "invalid_evidence"
        print(json.dumps({"status": "rejected", "reason": reason}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
