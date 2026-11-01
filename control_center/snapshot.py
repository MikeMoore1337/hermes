"""Produce a bounded, sanitized systemd snapshot; never touch agent secrets or logs."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys

# The UI is deployed as an immutable release behind an atomic 'current'
# symlink. Explicitly resolve the sibling research package against THIS code
# release: systemd's python -m startup must not depend on inherited PYTHONPATH
# or a current working directory that might resolve differently at restart.
_RELEASE_ROOT = str(Path(__file__).resolve().parent.parent)
if _RELEASE_ROOT not in sys.path:
    sys.path.insert(0, _RELEASE_ROOT)

from research_scout.report_view import read_owner_view
from control_center.infrastructure import collect as collect_host_metrics
from control_center.infrastructure import save as save_host_metrics
from control_center.github_observe_view import load as read_github_observe_feed, FeedRefused


DEFAULT_OUTPUT = Path("/var/lib/hermes-control-center/overview.json")
UNITS = (
    ("news", "Новости YFC", "hermes-discovery.timer", "schedule"),
    ("ops", "Ops Watch", "hermes-ops-watch.timer", "schedule"),
    ("alerts", "Telegram-уведомления", "hermes-ops-alerts.timer", "schedule"),
    ("qa", "QA Advisor", "hermes-qa-watch.timer", "schedule"),
    ("research", "Research Scout", "hermes-research-scout.timer", "schedule"),
    ("network", "Защита сети", "hermes-cloudflare-network-guard.service", "service"),
    ("agent_bounded", "H-01 Ops AI (ограниченный)", "hermes-h01-ops-agent.timer", "schedule"),
    ("agent", "Полный AI Agent (без допуска)", "hermes-agent-sandbox.service", "restricted"),
)
ALLOWED = {"active", "inactive", "failed", "unknown", "blocked", "unexpected_active"}


def unit_state(unit: str, runner=subprocess.run) -> str:
    """Call only the fixed systemd show command; no shell, journals or secrets."""
    try:
        proc = runner(
            ["systemctl", "show", "--no-pager", "--property=ActiveState",
             "--property=LoadState", unit],
            capture_output=True, text=True, timeout=3, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    if proc.returncode != 0:
        return "unknown"
    fields = dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)
    if fields.get("LoadState") not in ("loaded",):
        return "unknown"
    state = fields.get("ActiveState", "")
    return state if state in {"active", "inactive", "failed"} else "unknown"


def collect(runner=subprocess.run, now=None) -> dict:
    time = now or dt.datetime.now(dt.timezone.utc)
    services = []
    for ident, label, unit, kind in UNITS:
        state = unit_state(unit, runner)
        if kind == "restricted":
            state = "unexpected_active" if state == "active" else "blocked"
        services.append({"id": ident, "name": label, "unit": unit,
                         "kind": kind, "state": state})
    # Root-owned sanitized feed projected by the existing snapshot collector.
    # The web server has no GitHub token or outbound network access.
    try:
        github_observe = read_github_observe_feed()
    except (FeedRefused, OSError, ValueError):
        github_observe = None
    bounded_state = next(x["state"] for x in services if x["id"] == "agent_bounded")
    policy = ("Ограниченный H-01 Ops AI: расписание активно. " if bounded_state == "active"
              else "Ограниченный H-01 Ops AI: расписание не подтверждено. ")
    policy += "Полный AI Agent не допущен; успешность полезного цикла не доказана."
    return {
        "schema": 1,
        "generated_at": time.isoformat().replace("+00:00", "Z"),
        "source": "systemd read-only snapshot",
        "mode": "read_only",
        "services": services,
        "github_observe_feed": github_observe,
        "research": read_owner_view(),
        "agent_policy": policy,
        "agent_runtime": {"scope": "bounded_event_driven", "scheduler_state": bounded_state,
                          "last_useful_cycle": "unknown", "full_agent_allowed": False},
    }


def save_snapshot(snapshot: dict, output: Path = DEFAULT_OUTPUT, group="hermes-control") -> None:
    """Atomic replacement within a root-owned directory, readable by the web group."""
    if os.geteuid() != 0:
        raise PermissionError("Snapshot collector must run as root")
    import grp
    gid = grp.getgrnam(group).gr_gid
    output.parent.mkdir(parents=True, exist_ok=True)
    os.chown(output.parent, 0, gid)
    os.chmod(output.parent, 0o750)
    name = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent,
                                         prefix=".overview-", delete=False) as f:
            name = f.name
            json.dump(snapshot, f, ensure_ascii=False, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chown(name, 0, gid)
        os.chmod(name, 0o640)
        os.replace(name, output)
    finally:
        if name and os.path.exists(name):
            os.unlink(name)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    # Existing systemd timer already executes this collector once per minute.
    # Reuse it instead of installing a second timer during H-01 #33 burn-in.
    # Overview is committed first: unavailable metrics must never interrupt
    # the legacy control center or mark a host falsely healthy.
    save_snapshot(collect(), args.output)
    try:
        save_host_metrics(collect_host_metrics("hermes"), group="hermes-control")
    except Exception as exc:
        # Only fixed exception type; never log paths, contents or credentials.
        print("INFRASTRUCTURE_SNAPSHOT=unavailable category=" + type(exc).__name__,
              file=sys.stderr)


if __name__ == "__main__":
    main()
