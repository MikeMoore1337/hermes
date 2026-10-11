"""Read-only host admission checks for isolated Hermes experiments.

No service changes, swap configuration, model calls or external IO.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

NEWS_MIN_AVAILABLE_MIB = 768
NEWS_MAX_SWAP_USED_MIB = 1024
NEWS_MAX_LOAD1 = 1.50
NEWS_MIN_DISK_FREE_MIB = 5120
SMOKE_RESERVED_MIB = 128
SMOKE_MARGIN_MIB = 32


@dataclass(frozen=True)
class HostFacts:
    """Наблюдения о ресурсах без приватных данных."""

    available_mib: int
    swap_used_mib: int
    load1: float
    disk_free_mib: int
    news_phase_active: bool


def parse_meminfo(raw: str) -> tuple[int, int]:
    """Прочитать MemAvailable и использованный swap из /proc/meminfo."""
    values: dict[str, int] = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(":"):
            values[parts[0][:-1]] = int(parts[1])
    available = values["MemAvailable"] // 1024
    used = max(0, values["SwapTotal"] - values["SwapFree"]) // 1024
    return available, used


def evaluate(facts: HostFacts, *, reserve_mib: int, margin_mib: int) -> dict[str, object]:
    """Принять консервативное решение без запуска контейнера."""
    if reserve_mib <= 0 or margin_mib < 0:
        raise ValueError("reserve_mib must be > 0 and margin_mib >= 0")
    blockers: list[str] = []
    if facts.news_phase_active:
        blockers.append("news_phase_active")
    if facts.available_mib < NEWS_MIN_AVAILABLE_MIB + reserve_mib + margin_mib:
        blockers.append("insufficient_news_memory_headroom")
    if facts.swap_used_mib > NEWS_MAX_SWAP_USED_MIB:
        blockers.append("existing_news_swap_pressure")
    if facts.load1 > NEWS_MAX_LOAD1:
        blockers.append("existing_news_load_pressure")
    if facts.disk_free_mib < NEWS_MIN_DISK_FREE_MIB:
        blockers.append("existing_news_disk_pressure")
    return {
        "status": "ready" if not blockers else "skipped",
        "blockers": blockers,
        "facts": asdict(facts),
        "reserve_mib": reserve_mib,
        "margin_mib": margin_mib,
        "news_available_floor_mib": NEWS_MIN_AVAILABLE_MIB,
    }


def _systemd_active(name: str) -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=3,
        check=False,
    )
    return result.returncode == 0


def read_host_facts(state_dir: Path) -> HostFacts:
    """Снимать статистику только с Linux /proc и systemd."""
    if state_dir.is_symlink() or not state_dir.is_dir():
        raise RuntimeError("hermes_news_state_dir_missing")
    available, swap = parse_meminfo(Path("/proc/meminfo").read_text(encoding="ascii"))
    load1 = float(Path("/proc/loadavg").read_text(encoding="ascii").split()[0])
    disk_free = shutil.disk_usage(state_dir).free // (1024 * 1024)
    return HostFacts(
        available_mib=available,
        swap_used_mib=swap,
        load1=load1,
        disk_free_mib=disk_free,
        news_phase_active=any(
            _systemd_active(name)
            for name in ("hermes-discovery.service", "hermes-worker-drain.service")
        ),
    )


def main() -> int:
    """Напечатать безопасный JSON и запретить запуск при недостатке ресурсов."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--reserve-mib", type=int, default=SMOKE_RESERVED_MIB)
    parser.add_argument("--margin-mib", type=int, default=SMOKE_MARGIN_MIB)
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/hermes"))
    args = parser.parse_args()
    try:
        decision = evaluate(
            read_host_facts(args.state_dir),
            reserve_mib=args.reserve_mib,
            margin_mib=args.margin_mib,
        )
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "skipped", "blockers": [type(exc).__name__]}))
        return 1
    print(json.dumps(decision, ensure_ascii=False, sort_keys=True))
    return 0 if decision["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
