"""Bounded read-only Linux metrics and offline snapshots for two explicitly known VPS."""
from __future__ import annotations

import argparse
import datetime as dt
import grp
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
from urllib.parse import quote

ROOT = Path("/var/lib/hermes-control-center/infrastructure")
HOSTS = {"hermes": "VPS Hermes", "yfc": "VPS YFC"}
SCHEMA = 1
STALE_AFTER = dt.timedelta(minutes=3)
MAX_FUTURE = dt.timedelta(seconds=30)
RETENTION_DAYS = 30


def cpu_counters(line: str) -> tuple[int, int]:
    parts = line.split()
    if len(parts) < 5 or parts[0] != "cpu":
        raise ValueError("invalid cpu counters")
    values = [int(x) for x in parts[1:]]
    if any(v < 0 for v in values):
        raise ValueError("negative cpu counter")
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def cpu_percent(before: str, after: str) -> float | None:
    t0, i0 = cpu_counters(before)
    t1, i1 = cpu_counters(after)
    elapsed = t1 - t0
    idle = i1 - i0
    if elapsed <= 0 or idle < 0 or idle > elapsed:
        return None
    return round(100 * (elapsed - idle) / elapsed, 1)


def memory(meminfo: str) -> dict:
    fields = {}
    for line in meminfo.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(":") and parts[1].isdigit():
            fields[parts[0][:-1]] = int(parts[1])
    total, available = fields["MemTotal"], fields["MemAvailable"]
    swap_total, swap_free = fields.get("SwapTotal", 0), fields.get("SwapFree", 0)
    if total <= 0 or not (0 <= available <= total) or not (0 <= swap_free <= swap_total):
        raise ValueError("invalid memory values")
    return {
        "ram_total_bytes": total * 1024,
        "ram_used_bytes": (total - available) * 1024,
        "ram_used_percent": round(100 * (total - available) / total, 1),
        "swap_total_bytes": swap_total * 1024,
        "swap_used_bytes": (swap_total - swap_free) * 1024,
    }


def network(dev: str) -> dict:
    """Report per-interface counters, not a misleading sum of virtual interfaces."""
    result = {}
    for line in dev.splitlines()[2:]:
        if ":" not in line:
            continue
        name, values = line.split(":", 1)
        name = name.strip()
        parts = values.split()
        if not name or name == "lo" or len(parts) < 16:
            continue
        if len(result) >= 24:
            break
        try:
            result[name] = {"rx_bytes": int(parts[0]), "tx_bytes": int(parts[8])}
        except ValueError:
            continue
    return result


def build(host: str, *, before: str, after: str, meminfo: str,
          loadavg: str, uptime: str, disk: os.statvfs_result, dev: str,
          now: dt.datetime | None = None) -> dict:
    if host not in HOSTS:
        raise ValueError("unknown host")
    load = [float(x) for x in loadavg.split()[:3]]
    if len(load) != 3 or any(x < 0 for x in load):
        raise ValueError("invalid load")
    total_disk = disk.f_blocks * disk.f_frsize
    available_disk = disk.f_bavail * disk.f_frsize
    if total_disk <= 0 or not (0 <= available_disk <= total_disk):
        raise ValueError("invalid disk")
    age = now or dt.datetime.now(dt.timezone.utc)
    if age.tzinfo is None:
        raise ValueError("timezone required")
    metrics = memory(meminfo)
    metrics.update({
        "cpu_used_percent": cpu_percent(before, after),
        "load1": load[0], "load5": load[1], "load15": load[2],
        "disk_total_bytes": total_disk,
        "disk_used_bytes": total_disk - available_disk,
        "disk_used_percent": round(100 * (total_disk - available_disk) / total_disk, 1),
        "uptime_seconds": int(float(uptime.split()[0])),
        "network_interfaces": network(dev),
    })
    return {
        "schema": SCHEMA,
        "host": host,
        "observed_at": age.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": "linux_procfs_local",
        "metrics": metrics,
    }


def collect(host: str, *, proc: Path = Path("/proc"), mount: Path = Path("/"),
            delay=time.sleep) -> dict:
    # No subprocess, network or model/provider invocation.
    before = (proc / "stat").read_text(encoding="ascii").splitlines()[0]
    delay(0.25)
    after = (proc / "stat").read_text(encoding="ascii").splitlines()[0]
    return build(
        host, before=before, after=after,
        meminfo=(proc / "meminfo").read_text(encoding="ascii"),
        loadavg=(proc / "loadavg").read_text(encoding="ascii"),
        uptime=(proc / "uptime").read_text(encoding="ascii"),
        disk=os.statvfs(mount),
        dev=(proc / "net/dev").read_text(encoding="ascii"),
    )


def _write_atomic(path: Path, payload: dict) -> None:
    name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.stem}-", delete=False,
        ) as fh:
            name = fh.name
            json.dump(payload, fh, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(name, 0o640)
        os.replace(name, path)
    finally:
        if name and os.path.exists(name):
            os.unlink(name)


def save(snapshot: dict, directory: Path = ROOT, *, group: str | None = None) -> None:
    host = snapshot.get("host")
    if host not in HOSTS or snapshot.get("schema") != SCHEMA:
        raise ValueError("invalid host snapshot")
    if directory.is_symlink():
        raise ValueError("symlink directory")
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o750)
    if group is not None:
        if os.geteuid() != 0:
            raise PermissionError("system collector must be root")
        gid = grp.getgrnam(group).gr_gid
        os.chown(directory, 0, gid)
    _write_atomic(directory / f"{host}.json", snapshot)
    if group is not None:
        os.chown(directory / f"{host}.json", 0, gid)
    db = directory / "history.sqlite3"
    if db.is_symlink():
        raise ValueError("symlink history database")
    with sqlite3.connect(db, timeout=3) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS samples "
                           "(host TEXT NOT NULL, observed_at TEXT NOT NULL, "
                           "cpu REAL, ram REAL, disk REAL, PRIMARY KEY(host, observed_at))")
        metrics = snapshot["metrics"]
        connection.execute("INSERT OR IGNORE INTO samples VALUES (?, ?, ?, ?, ?)",
                           (host, snapshot["observed_at"],
                            metrics["cpu_used_percent"], metrics["ram_used_percent"],
                            metrics["disk_used_percent"]))
        cutoff = (dt.datetime.now(dt.timezone.utc) -
                  dt.timedelta(days=RETENTION_DAYS)).isoformat().replace("+00:00", "Z")
        connection.execute("DELETE FROM samples WHERE observed_at < ?", (cutoff,))
    os.chmod(db, 0o640)
    if group is not None:
        os.chown(db, 0, gid)


def _validated(raw: object, host: str, now: dt.datetime) -> dict:
    if not isinstance(raw, dict) or raw.get("schema") != SCHEMA or raw.get("host") != host:
        raise ValueError("untrusted host data")
    date = dt.datetime.fromisoformat(str(raw["observed_at"]).replace("Z", "+00:00"))
    if date.tzinfo is None or date - now > MAX_FUTURE:
        raise ValueError("invalid timestamp")
    m = raw.get("metrics")
    if not isinstance(m, dict):
        raise ValueError("invalid metrics")
    required = ("ram_used_percent", "disk_used_percent", "ram_total_bytes",
                "ram_used_bytes", "disk_total_bytes", "disk_used_bytes")
    if any(not isinstance(m.get(k), (int, float)) or isinstance(m.get(k), bool)
           for k in required):
        raise ValueError("invalid numeric metric")
    if any(not 0 <= m[k] <= 100 for k in ("ram_used_percent", "disk_used_percent")):
        raise ValueError("invalid percent")
    cpu = m.get("cpu_used_percent")
    if cpu is not None and (not isinstance(cpu, (int, float)) or isinstance(cpu, bool)
                            or not 0 <= cpu <= 100):
        raise ValueError("invalid cpu percent")
    # Prevent rendering arbitrary attacker-controlled keys/text in API responses.
    safe = {k: m.get(k) for k in (
        "cpu_used_percent", "ram_used_percent", "ram_total_bytes", "ram_used_bytes",
        "swap_total_bytes", "swap_used_bytes", "disk_used_percent",
        "disk_total_bytes", "disk_used_bytes", "load1", "load5", "load15",
        "uptime_seconds")}
    if any(v is not None and (not isinstance(v, (int, float))
                             or isinstance(v, bool) or not 0 <= v < 10**18)
           for v in safe.values()):
        raise ValueError("invalid metric")
    return {
        "host": host, "name": HOSTS[host],
        "status": "stale" if now - date > STALE_AFTER else "online",
        "observed_at": raw["observed_at"], "metrics": safe,
    }


def hosts(directory: Path = ROOT, now: dt.datetime | None = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    result = []
    for host, name in HOSTS.items():
        path = directory / f"{host}.json"
        if path.is_symlink() or not path.is_file():
            result.append({"host": host, "name": name, "status": "not_connected"})
            continue
        try:
            if path.stat().st_size > 16384:
                raise ValueError("oversized snapshot")
            entry = _validated(json.loads(path.read_text(encoding="utf-8")), host, now)
        except (OSError, UnicodeError, ValueError, KeyError, TypeError, OverflowError):
            entry = {"host": host, "name": name, "status": "unknown"}
        result.append(entry)
    return {"schema": SCHEMA, "mode": "read_only", "hosts": result}


def history(directory: Path, host: str, days: int = 1) -> dict:
    if host not in HOSTS or days not in (1, 7, 30):
        raise ValueError("invalid history request")
    db = directory / "history.sqlite3"
    if db.is_symlink() or not db.is_file():
        return {"schema": SCHEMA, "host": host, "samples": []}
    cutoff = (dt.datetime.now(dt.timezone.utc) -
              dt.timedelta(days=days)).isoformat().replace("+00:00", "Z")
    uri = "file:" + quote(str(db.resolve())) + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=2) as connection:
        rows = connection.execute(
            "SELECT observed_at, cpu, ram, disk FROM samples "
            "WHERE host=? AND observed_at>=? ORDER BY observed_at ASC LIMIT 44000",
            (host, cutoff),
        ).fetchall()
    return {"schema": SCHEMA, "host": host,
            "samples": [{"observed_at": t, "cpu": c, "ram": r, "disk": d}
                        for t, c, r, d in rows]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, choices=tuple(HOSTS))
    args = parser.parse_args()
    # Two deployments, one immutable collector. Transport for YFC is intentionally
    # not inferred from the existence of a local snapshot.
    save(collect(args.host), group="hermes-control")


if __name__ == "__main__":
    main()
