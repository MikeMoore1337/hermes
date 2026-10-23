"""Bounded read-only Linux metrics and offline snapshots for two explicitly known VPS."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
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
OFFLINE_AFTER = dt.timedelta(minutes=15)
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
    # Linux guest and guest_nice are already included in user and nice.
    # Counting them again inflates total CPU and distorts utilization.
    return sum(values[:8]), idle


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


def network_speed(before: str, after: str, seconds: float) -> dict[str, dict[str, float]]:
    """Per-interface B/s based on a bounded positive sampling interval."""
    if not (0 < seconds <= 10):
        raise ValueError("invalid network interval")
    first, last = network(before), network(after)
    result = {}
    for iface, counters in last.items():
        previous = first.get(iface)
        if previous is None:
            continue
        if any(counters[key] < previous[key] for key in ("rx_bytes", "tx_bytes")):
            continue
        result[iface] = {
            "rx_bytes_per_second": round((counters["rx_bytes"] - previous["rx_bytes"]) / seconds),
            "tx_bytes_per_second": round((counters["tx_bytes"] - previous["tx_bytes"]) / seconds),
        }
    return result


def build(host: str, *, before: str, after: str, meminfo: str,
          loadavg: str, uptime: str, disk: os.statvfs_result, dev: str,
          now: dt.datetime | None = None, dev_before: str | None = None,
          elapsed_seconds: float | None = None, cores: int | None = None) -> dict:
    if host not in HOSTS:
        raise ValueError("unknown host")
    load = [float(x) for x in loadavg.split()[:3]]
    if len(load) != 3 or any(not math.isfinite(x) or x < 0 for x in load):
        raise ValueError("invalid load")
    total_disk = disk.f_blocks * disk.f_frsize
    available_disk = disk.f_bavail * disk.f_frsize
    if total_disk <= 0 or not (0 <= available_disk <= total_disk):
        raise ValueError("invalid disk")
    age = now or dt.datetime.now(dt.timezone.utc)
    if age.tzinfo is None:
        raise ValueError("timezone required")
    metrics = memory(meminfo)
    inode_count = getattr(disk, "f_files", 0)
    inode_available = getattr(disk, "f_favail", 0)
    if inode_count and not 0 <= inode_available <= inode_count:
        raise ValueError("invalid inode count")
    metrics.update({
        "cpu_used_percent": cpu_percent(before, after),
        "cpu_cores": cores if isinstance(cores, int) and cores > 0 else None,
        "inode_used_percent": round(100 * (inode_count - inode_available) / inode_count, 1)
        if inode_count else None,
        "load1": load[0], "load5": load[1], "load15": load[2],
        "disk_total_bytes": total_disk,
        "disk_used_bytes": total_disk - available_disk,
        "disk_used_percent": round(100 * (total_disk - available_disk) / total_disk, 1),
        "uptime_seconds": int(float(uptime.split()[0])),
        "network_interfaces": network(dev),
        "network_rates": network_speed(dev_before, dev, elapsed_seconds)
        if dev_before is not None and elapsed_seconds is not None else {},
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
    dev_before = (proc / "net/dev").read_text(encoding="ascii")
    started = time.monotonic()
    delay(0.25)
    after = (proc / "stat").read_text(encoding="ascii").splitlines()[0]
    elapsed = time.monotonic() - started
    dev_after = (proc / "net/dev").read_text(encoding="ascii")
    return build(
        host, before=before, after=after,
        meminfo=(proc / "meminfo").read_text(encoding="ascii"),
        loadavg=(proc / "loadavg").read_text(encoding="ascii"),
        uptime=(proc / "uptime").read_text(encoding="ascii"),
        disk=os.statvfs(mount),
        dev=dev_after, dev_before=dev_before, elapsed_seconds=elapsed,
        cores=os.cpu_count(),
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
    # Refuse malformed or future input before touching the current host snapshot.
    checked = _validated(snapshot, host, dt.datetime.now(dt.timezone.utc))
    if checked["status"] == "stale" and host == "yfc":
        raise ValueError("stale remote input")
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o750)
    if group is not None:
        if os.geteuid() != 0:
            raise PermissionError("system collector must be root")
        import grp  # Linux only, never imported by the Windows UI
        gid = grp.getgrnam(group).gr_gid
        os.chown(directory, 0, gid)
    # A bounded lock prevents two timers from replacing an equal/newer snapshot
    # out of order. Different hosts also share one SQLite database.
    lock = directory / ".ingest.lock"
    if lock.is_symlink():
        raise ValueError("symlink ingest lock")
    with lock.open("a+b") as guard:
        if os.name == "posix":
            import fcntl  # Linux only; SQLite/unit fixtures can run on Windows.
            fcntl.flock(guard.fileno(), fcntl.LOCK_EX)
        current = directory / f"{host}.json"
        if current.is_symlink():
            raise ValueError("symlink host snapshot")
        if current.exists():
            if current.stat().st_size > 16384:
                raise ValueError("previous snapshot oversized")
            previous = json.loads(current.read_text(encoding="utf-8"))
            prior_time = dt.datetime.fromisoformat(
                str(previous["observed_at"]).replace("Z", "+00:00"))
            next_time = dt.datetime.fromisoformat(
                str(snapshot["observed_at"]).replace("Z", "+00:00"))
            if next_time <= prior_time:
                raise ValueError("out_of_order_snapshot")
        sanitized = {
            "schema": SCHEMA, "host": host,
            "source": "linux_procfs_local",
            "observed_at": checked["observed_at"],
            "received_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "metrics": checked["metrics"],
        }
        _write_atomic(current, sanitized)
        if group is not None:
            os.chown(current, 0, gid)
        _insert_history(directory, host, sanitized, group=group)
    return


def _insert_history(directory: Path, host: str, snapshot: dict, *, group: str | None) -> None:
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
        import grp
        os.chown(db, 0, grp.getgrnam(group).gr_gid)


def _validated(raw: object, host: str, now: dt.datetime) -> dict:
    if not isinstance(raw, dict) or raw.get("schema") != SCHEMA or raw.get("host") != host:
        raise ValueError("untrusted host data")
    date = dt.datetime.fromisoformat(str(raw["observed_at"]).replace("Z", "+00:00"))
    if date.tzinfo is None or date - now > MAX_FUTURE:
        raise ValueError("invalid timestamp")
    # Keep all stored and compared keys in the same UTC lexical ordering.
    canonical_time = date.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
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
    # These four counters and their rounded percentages come from the same
    # procfs/statvfs sample. Reject contradictory values before persistence,
    # display or Ops Watch consumers can interpret a fabricated low percent as
    # healthy. The collector rounds to one decimal; allow its 0.1% precision.
    for prefix in ("ram", "disk"):
        total = m[prefix + "_total_bytes"]
        used = m[prefix + "_used_bytes"]
        percent = m[prefix + "_used_percent"]
        if (type(total) is not int or type(used) is not int
                or not 0 < total < 10**18 or not 0 <= used <= total
                or abs(percent - 100 * used / total) > 0.11):
            raise ValueError("inconsistent capacity metrics")
    cpu = m.get("cpu_used_percent")
    if cpu is not None and (not isinstance(cpu, (int, float)) or isinstance(cpu, bool)
                            or not 0 <= cpu <= 100):
        raise ValueError("invalid cpu percent")
    # Prevent rendering arbitrary attacker-controlled keys/text in API responses.
    safe = {k: m.get(k) for k in (
        "cpu_used_percent", "ram_used_percent", "ram_total_bytes", "ram_used_bytes",
        "swap_total_bytes", "swap_used_bytes", "disk_used_percent",
        "disk_total_bytes", "disk_used_bytes", "load1", "load5", "load15",
        "uptime_seconds", "cpu_cores", "inode_used_percent")}
    if any(v is not None and (not isinstance(v, (int, float))
                             or isinstance(v, bool) or not math.isfinite(v)
                             or not 0 <= v < 10**18)
           for v in safe.values()):
        raise ValueError("invalid metric")
    if safe["inode_used_percent"] is not None and safe["inode_used_percent"] > 100:
        raise ValueError("invalid inode percent")
    if safe["cpu_cores"] is not None and (
            not isinstance(safe["cpu_cores"], int) or not 1 <= safe["cpu_cores"] <= 4096):
        raise ValueError("invalid cpu core count")
    net = m.get("network_rates", {})
    if not isinstance(net, dict) or len(net) > 24:
        raise ValueError("invalid network rates")
    cleaned_net = {}
    for key, item in net.items():
        if not isinstance(key, str) or not (1 <= len(key) <= 16) or not all(
                ch.isascii() and (ch.isalnum() or ch in "._-") for ch in key):
            raise ValueError("invalid interface name")
        if not isinstance(item, dict):
            raise ValueError("invalid network record")
        recv, sent = item.get("rx_bytes_per_second"), item.get("tx_bytes_per_second")
        if any(not isinstance(v, int) or isinstance(v, bool) or not 0 <= v < 10**12
               for v in (recv, sent)):
            raise ValueError("invalid network rate")
        cleaned_net[key] = {"rx_bytes_per_second": recv, "tx_bytes_per_second": sent}
    safe["network_rates"] = cleaned_net
    return {
        "host": host, "name": HOSTS[host],
        "status": "offline" if now - date > OFFLINE_AFTER else
                  "stale" if now - date > STALE_AFTER else "online",
        "observed_at": canonical_time, "metrics": safe,
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
    # Store minute-level details, serve bounded averages for 24h / 7d / 30d.
    # The response is under 300 points even after months of observations.
    window = {1: 300, 7: 3600, 30: 14400}[days]
    with sqlite3.connect(uri, uri=True, timeout=2) as connection:
        rows = connection.execute(
            "SELECT MAX(observed_at), AVG(cpu), AVG(ram), AVG(disk) "
            "FROM samples WHERE host=? AND observed_at>=? "
            "GROUP BY CAST(strftime('%s', observed_at) AS INTEGER) / ? "
            "ORDER BY MAX(observed_at) ASC LIMIT 400",
            (host, cutoff, window),
        ).fetchall()
    return {"schema": SCHEMA, "host": host,
            "samples": [{"observed_at": t, "cpu": c, "ram": r, "disk": d}
                        for t, c, r, d in rows]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, choices=tuple(HOSTS))
    parser.add_argument("--stdout", action="store_true",
                        help="emit a bounded fresh snapshot without modifying disk (SSH forced command)")
    args = parser.parse_args()
    snapshot = collect(args.host)
    if args.stdout:
        print(json.dumps(snapshot, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
    else:
        if args.host != "hermes":
            parser.error("YFC collection must be read via its scoped remote emit command")
        save(snapshot, group="hermes-control")


if __name__ == "__main__":
    main()
