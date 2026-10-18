"""#295 Cloudflare Workers AI historical adaptive analytics - advisory only.

This is NOT a Free-tier quota meter, billable ledger, or model admission gate.
Only completed UTC days with validated samples can be stored. Read and write
are bounded and sanitised; no account IDs, tokens, prompts or GraphQL payloads.
"""
from __future__ import annotations

import datetime as dt
import grp
import json
import math
import os
from pathlib import Path
import stat
import tempfile

OUTPUT = Path("/var/lib/hermes-provider-quota/cloudflare-analytics-advisory.json")
SOURCE = "cloudflare-ai-inference-adaptive"
SCHEMA = 1
MAX_DAYS = 30
MAX_BYTES = 8192
FIELDS = {"day", "estimate_neurons", "lower95_neurons", "upper95_neurons",
          "sample_size", "quality"}
QUALITY = {"very_small_sample", "limited_sample", "adaptive_estimate"}


class AdvisoryError(ValueError):
    pass


def _date(value: object) -> dt.date:
    if not isinstance(value, str) or len(value) != 10:
        raise AdvisoryError("date")
    try:
        return dt.date.fromisoformat(value)
    except ValueError as exc:
        raise AdvisoryError("date") from exc


def _time(value: object) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 32:
        raise AdvisoryError("timestamp")
    try:
        moment = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AdvisoryError("timestamp") from exc
    if moment.tzinfo is None:
        raise AdvisoryError("timestamp")
    return moment.astimezone(dt.timezone.utc)


def _number(value: object) -> bool:
    return type(value) in (float, int) and math.isfinite(value) and 0 <= value <= 1e9


def _validate(row: dict, *, now: dt.datetime) -> dict:
    if not isinstance(row, dict) or set(row) != FIELDS:
        raise AdvisoryError("observation_fields")
    day = _date(row["day"])
    current_day = now.astimezone(dt.timezone.utc).date()
    if day >= current_day or (current_day - day).days > MAX_DAYS:
        raise AdvisoryError("observation_day")
    numbers = [row[key] for key in
               ("estimate_neurons", "lower95_neurons", "upper95_neurons")]
    if not all(_number(num) for num in numbers):
        raise AdvisoryError("observation_values")
    estimate, lower, upper = numbers
    if lower > estimate or estimate > upper:
        raise AdvisoryError("observation_interval")
    size = row["sample_size"]
    if type(size) is not int or not 1 <= size <= 1_000_000_000:
        raise AdvisoryError("observation_sample")
    quality = ("very_small_sample" if size < 10 else
               "limited_sample" if size < 30 else "adaptive_estimate")
    if row["quality"] != quality or quality not in QUALITY:
        raise AdvisoryError("observation_quality")
    return row


def observation(day: str, ci: dict, *, now: dt.datetime) -> dict:
    if not isinstance(ci, dict) or set(ci) != {
            "estimate", "lower", "upper", "sample_size"}:
        raise AdvisoryError("interval_fields")
    size = ci["sample_size"]
    if type(size) is not int:
        raise AdvisoryError("sample_size")
    row = {
        "day": day, "estimate_neurons": ci["estimate"],
        "lower95_neurons": ci["lower"],
        "upper95_neurons": ci["upper"],
        "sample_size": size,
        "quality": ("very_small_sample" if size < 10 else
                    "limited_sample" if size < 30 else "adaptive_estimate"),
    }
    return _validate(row, now=now)


def read(path: Path = OUTPUT, *, now: dt.datetime | None = None) -> dict:
    moment = now or dt.datetime.now(dt.timezone.utc)
    if moment.tzinfo is None:
        raise AdvisoryError("timezone")
    result = {"status": "unknown", "observed_at": None, "days": []}
    try:
        if path.is_symlink() or not path.is_file():
            return result
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            return result
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or set(raw) != {
                "schema", "source", "observed_at", "days"}:
            return result
        if raw["schema"] != SCHEMA or raw["source"] != SOURCE:
            return result
        when = _time(raw["observed_at"])
        if when > moment.astimezone(dt.timezone.utc) + dt.timedelta(minutes=2):
            return result
        days = raw["days"]
        if not isinstance(days, list) or not 1 <= len(days) <= MAX_DAYS:
            return result
        if [_validate(row, now=moment)["day"] for row in days] != sorted(
                {row["day"] for row in days}):
            return result
        result["observed_at"] = raw["observed_at"]
        result["days"] = days
        newest = _date(days[-1]["day"])
        result["status"] = ("historical_estimate" if
                            (moment.astimezone(dt.timezone.utc).date() - newest).days <= 2
                            else "stale")
        return result
    except (OSError, UnicodeError, ValueError, TypeError, KeyError,
            OverflowError, AttributeError):
        return result


def append(row: dict, *, path: Path = OUTPUT, group: str = "hermes-control",
           now: dt.datetime | None = None) -> None:
    moment = now or dt.datetime.now(dt.timezone.utc)
    if moment.tzinfo is None:
        raise AdvisoryError("timezone")
    _validate(row, now=moment)
    if path.is_symlink():
        raise AdvisoryError("symlink")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise AdvisoryError("state_directory")
    directory = path.parent.stat()
    required_gid = grp.getgrnam(group).gr_gid
    if (directory.st_uid != os.geteuid() or directory.st_gid != required_gid
            or (directory.st_mode & 0o777) != 0o750
            or os.getegid() != required_gid):
        raise AdvisoryError("state_ownership")
    stored = read(path, now=moment)
    if path.exists() and stored["status"] == "unknown":
        raise AdvisoryError("invalid_existing_archive")
    days = [day for day in stored["days"] if day["day"] != row["day"]]
    days.append(row)
    days.sort(key=lambda item: item["day"])
    days = [x for x in days if (
        moment.astimezone(dt.timezone.utc).date() - _date(x["day"])).days <= MAX_DAYS][-MAX_DAYS:]
    payload = {
        "schema": SCHEMA, "source": SOURCE,
        "observed_at": moment.astimezone(dt.timezone.utc)
        .isoformat(timespec="seconds").replace("+00:00", "Z"),
        "days": days,
    }
    data = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_BYTES:
        raise AdvisoryError("archive_oversize")
    temp = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="wb", dir=path.parent, prefix=".cloudflare-analytics-",
                delete=False) as file:
            temp = Path(file.name)
            os.fchmod(file.fileno(), 0o640)
            info = os.fstat(file.fileno())
            if info.st_uid != os.geteuid() or info.st_gid != required_gid:
                raise AdvisoryError("temp_ownership")
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp, path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)
