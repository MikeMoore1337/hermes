"""Opt-in official Cloudflare billing (DAILY, delayed) read-only usage.

This is NOT a live Workers AI daily quota meter. Billable Usage API data can
lag by 24+ hours and permissions may be absent. Never issue inference requests.
Never log API response bodies, account identifiers, headers or credentials.
"""
from __future__ import annotations

import datetime as dt
import json
import math
import os
from pathlib import Path
import re
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ACCOUNT = re.compile(r"[a-fA-F0-9]{32}\Z")
ROOT = Path("/var/lib/hermes-provider-quota")
OUTPUT = ROOT / "cloudflare-billing.json"
MAX_BODY = 131072
MAX_ROWS = 1024
TTL = dt.timedelta(days=3)
STATUSES = frozenset({"ok", "auth_required", "throttled", "unavailable", "unknown"})


class BillingError(Exception):
    """Public, fixed reason only. Raw HTTP data must never appear in logs."""
    pass


def utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        raise ValueError("timezone_required")
    return value.astimezone(dt.timezone.utc)


def iso(value: dt.datetime) -> str:
    return utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def error(status: str, now: dt.datetime) -> dict:
    if status not in STATUSES - {"ok"}:
        raise ValueError("status")
    return {"schema": 1, "source": "cloudflare-billable-usage-api",
            "status": status, "observed_at": iso(now),
            "last_complete_day": None, "days": []}


def parse(payload: bytes, *, now: dt.datetime) -> dict:
    """Store only exact day+neuron totals from unambiguous official rows."""
    if len(payload) > MAX_BODY:
        raise BillingError("oversized_response")
    try:
        obj = json.loads(payload)
    except (UnicodeDecodeError, ValueError) as exc:
        raise BillingError("invalid_json") from exc
    if not isinstance(obj, dict) or obj.get("success") is not True:
        raise BillingError("provider_failure")
    rows = obj.get("result")
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise BillingError("invalid_rows")
    today = utc(now).date()
    result = {}
    ambiguous = False
    for row in rows:
        if not isinstance(row, dict):
            raise BillingError("invalid_row")
        family = str(row.get("ServiceFamilyName") or row.get("x_ProductFamilyName") or "")
        description = str(row.get("ServiceName") or row.get("x_BillableMetricName") or "")
        unit = row.get("ConsumedUnit")
        if "workers ai" not in (family + " " + description).lower():
            continue
        # Never infer neurons from tokens, prices or units of "Requests".
        if not isinstance(unit, str) or unit.casefold() not in {"neuron", "neurons"}:
            ambiguous = True
            continue
        try:
            start = dt.datetime.fromisoformat(row["ChargePeriodStart"].replace("Z", "+00:00"))
            end = dt.datetime.fromisoformat(row["ChargePeriodEnd"].replace("Z", "+00:00"))
            quantity = row["ConsumedQuantity"]
        except (KeyError, AttributeError, ValueError, TypeError) as exc:
            raise BillingError("invalid_period") from exc
        if start.tzinfo is None or end.tzinfo is None:
            raise BillingError("timezone_missing")
        start, end = utc(start), utc(end)
        if (start.time() != dt.time(0, 0) or end - start != dt.timedelta(days=1)
                or end > dt.datetime.combine(today, dt.time(), dt.timezone.utc)):
            # Never treat incomplete/current UTC day as a current quota balance.
            continue
        if type(quantity) not in (int, float) or not math.isfinite(quantity) or quantity < 0:
            raise BillingError("invalid_quantity")
        if quantity > 1_000_000_000:
            raise BillingError("quantity_oversized")
        key = start.date().isoformat()
        result[key] = result.get(key, 0.0) + float(quantity)
    if ambiguous or not result:
        return error("unknown", now)
    days = [{"day": day, "neurons": round(neurons, 3)}
            for day, neurons in sorted(result.items())[-30:]]
    return {"schema": 1, "source": "cloudflare-billable-usage-api",
            "status": "ok", "observed_at": iso(now),
            "last_complete_day": days[-1]["day"], "days": days}


def read(token_path: Path, account: str, *, now: dt.datetime | None = None,
         transport=urlopen) -> dict:
    when = utc(now or dt.datetime.now(dt.timezone.utc))
    if not ACCOUNT.fullmatch(account):
        raise BillingError("invalid_account_config")
    if token_path.is_symlink() or not token_path.is_file():
        raise BillingError("missing_token")
    stat = token_path.stat()
    if stat.st_mode & 0o077 or stat.st_size > 512 or stat.st_size < 20:
        raise BillingError("invalid_token_file_permissions")
    secret = token_path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[\x21-\x7e]{20,512}", secret):
        raise BillingError("invalid_token")
    # Cloudflare Billing Read only: historical account usage, never model calls.
    start = (when.date() - dt.timedelta(days=30)).isoformat()
    end = when.date().isoformat()
    url = ("https://api.cloudflare.com/client/v4/accounts/" + account.lower()
           + "/billable-usage?from=" + start + "&to=" + end)
    request = Request(url, headers={
        "Authorization": "Bearer " + secret,
        "Accept": "application/json",
        "User-Agent": "hermes-provider-quota/1",
    }, method="GET")
    try:
        with transport(request, timeout=7) as response:
            status = response.status
            body = response.read(MAX_BODY + 1)
    except HTTPError as exc:
        if exc.code in (401, 403):
            return error("auth_required", when)
        if exc.code == 429:
            return error("throttled", when)
        return error("unavailable", when)
    except (OSError, URLError, TimeoutError):
        return error("unavailable", when)
    if status in (401, 403):
        return error("auth_required", when)
    if status == 429:
        return error("throttled", when)
    if status != 200:
        return error("unavailable", when)
    try:
        return parse(body, now=when)
    except BillingError:
        return error("unknown", when)


def save(snapshot: dict, path: Path = OUTPUT, *, group: str | None = None) -> None:
    if path.is_symlink():
        raise BillingError("symlink_denied")
    # Validate a complete sanitized round-trip before writing.
    if not isinstance(snapshot, dict) or set(snapshot) != {
        "schema", "source", "status", "observed_at", "last_complete_day", "days"
    } or snapshot["source"] != "cloudflare-billable-usage-api":
        raise BillingError("invalid_snapshot")
    if snapshot["status"] not in STATUSES or not isinstance(snapshot["days"], list):
        raise BillingError("invalid_snapshot")
    if len(snapshot["days"]) > 30:
        raise BillingError("invalid_history")
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    target_gid = None
    if group is not None:
        import grp
        target_gid = grp.getgrnam(group).gr_gid
        state = path.parent.lstat()
        # systemd owns the StateDirectory; CAP_CHOWN is intentionally absent.
        if (not path.parent.is_dir() or path.parent.is_symlink()
                or state.st_uid != os.geteuid() or state.st_gid != target_gid
                or (state.st_mode & 0o777) != 0o750):
            raise BillingError("unsafe_state_directory")
    target = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".cf-quota-", delete=False) as file:
            target = Path(file.name)
            json.dump(snapshot, file, separators=(",", ":"))
            file.write("\n")
            file.flush()
            os.fchmod(file.fileno(), 0o640)
            if target_gid is not None:
                owner = os.fstat(file.fileno())
                if owner.st_uid != os.geteuid() or owner.st_gid != target_gid:
                    raise BillingError("unsafe_snapshot_group")
            os.fsync(file.fileno())
        os.replace(target, path)
    finally:
        if target is not None:
            target.unlink(missing_ok=True)


def snapshot(path: Path = OUTPUT, *, now: dt.datetime | None = None) -> dict:
    current = utc(now or dt.datetime.now(dt.timezone.utc))
    if path.is_symlink() or not path.is_file():
        return error("unknown", current)
    try:
        if path.stat().st_size > 8192:
            raise ValueError("oversized_snapshot")
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("source") != "cloudflare-billable-usage-api":
            raise ValueError("invalid_source")
        if raw.get("schema") != 1 or raw.get("status") not in STATUSES:
            raise ValueError("invalid_schema")
        if set(raw) != {"schema", "source", "status", "observed_at",
                        "last_complete_day", "days"}:
            raise ValueError("invalid_fields")
        when = dt.datetime.fromisoformat(raw["observed_at"].replace("Z", "+00:00"))
        if utc(when) - current > dt.timedelta(minutes=2) or current - utc(when) > TTL:
            return error("unknown", current)
        if type(raw["days"]) is not list or len(raw["days"]) > 30:
            raise ValueError("days")
        previous = ""
        for row in raw["days"]:
            if not isinstance(row, dict) or set(row) != {"day", "neurons"}:
                raise ValueError("row")
            date = dt.date.fromisoformat(row["day"])
            if date >= current.date() or row["day"] <= previous:
                raise ValueError("date")
            value = row["neurons"]
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1e9:
                raise ValueError("value")
            previous = row["day"]
        if raw["last_complete_day"] != (previous or None):
            raise ValueError("last_complete_day")
        return raw
    except (OSError, TypeError, ValueError, AttributeError, KeyError, OverflowError):
        return error("unknown", current)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--account-id", default=os.environ.get("CLOUDFLARE_BILLING_ACCOUNT_ID"))
    parser.add_argument("--token-file", type=Path, default=Path(os.environ.get("CLOUDFLARE_BILLING_TOKEN_FILE", "/etc/hermes/cloudflare-billing-read.token")))
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    try:
        data = read(args.token_file, args.account_id or "")
        save(data, args.output, group="hermes-control")
        print("CLOUDFLARE_BILLING_READ=" + data["status"])
        return 0 if data["status"] == "ok" else 1
    except (OSError, BillingError, ValueError):
        print("CLOUDFLARE_BILLING_READ=unavailable")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
