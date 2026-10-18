"""Owner-invoked, single Cloudflare GraphQL Analytics read (#295).

Only a **completed previous UTC day** is queried. Adaptive aggregates can
be sampled and are NOT Free-tier billable usage or an admission quota. No
tokens, account IDs, GraphQL errors, raw responses, or history are logged.
No timer or inference is involved.
"""
from __future__ import annotations

import datetime as dt
import json
import math
import os
from pathlib import Path
import re
import stat
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

TOKEN = Path("/etc/hermes/cloudflare-analytics-read.token")
ACCOUNT_ENV = Path("/etc/hermes/cloudflare-analytics-read.env")
ENDPOINT = "https://api.cloudflare.com/client/v4/graphql"
MAX_BODY = 32768
QUERY = """
query HermesAdvisory($accountTag: string, $start: Time, $end: Time) {
  viewer {
    accounts(filter: {accountTag: $accountTag}) {
      aiInferenceAdaptiveGroups(
        limit: 1, filter: {datetime_geq: $start, datetime_lt: $end}
      ) { sum { totalNeurons } }
    }
  }
}
"""


class PreflightError(Exception):
    """Fixed output category - never wrap a raw provider exception."""


def root_secret(path: Path, *, max_bytes: int = 512, uid: int = 0) -> bytes:
    """Reject symlinks/hardlinks and non-root-owned or non-0600 secrets."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode)
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != uid or info.st_nlink != 1
                    or not 1 <= info.st_size <= max_bytes):
                raise PreflightError("unsafe_credentials")
            content = os.read(fd, max_bytes + 1)
            if len(content) != info.st_size:
                raise PreflightError("unsafe_credentials")
            return content
        finally:
            os.close(fd)
    except OSError as exc:
        raise PreflightError("unsafe_credentials") from None


def load_credentials(token_path: Path = TOKEN, account_path: Path = ACCOUNT_ENV,
                     *, uid: int = 0) -> tuple[str, str]:
    token = root_secret(token_path, uid=uid).rstrip(b"\n")
    if not re.fullmatch(rb"[\x21-\x7e]{20,512}", token):
        raise PreflightError("unsafe_credentials")
    account = root_secret(account_path, max_bytes=100, uid=uid)
    match = re.fullmatch(
        rb"CLOUDFLARE_ANALYTICS_ACCOUNT_ID=([0-9a-fA-F]{32})\n?", account
    )
    if match is None:
        raise PreflightError("unsafe_credentials")
    return token.decode("ascii"), match.group(1).decode("ascii")


def yesterday_window(now: dt.datetime) -> tuple[str, str]:
    if now.tzinfo is None:
        raise ValueError("timezone_required")
    utc = now.astimezone(dt.timezone.utc)
    midnight = dt.datetime.combine(utc.date(), dt.time(), dt.timezone.utc)
    previous = midnight - dt.timedelta(days=1)
    return (previous.isoformat().replace("+00:00", "Z"),
            midnight.isoformat().replace("+00:00", "Z"))


def inspect(*, token: str, account: str, now: dt.datetime,
            transport=urlopen) -> tuple[str, float | None]:
    """Bounded real analytics query; only validated advisory sum is returned."""
    start, end = yesterday_window(now)
    payload = json.dumps({
        "query": QUERY, "variables": {
            "accountTag": account, "start": start, "end": end,
        }
    }, separators=(",", ":")).encode("utf-8")
    request = Request(ENDPOINT, data=payload, headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json",
        "Accept": "application/json", "User-Agent": "hermes-h15-analytics/1",
    }, method="POST")  # GraphQL uses POST, but the operation is read-only query.
    try:
        with transport(request, timeout=7) as response:
            if response.status != 200:
                return ("auth_required" if response.status in (401, 403)
                        else "throttled" if response.status == 429
                        else "unavailable", None)
            raw = response.read(MAX_BODY + 1)
    except HTTPError as exc:
        return ("auth_required" if exc.code in (401, 403) else
                "throttled" if exc.code == 429 else "unavailable", None)
    except (OSError, URLError, TimeoutError):
        return "unavailable", None
    if len(raw) > MAX_BODY:
        return "unavailable", None
    try:
        decoded = json.loads(raw)
        if not isinstance(decoded, dict) or decoded.get("errors"):
            return "unsupported_or_denied", None
        rows = decoded["data"]["viewer"]["accounts"]
        if not isinstance(rows, list) or len(rows) != 1:
            return "unknown", None
        groups = rows[0]["aiInferenceAdaptiveGroups"]
        if not isinstance(groups, list) or len(groups) > 1:
            return "unknown", None
        if len(groups) == 0:
            return "no_confirmed_samples", None
        neurons = groups[0]["sum"]["totalNeurons"]
        if type(neurons) not in (int, float) or not math.isfinite(neurons):
            return "unknown", None
        if neurons < 0 or neurons > 1_000_000_000:
            return "unknown", None
        return "advisory_estimate", round(float(neurons), 3)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError):
        return "unknown", None


def main() -> int:
    if os.geteuid() != 0:
        print("CLOUDFLARE_ANALYTICS=ROOT_REQUIRED")
        return 2
    try:
        token, account = load_credentials()
    except PreflightError:
        print("CLOUDFLARE_ANALYTICS=UNSAFE_OR_MISSING_CREDENTIALS")
        return 2
    status, estimate = inspect(
        token=token, account=account, now=dt.datetime.now(dt.timezone.utc))
    print("CLOUDFLARE_ANALYTICS=" + status)
    if estimate is not None:
        print("PREVIOUS_UTC_DAY_NEURONS_ADAPTIVE_ESTIMATE=" + str(estimate))
        print("QUOTA_REMAINING=UNKNOWN")
        print("BILLABLE_USAGE=NOT_VERIFIED")
    return 0 if status == "advisory_estimate" else 1


if __name__ == "__main__":
    raise SystemExit(main())
