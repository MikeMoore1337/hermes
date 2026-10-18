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


# This dataset is adaptive; Cloudflare may not expose confidence metadata
# for this account/field. A schema rejection must fail closed.
CONFIDENCE_QUERY = """
query HermesAdvisoryConfidence($accountTag: string, $start: Time, $end: Time) {
  viewer {
    accounts(filter: {accountTag: $accountTag}) {
      aiInferenceAdaptiveGroups(
        limit: 1, filter: {datetime_geq: $start, datetime_lt: $end}
      ) {
        sum { totalNeurons }
        confidence(level: 0.95) {
          sum { totalNeurons { estimate lower upper sampleSize } }
        }
      }
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


def _graphql(*, query: str, token: str, account: str,
             now: dt.datetime, transport=urlopen) -> tuple[str, dict | None]:
    """One read-only POST. Never return provider error messages or secrets."""
    start, end = yesterday_window(now)
    payload = json.dumps({"query": query, "variables": {
        "accountTag": account, "start": start, "end": end,
    }}, separators=(",", ":")).encode("utf-8")
    request = Request(ENDPOINT, data=payload, headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json",
        "Accept": "application/json", "User-Agent": "hermes-h15-analytics/1",
    }, method="POST")
    try:
        with transport(request, timeout=7) as response:
            if response.status != 200:
                return ("auth_required" if response.status in (401, 403)
                        else "unsupported_or_denied" if response.status == 400
                        else "throttled" if response.status == 429
                        else "unavailable", None)
            raw = response.read(MAX_BODY + 1)
    except HTTPError as exc:
        return ("auth_required" if exc.code in (401, 403)
                else "unsupported_or_denied" if exc.code == 400
                else "throttled" if exc.code == 429
                else "unavailable", None)
    except (OSError, URLError, TimeoutError):
        return "unavailable", None
    if len(raw) > MAX_BODY:
        return "unavailable", None
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, ValueError):
        return "unknown", None
    if not isinstance(decoded, dict) or decoded.get("errors"):
        return "unsupported_or_denied", None
    return "ok", decoded


def _single_group(decoded: dict) -> tuple[str, dict | None]:
    """The result has only one returned group, NOT proven total Free usage."""
    try:
        rows = decoded["data"]["viewer"]["accounts"]
        if not isinstance(rows, list) or len(rows) != 1:
            return "unknown", None
        groups = rows[0]["aiInferenceAdaptiveGroups"]
        if not isinstance(groups, list) or len(groups) > 1:
            return "unknown", None
        if not groups:
            return "no_confirmed_samples", None
        if not isinstance(groups[0], dict):
            return "unknown", None
        return "ok", groups[0]
    except (KeyError, TypeError, IndexError, AttributeError):
        return "unknown", None


def _valid_number(value: object) -> bool:
    return (type(value) in (int, float) and math.isfinite(value)
            and 0 <= value <= 1_000_000_000)


def inspect(*, token: str, account: str, now: dt.datetime,
            transport=urlopen) -> tuple[str, float | None]:
    """Original owner smoke: one read, informational single-group estimate."""
    status, decoded = _graphql(query=QUERY, token=token,
                               account=account, now=now, transport=transport)
    if status != "ok":
        return status, None
    status, group = _single_group(decoded)
    if status != "ok":
        return status, None
    try:
        neurons = group["sum"]["totalNeurons"]
    except (TypeError, KeyError):
        return "unknown", None
    if not _valid_number(neurons):
        return "unknown", None
    return "advisory_estimate", round(float(neurons), 3)


def inspect_confidence(*, token: str, account: str, now: dt.datetime,
                       transport=urlopen) -> tuple[str, dict | None]:
    """Optional one-query 95% CI capability check; no quota gate or persistence.

    The exact dataset might not support confidence for totalNeurons.
    A missing field/schema 400/GraphQL error is safely unsupported.
    """
    status, decoded = _graphql(query=CONFIDENCE_QUERY, token=token,
                               account=account, now=now, transport=transport)
    if status != "ok":
        return status, None
    status, group = _single_group(decoded)
    if status != "ok":
        return status, None
    try:
        consumed = group["sum"]["totalNeurons"]
        quality = group["confidence"]["sum"]["totalNeurons"]
        point, low, high = (quality[k] for k in ("estimate", "lower", "upper"))
        samples = quality["sampleSize"]
    except (TypeError, KeyError):
        return "unsupported_or_denied", None
    if (not all(map(_valid_number, (consumed, point, low, high)))
            or low > point or point > high
            or type(samples) is not int or not 1 <= samples <= 1_000_000_000):
        return "unknown", None
    return "advisory_confidence", {
        "estimate": round(float(point), 3),
        "lower": round(float(low), 3),
        "upper": round(float(high), 3),
        "sample_size": samples,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Owner-only advisory Cloudflare read")
    parser.add_argument("--confidence", action="store_true",
                        help="One separate optional read; fail closed if CI unsupported")
    args = parser.parse_args(argv or [])
    if os.geteuid() != 0:
        print("CLOUDFLARE_ANALYTICS=ROOT_REQUIRED")
        return 2
    try:
        token, account = load_credentials()
    except PreflightError:
        print("CLOUDFLARE_ANALYTICS=UNSAFE_OR_MISSING_CREDENTIALS")
        return 2
    now = dt.datetime.now(dt.timezone.utc)
    if args.confidence:
        status, interval = inspect_confidence(token=token, account=account, now=now)
        print("CLOUDFLARE_ANALYTICS_CONFIDENCE=" + status)
        if interval is not None:
            for name, field in (
                ("NEURONS_ESTIMATE", "estimate"),
                ("NEURONS_LOWER_95", "lower"),
                ("NEURONS_UPPER_95", "upper"),
                ("SAMPLE_SIZE", "sample_size"),
            ):
                print(name + "=" + str(interval[field]))
            print("QUOTA_REMAINING=UNKNOWN")
            print("BILLABLE_USAGE=NOT_VERIFIED")
        return 0 if status == "advisory_confidence" else 1
    status, estimate = inspect(token=token, account=account, now=now)
    print("CLOUDFLARE_ANALYTICS=" + status)
    if estimate is not None:
        print("PREVIOUS_UTC_DAY_NEURONS_ADAPTIVE_ESTIMATE=" + str(estimate))
        print("QUOTA_REMAINING=UNKNOWN")
        print("BILLABLE_USAGE=NOT_VERIFIED")
    return 0 if status == "advisory_estimate" else 1


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
