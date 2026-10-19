"""One-shot owner opt-in: archive Cloudflare's completed-day adaptive estimate.

Never reads Billing API or runs Workers AI inference, never derives Free quota.
Designed for root process with an explicit hermes-control primary group.
No background timer or on-host action is installed by adding this module.
"""
from __future__ import annotations

import datetime as dt
import grp
import os
import stat

from control_center import cloudflare_analytics_history as history
from scripts import h15_cloudflare_analytics_probe as probe


def main() -> int:
    if os.geteuid() != 0:
        print("CLOUDFLARE_ADVISORY_ARCHIVE=ROOT_REQUIRED")
        return 2
    if os.getegid() != grp.getgrnam("hermes-control").gr_gid:
        print("CLOUDFLARE_ADVISORY_ARCHIVE=GROUP_REQUIRED")
        return 2
    directory = history.OUTPUT.parent
    if directory.is_symlink() or not directory.is_dir():
        print("CLOUDFLARE_ADVISORY_ARCHIVE=STATE_UNAVAILABLE")
        return 2
    info = directory.stat()
    if (info.st_uid != 0 or
            info.st_gid != os.getegid() or
            stat.S_IMODE(info.st_mode) != 0o750):
        print("CLOUDFLARE_ADVISORY_ARCHIVE=UNSAFE_STATE_DIRECTORY")
        return 2

    # One confirmed observation per *completed UTC day*. Persistent timer
    # catch-up and manual smoke must not trigger duplicate provider reads.
    now = dt.datetime.now(dt.timezone.utc)
    previous, _ = probe.yesterday_window(now)
    archive = history.OUTPUT
    if archive.is_symlink():
        print("CLOUDFLARE_ADVISORY_ARCHIVE=UNSAFE_EXISTING_ARCHIVE")
        return 2
    if archive.exists():
        metadata = archive.stat()
        if (not stat.S_ISREG(metadata.st_mode) or
                metadata.st_uid != 0 or
                metadata.st_gid != os.getegid() or
                metadata.st_nlink != 1 or
                stat.S_IMODE(metadata.st_mode) != 0o640):
            print("CLOUDFLARE_ADVISORY_ARCHIVE=UNSAFE_EXISTING_ARCHIVE")
            return 2
    stored = history.read(now=now)
    if archive.exists() and stored["status"] == "unknown":
        print("CLOUDFLARE_ADVISORY_ARCHIVE=UNSAFE_EXISTING_ARCHIVE")
        return 2
    if any(x["day"] == previous[:10] for x in stored["days"]):
        print("CLOUDFLARE_ADVISORY_ARCHIVE=already_collected")
        print("OBSERVATION_DAY=" + previous[:10])
        print("QUOTA_REMAINING=UNKNOWN")
        print("BILLABLE_USAGE=NOT_VERIFIED")
        return 0
    try:
        token, account = probe.load_credentials()
    except probe.PreflightError:
        print("CLOUDFLARE_ADVISORY_ARCHIVE=UNSAFE_OR_MISSING_CREDENTIALS")
        return 2
    status, confidence = probe.inspect_confidence(
        token=token, account=account, now=now)
    if status == "no_confirmed_samples" and confidence is None:
        # An authenticated, well-formed response with no Adaptive groups
        # is a completed source check, not a provider outage or zero use.
        # Keep historical estimates untouched and NEVER record 0 Neurons.
        print("CLOUDFLARE_ADVISORY_ARCHIVE=no_confirmed_samples")
        print("OBSERVATION_DAY=" + previous[:10])
        print("HISTORY_UPDATED=false")
        print("QUOTA_REMAINING=UNKNOWN")
        print("BILLABLE_USAGE=NOT_VERIFIED")
        return 0
    if status != "advisory_confidence" or confidence is None:
        print("CLOUDFLARE_ADVISORY_ARCHIVE=" + status)
        return 1
    try:
        previous, _ = probe.yesterday_window(now)
        row = history.observation(previous[:10], confidence, now=now)
        history.append(row, now=now)
    except (OSError, ValueError, KeyError):
        print("CLOUDFLARE_ADVISORY_ARCHIVE=SAVE_UNAVAILABLE")
        return 1
    print("CLOUDFLARE_ADVISORY_ARCHIVE=historical_estimate_saved")
    print("OBSERVATION_DAY=" + row["day"])
    print("QUALITY=" + row["quality"])
    print("SAMPLE_SIZE=" + str(row["sample_size"]))
    print("QUOTA_REMAINING=UNKNOWN")
    print("BILLABLE_USAGE=NOT_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
