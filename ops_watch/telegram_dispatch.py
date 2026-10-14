"""Constrained Ops Watch Telegram dispatch for a separately approved systemd timer.

One invocation sends at most one already persisted catalog event. With no
--execute flag, it reads only aggregate state, not credentials or the network.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from .core import InputError
from .delivery_contract import stats
from .telegram_e2e import VerificationError, read_credentials
from .telegram_sender import TARGET, TelegramGateError, send_one

# systemd mounts only this approved outbox inside a private runtime directory.
SANDBOX_OUTBOX = Path("/run/hermes-ops-alerts/outbox")


def dispatch_once(directory: Path = SANDBOX_OUTBOX) -> dict[str, object]:
    """Read protected credentials, reserve one event, and persist real ACK."""
    token, chat = read_credentials()
    return send_one(directory, token=token, chat=chat, now=datetime.now(UTC))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hermes Ops Watch private alert sender")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.execute:
            result = dispatch_once()
        else:
            result = {"status": "DRY_RUN_ONLY", "queue": stats(TARGET)}
    except (VerificationError, TelegramGateError, InputError):
        # Never emit a credential, an HTTP URL, an untrusted exception or a body.
        print(json.dumps({"status": "REJECTED", "retry": "MANUAL_REVIEW_IF_UNCERTAIN"}))
        return 2
    except (OSError, TimeoutError):
        print(json.dumps({"status": "UNAVAILABLE", "retry": "MANUAL_REVIEW_IF_UNCERTAIN"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in (
        "DRY_RUN_ONLY", "EMPTY_OR_LEASED", "ACCEPTED_BY_TELEGRAM",
    ) else 2


if __name__ == "__main__":
    raise SystemExit(main())
