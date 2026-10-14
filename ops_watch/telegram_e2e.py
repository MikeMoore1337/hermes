"""One-shot, owner-approved Ops Watch delivery E2E in an ISOLATED temp journal.

Never write a synthetic incident into the production Ops Watch queue.
A Telegram 200+message_id is accepted by Telegram, not proof user read it.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable

from .core import InputError
from .state_store import persist
from .telegram_sender import (
    TelegramGateError, _credentials, post_once, send_one,
)

CREDENTIALS = Path("/etc/hermes-agent/ops-watch.env")
EXPECTED = frozenset({"HERMES_ALERT_BOT_TOKEN", "HERMES_ALERT_PRIVATE_CHAT_ID"})
MAX_CREDENTIAL_BYTES = 512
MARKER = "ТЕСТ Hermes Ops Watch. Реального сбоя нет.\n"


class VerificationError(ValueError):
    """Fixed sanitized error code, never raw external input."""


def read_credentials(path: Path = CREDENTIALS) -> tuple[str, str]:
    """Read exactly two secrets through an O_NOFOLLOW, owner-only descriptor."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise VerificationError("credential_file_unavailable") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.geteuid() or info.st_nlink != 1
                or not 1 <= info.st_size <= MAX_CREDENTIAL_BYTES):
            raise VerificationError("credential_file_unsafe")
        raw = os.read(fd, MAX_CREDENTIAL_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_CREDENTIAL_BYTES:
        raise VerificationError("credential_file_unsafe")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        raise VerificationError("credential_file_invalid") from None
    if len(lines) != 2 or any(line.count("=") != 1 for line in lines):
        raise VerificationError("credential_file_invalid")
    pairs = [line.split("=", 1) for line in lines]
    values = dict(pairs)
    if set(values) != EXPECTED or len(values) != 2:
        raise VerificationError("credential_file_invalid")
    token, chat = values["HERMES_ALERT_BOT_TOKEN"], values["HERMES_ALERT_PRIVATE_CHAT_ID"]
    try:
        _credentials(token, chat)
    except TelegramGateError:
        raise VerificationError("credential_values_invalid") from None
    return token, chat


def verify_once(
    token: str, chat: str, *,
    transport: Callable[..., int] = post_once,
) -> dict[str, object]:
    """Send one explicitly marked TEST to private chat and verify real receipt."""
    _credentials(token, chat)
    now = datetime.now(UTC)
    with TemporaryDirectory(prefix="hermes-ops-e2e-") as name:
        isolated = Path(name)
        isolated.chmod(0o700)
        delta, preview, count = persist(
            isolated,
            [{"code": "ci_failed", "fingerprint": "ops:ci_failed"}],
            lambda: [], observed=now,
        )
        if (delta != {"raised": ["ops:ci_failed"], "resolved": []}
                or count != 1 or len(preview) != 1):
            raise VerificationError("synthetic_event_invalid")
        sent_calls = 0

        def marked_transport(*, token: str, chat_id: int, text: str) -> int:
            nonlocal sent_calls
            sent_calls += 1
            if sent_calls != 1:
                raise VerificationError("multiple_transports_attempted")
            return transport(token=token, chat_id=chat_id, text=MARKER + text)

        first = send_one(
            isolated, token=token, chat=chat, now=now,
            transport=marked_transport,
        )
        if first != {"status": "ACCEPTED_BY_TELEGRAM", "event_id": 1}:
            raise VerificationError("receipt_status_invalid")

        def fail_if_sent_again(**_kwargs: object) -> int:
            raise VerificationError("duplicate_transport_attempted")

        again = send_one(
            isolated, token=token, chat=chat, now=datetime.now(UTC),
            transport=fail_if_sent_again,
        )
        if again.get("status") != "EMPTY_OR_LEASED" or sent_calls != 1:
            raise VerificationError("duplicate_not_blocked")

        db_path = isolated / "incidents.sqlite3"
        with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True) as db:
            row = db.execute(
                "SELECT status,attempts,telegram_message_id,acknowledged_at "
                "FROM delivery_receipts WHERE event_id=1"
            ).fetchone()
        if (row is None or row[0] != "acknowledged" or row[1] != 1
                or type(row[2]) is not int or row[2] <= 0
                or not row[3]):
            raise VerificationError("persisted_receipt_invalid")
        return {
            "status": "ACCEPTED_BY_TELEGRAM_AND_ACK_PERSISTED",
            "synthetic_only": True,
            "message_id": row[2],
            "attempts": 1,
            "duplicate_send_blocked": True,
            "production_queue_modified": False,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explicit owner-only Telegram E2E")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"status": "NOT_EXECUTED", "reason": "requires_--execute"}))
        return 0
    os.umask(0o077)
    try:
        token, chat = read_credentials()
        result = verify_once(token, chat)
    except (VerificationError, TelegramGateError, InputError, OSError, sqlite3.Error):
        # Remote exceptions, credentials, request details and file paths are never printed.
        print(json.dumps({"status": "UNKNOWN_OR_FAILED", "retry": "DO_NOT_AUTO_RETRY"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
