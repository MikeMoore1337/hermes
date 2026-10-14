"""Opt-in owner-only Telegram transport for local Ops Watch incident receipts.

Not deployed or scheduled. No credentials in source. It can send at most ONE
event per explicit --execute invocation, after strict owner-chat preflight.
A Telegram message_id confirms Telegram API acceptance, NOT user's reading.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from .core import InputError
from .delivery_contract import claim_one, confirm_one, stats

HOST = "api.telegram.org"
TOKEN = re.compile(r"^[0-9]{6,12}:[A-Za-z0-9_-]{30,80}$")
MAX_BODY_BYTES = 32768
TARGET = Path("/var/lib/hermes-agent/ops-watch")


class TelegramGateError(ValueError):
    """Constant error category; never include token, recipient, URL or body."""


def _credentials(token: Any, chat: Any) -> tuple[str, int]:
    if type(token) is not str or TOKEN.fullmatch(token) is None:
        raise TelegramGateError("telegram_token_missing_or_invalid")
    if type(chat) is not str or not re.fullmatch(r"[1-9][0-9]{4,15}", chat):
        raise TelegramGateError("telegram_owner_chat_missing_or_invalid")
    # Require a POSITIVE private user chat; never group, channel or username.
    chat_id = int(chat)
    if chat_id > 2**63 - 1:
        raise TelegramGateError("telegram_owner_chat_missing_or_invalid")
    return token, chat_id


def _resolve() -> str:
    try:
        records = socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise TelegramGateError("telegram_dns_unavailable") from exc
    addresses = {answer[4][0] for answer in records
                 if answer[0] in (socket.AF_INET, socket.AF_INET6)}
    if not addresses:
        raise TelegramGateError("telegram_dns_unavailable")
    try:
        parsed = [ipaddress.ip_address(ip) for ip in addresses]
    except ValueError as exc:
        raise TelegramGateError("telegram_dns_invalid") from exc
    if not all(ip.is_global for ip in parsed):
        raise TelegramGateError("telegram_private_dns_denied")
    ipv4 = [ip for ip in parsed if ip.version == 4]
    return str(sorted(ipv4 or parsed, key=int)[0])


class _PinnedTelegram(http.client.HTTPSConnection):
    def __init__(self, address: str):
        super().__init__(HOST, port=443, timeout=8, context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=HOST)
        except BaseException:
            raw.close()
            raise


def _message(event: dict[str, Any]) -> str:
    if not isinstance(event, dict):
        raise TelegramGateError("telegram_event_invalid")
    event_id = event.get("event_id")
    if type(event_id) is not int or event_id <= 0:
        raise TelegramGateError("telegram_event_invalid")
    title = event.get("title")
    action = event.get("action")
    if (type(title) is not str or type(action) is not str
            or len(title) > 200 or len(action) > 250):
        raise TelegramGateError("telegram_event_invalid")
    # The canonical delivery claim already validates title/action against
    # the fixed incident catalog. Never append arbitrary external content.
    message = f"Hermes Ops Watch\n{title}\n{action}\nСобытие #{event_id}"
    if not 1 <= len(message) <= 4096:
        raise TelegramGateError("telegram_message_invalid")
    return message


def _unique_telegram_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate keys at any depth, rather than accepting last value."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TelegramGateError("telegram_duplicate_json_key")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> Any:
    raise TelegramGateError("telegram_nonfinite_json")


def post_once(
    *, token: str, chat_id: int, text: str,
    connect: Callable[[str], Any] = _PinnedTelegram,
) -> int:
    """One POST, one bounded response, no retry/redirect/payment flags."""
    if (type(chat_id) is not int or chat_id <= 0
            or type(token) is not str or TOKEN.fullmatch(token) is None
            or type(text) is not str or not 1 <= len(text) <= 4096):
        raise TelegramGateError("telegram_post_invalid")
    address = _resolve()
    client = connect(address)
    body = json.dumps({"chat_id": chat_id, "text": text},
                      ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    try:
        client.request(
            "POST", f"/bot{token}/sendMessage", body=body,
            headers={
                "Host": HOST, "Content-Type": "application/json",
                "Accept": "application/json", "Accept-Encoding": "identity",
                "Content-Length": str(len(body)), "Connection": "close",
            },
        )
        reply = client.getresponse()
        if reply.status != 200:
            raise TelegramGateError("telegram_api_refused")
        if reply.getheader("Content-Encoding", "identity").lower() != "identity":
            raise TelegramGateError("telegram_compressed_response")
        media = reply.getheader("Content-Type", "").lower()
        if not media.startswith("application/json"):
            raise TelegramGateError("telegram_response_content_invalid")
        declared = reply.getheader("Content-Length")
        if declared is not None and (
            not declared.isascii() or not declared.isdigit()
            or int(declared) > MAX_BODY_BYTES
        ):
            raise TelegramGateError("telegram_response_oversize")
        raw = reply.read(MAX_BODY_BYTES + 1)
        if len(raw) > MAX_BODY_BYTES:
            raise TelegramGateError("telegram_response_oversize")
        try:
            result = json.loads(
                raw, object_pairs_hook=_unique_telegram_object,
                parse_constant=_invalid_constant,
            )
        except TelegramGateError:
            raise
        except (ValueError, UnicodeError) as exc:
            raise TelegramGateError("telegram_response_invalid") from exc
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise TelegramGateError("telegram_api_refused")
        sent = result.get("result")
        if not isinstance(sent, dict) or type(sent.get("message_id")) is not int:
            raise TelegramGateError("telegram_receipt_missing")
        target = sent.get("chat")
        if (not isinstance(target, dict) or type(target.get("id")) is not int
                or target["id"] != chat_id or target.get("type") != "private"
                or sent["message_id"] <= 0):
            raise TelegramGateError("telegram_receipt_mismatch")
        return sent["message_id"]
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        raise TelegramGateError("telegram_network_or_tls_failure") from exc
    finally:
        client.close()


def send_one(
    directory: Path, *, token: str, chat: str, now: datetime,
    transport: Callable[..., int] = post_once,
) -> dict[str, Any]:
    """Send one owner alert; persist ACK only on a validated API message ID."""
    token, chat_id = _credentials(token, chat)
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise TelegramGateError("telegram_clock_invalid")
    event = claim_one(directory, now=now)
    if event is None:
        if stats(directory)["exhausted"]:
            raise TelegramGateError("telegram_delivery_exhausted")
        return {"status": "EMPTY_OR_LEASED"}
    receipt = transport(token=token, chat_id=chat_id, text=_message(event))
    confirm_one(
        directory, event_id=event["event_id"], lease_token=event["lease_token"],
        telegram_message_id=receipt, now=datetime.now(UTC),
    )
    return {"status": "ACCEPTED_BY_TELEGRAM", "event_id": event["event_id"]}


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true",
                        help="Explicitly send at most one event with separate credentials")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if not args.execute:
            result = {"status": "DRY_RUN_ONLY", "queue": stats(TARGET)}
        else:
            result = send_one(
                TARGET, token=os.environ.get("HERMES_ALERT_BOT_TOKEN", ""),
                chat=os.environ.get("HERMES_ALERT_PRIVATE_CHAT_ID", ""),
                now=datetime.now(UTC),
            )
    except (TelegramGateError, InputError) as exc:
        result = {"status": "REJECTED", "reason": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in ("DRY_RUN_ONLY", "EMPTY_OR_LEASED",
                                    "ACCEPTED_BY_TELEGRAM") else 2


if __name__ == "__main__":
    raise SystemExit(main())
