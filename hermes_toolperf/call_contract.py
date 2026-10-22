"""Issue #480: isolated tool-call contract oracle. NOT a live MCP dispatcher.

All state and side effects exist only in memory. No filesystem, subprocess,
network, device, credential, or model interface is imported or called.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import PurePosixPath
import re

SCHEMA = 1
MAX_INPUT = 2048
MAX_OUTPUT = 128
MAX_STEPS = 4
MAX_DEPTH = 1
ENVELOPE = frozenset({
    "schema_version", "attempt_id", "tool_call_id", "approval_id",
    "idempotency_key", "deadline_epoch", "depth", "step", "device_id",
    "scope", "tool", "arguments",
})
TOOL_ARGUMENTS = {
    "mock.read_file": frozenset({"path"}),
    "mock.write_file": frozenset({"path", "content"}),
}
RESPONSE = frozenset({"schema_version", "tool_call_id", "status", "output"})
IDENT = re.compile(r"^(?:attempt|call|idem)-[a-z0-9-]{4,40}$")
PATH = re.compile(r"^docs/[a-zA-Z0-9_.-/]{1,64}$")


class ContractDenied(ValueError):
    """Only a fixed reason code, never an untrusted payload."""


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ContractDenied("DUPLICATE_JSON_KEY")
        obj[key] = value
    return obj


def _invalid_constant(_):
    raise ContractDenied("INVALID_NUMBER")


def decode(raw):
    """Reject encoding errors, duplicate keys, non-objects and large JSON."""
    if type(raw) is not str:
        raise ContractDenied("MALFORMED_JSON")
    try:
        if len(raw.encode("utf-8", errors="strict")) > MAX_INPUT:
            raise ContractDenied("INPUT_LIMIT")
        obj = json.loads(raw, object_pairs_hook=_unique_object,
                         parse_constant=_invalid_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ContractDenied("MALFORMED_JSON") from exc
    if type(obj) is not dict:
        raise ContractDenied("INVALID_ENVELOPE")
    return obj


def _valid_path(value):
    if type(value) is not str or not PATH.fullmatch(value):
        return False
    posix = PurePosixPath(value)
    return not posix.is_absolute() and all(
        segment not in ("", ".", "..") and not segment.startswith(".")
        for segment in value.split("/")
    )


def _id(value, prefix):
    return type(value) is str and bool(IDENT.fullmatch(value)) and value.startswith(prefix)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(",", ":")).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


class SyntheticSession:
    """A fixed read/write policy and trusted in-memory effect ledger."""

    def __init__(self, *, approval_expires_at=1700000200):
        self.device_id = "synthetic-device"
        self.scope = "workspace:docs"
        self.approval_id = "grant-owner-reviewed"
        self.approval_expires_at = approval_expires_at
        self.files = {"docs/note.txt": "old\n"}
        self.effects = []
        self.ledger = {}
        self.keys = set()
        self.uncertain_write = False
        self.calls = 0

    def dispatch(self, raw, *, now=1700000000, ack_lost=False,
                 cancelled=False):
        """One bounded attempt; a missing ACK can never trigger automatic replay."""
        self.calls += 1
        if self.calls > MAX_STEPS:
            return {"status": "DENIED", "reason": "STEP_BUDGET"}
        try:
            item = decode(raw)
            if set(item) != ENVELOPE:
                raise ContractDenied("UNKNOWN_ENVELOPE_FIELD")
            if type(item["schema_version"]) is not int or item["schema_version"] != SCHEMA:
                raise ContractDenied("UNSUPPORTED_SCHEMA")
            for field, prefix in (("attempt_id", "attempt-"),
                                  ("tool_call_id", "call-"),
                                  ("idempotency_key", "idem-")):
                if not _id(item[field], prefix):
                    raise ContractDenied("INVALID_ID")
            if type(item["deadline_epoch"]) not in (int, float) or (
                    not math.isfinite(item["deadline_epoch"]) or
                    not now <= item["deadline_epoch"] <= now + 300):
                raise ContractDenied("EXPIRED_DEADLINE")
            if (type(item["depth"]) is not int or item["depth"] < 0 or
                    item["depth"] > MAX_DEPTH):
                raise ContractDenied("DEPTH_LIMIT")
            if type(item["step"]) is not int or item["step"] != self.calls:
                raise ContractDenied("INVALID_STEP")
            if item["device_id"] != self.device_id or type(item["device_id"]) is not str:
                raise ContractDenied("DEVICE_SCOPE_DENIED")
            if item["scope"] != self.scope or type(item["scope"]) is not str:
                raise ContractDenied("DATA_SCOPE_DENIED")
            tool = item["tool"]
            if type(tool) is not str or tool not in TOOL_ARGUMENTS:
                raise ContractDenied("TOOL_NOT_ALLOWLISTED")
            args = item["arguments"]
            if type(args) is not dict or set(args) != TOOL_ARGUMENTS[tool]:
                raise ContractDenied("ARGUMENT_SCHEMA")
            if not _valid_path(args["path"]):
                raise ContractDenied("INVALID_PATH")
            if args["path"] not in self.files:
                raise ContractDenied("FILE_NOT_ALLOWLISTED")
            if tool == "mock.write_file":
                # Ambiguous effects require independent reconciliation. Changing
                # a call ID or key must not bypass an unresolved prior write.
                if self.uncertain_write:
                    raise ContractDenied("UNRESOLVED_WRITE_BLOCKS_DISPATCH")
                if (type(item["approval_id"]) is not str or
                        item["approval_id"] != self.approval_id or
                        not now < self.approval_expires_at):
                    raise ContractDenied("APPROVAL_DENIED")
                content = args["content"]
                if type(content) is not str:
                    raise ContractDenied("ARGUMENT_TYPE")
                try:
                    size = len(content.encode("utf-8", errors="strict"))
                except UnicodeError as exc:
                    raise ContractDenied("ARGUMENT_TYPE") from exc
                if size > MAX_OUTPUT:
                    raise ContractDenied("OUTPUT_LIMIT")
            elif item["approval_id"] is not None:
                raise ContractDenied("READ_APPROVAL_MUST_BE_NULL")

            key, call = item["idempotency_key"], item["tool_call_id"]
            if call in self.ledger:
                raise ContractDenied("DUPLICATE_TOOL_CALL")
            if key in self.keys:
                raise ContractDenied("DUPLICATE_IDEMPOTENCY")
            self.keys.add(key)
            if cancelled:
                self.ledger[call] = {"status": "CANCELLED", "output": ""}
                return {"status": "CANCELLED", "reason": "CANCELLED_BEFORE_EFFECT"}
            if tool == "mock.write_file":
                self.files[args["path"]] = args["content"]
                self.effects.append({"call": call, "path": args["path"],
                                     "digest": digest(args["content"])})
                output = "written"
            else:
                output = self.files[args["path"]]
                if len(output.encode("utf-8")) > MAX_OUTPUT:
                    self.ledger[call] = {"status": "DENIED", "output": ""}
                    raise ContractDenied("OUTPUT_LIMIT")
            if ack_lost:
                self.ledger[call] = {"status": "UNKNOWN", "output": ""}
                if tool == "mock.write_file":
                    self.uncertain_write = True
                return {"status": "UNKNOWN", "reason": "ACK_UNCERTAIN_NO_RETRY"}
            self.ledger[call] = {"status": "OK", "output": output}
            return {"status": "OK", "reason": "OK"}
        except ContractDenied as exc:
            return {"status": "DENIED", "reason": str(exc)}

    def verify_response(self, raw):
        """An untrusted response cannot manufacture a receipt or undo UNKNOWN."""
        item = decode(raw)
        if set(item) != RESPONSE or type(item["schema_version"]) is not int or (
                item["schema_version"] != SCHEMA):
            raise ContractDenied("RESPONSE_SCHEMA")
        if (type(item["tool_call_id"]) is not str or
                type(item["status"]) is not str or
                item["status"] != "ok" or
                type(item["output"]) is not str):
            raise ContractDenied("RESPONSE_TYPE")
        try:
            size = len(item["output"].encode("utf-8", errors="strict"))
        except UnicodeError as exc:
            raise ContractDenied("RESPONSE_TYPE") from exc
        if size > MAX_OUTPUT:
            raise ContractDenied("OUTPUT_LIMIT")
        recorded = self.ledger.get(item["tool_call_id"])
        if recorded is None or recorded["status"] != "OK":
            raise ContractDenied("RESPONSE_WITHOUT_TRUSTED_RECEIPT")
        if item["output"] != recorded["output"]:
            raise ContractDenied("RESPONSE_MISMATCH")
        return {"status": "VERIFIED"}


def fixture(*, tool="mock.write_file", step=1, **overrides):
    """Test-only fixed-value JSON envelope; not a production approval issuer."""
    value = {
        "schema_version": SCHEMA,
        "attempt_id": "attempt-test-0001",
        "tool_call_id": "call-test-0001",
        "approval_id": "grant-owner-reviewed" if tool == "mock.write_file" else None,
        "idempotency_key": "idem-test-0001",
        "deadline_epoch": 1700000040,
        "depth": 0, "step": step,
        "device_id": "synthetic-device",
        "scope": "workspace:docs",
        "tool": tool,
        "arguments": ({"path": "docs/note.txt", "content": "new\n"}
                      if tool == "mock.write_file" else {"path": "docs/note.txt"}),
    }
    value.update(overrides)
    return value
