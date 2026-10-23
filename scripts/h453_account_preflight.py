"""Local H-453 Workers Free account attestation; zero network, zero inference.

Operator must enter current dashboard facts. Values are owner-attested, not
an independent Cloudflare Billing API proof. Never print the token or ID.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from urllib.parse import urlsplit

from agent_budget.pilot import (
    ACCOUNT_STATUS_SCHEMA, PRIMARY_MODEL, PilotError,
    load_account_status, validate_account_status,
)
from scripts.cloudflare_text_probe import ProbeError, read_env


def prepare(*, remaining: int, workers_free: bool, no_gateways: bool,
            output: Path, write: bool = False) -> dict[str, object]:
    if not workers_free or not no_gateways:
        raise PilotError("owner_dashboard_confirmation_required")
    if type(remaining) is not int:
        raise PilotError("account_quota_invalid")
    # Reuse existing strict .env parser: no shell source, no network access.
    token, endpoint = read_env()
    del token
    account_id = urlsplit(endpoint).path.split("/")[4].lower()
    proof = {
        "schema": ACCOUNT_STATUS_SCHEMA,
        "plan": "WORKERS_FREE",
        "account_id_sha256": hashlib.sha256(account_id.encode("ascii")).hexdigest(),
        "model": PRIMARY_MODEL,
        "daily_neurons_remaining": remaining,
        "ai_gateway_unified_billing": False,
        "checked_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    validate_account_status(proof)
    if not write:
        return {"status": "PREFLIGHT_PASS", "wrote_file": False,
                "source": "OWNER_DASHBOARD_NOT_API_ATTESTED"}
    if output.is_symlink() or output.exists():
        raise PilotError("preflight_output_exists")
    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise PilotError("preflight_unsafe_directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(output, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(proof, stream, ensure_ascii=False, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        # Self-check exact file through the normal live pilot admission gate.
        load_account_status(output)
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return {"status": "OWNER_ACCOUNT_STATUS_READY", "wrote_file": True,
            "source": "OWNER_DASHBOARD_NOT_API_ATTESTED"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="H-453 free-only local admission; no inference")
    parser.add_argument("--remaining-neurons", required=True, type=int)
    parser.add_argument("--confirm-workers-free", action="store_true")
    parser.add_argument("--confirm-no-ai-gateways", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = prepare(
            remaining=args.remaining_neurons,
            workers_free=args.confirm_workers_free,
            no_gateways=args.confirm_no_ai_gateways,
            output=args.output,
            write=args.write,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (PilotError, ProbeError, OSError, ValueError) as exc:
        # Known validation errors are sanitized; do not print secret context.
        print(json.dumps({"status": "DENIED", "reason": type(exc).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
