"""Fail-closed, offline canary admission assessment. Never performs model calls.

The independently signed assessment is a prerequisite for *operator review*,
not permission to dispatch. Only a separate constrained runner with actual
pre-dispatch quota and process/egress enforcement could start a real call.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import argparse
import json
from typing import Any

from .canary import (
    MODEL, PROVIDER, SCHEMA, _approval_valid, _auth, _private_key, _read_json,
    _result, _timestamp,
)

PREFLIGHT_SCHEMA = "hermes-canary-preflight-v1"
SOURCE = "trusted-local-readonly-preflight"
MAX_QUOTA_AGE_SECONDS = 300
MIN_NEURONS_HEADROOM = 1000


def assess(approval: Any, preflight: Any, *, owner_key: bytes,
           observer_key: bytes, now: datetime) -> dict[str, Any]:
    """Return readiness for human review only; READY never authorizes live inference."""
    if (type(owner_key) is not bytes or type(observer_key) is not bytes or
            len(owner_key) < 32 or len(observer_key) < 32 or
            owner_key == observer_key):
        return {"status": "unverified", "reason_code": "KEY_SEPARATION_REQUIRED",
                "dispatch_authorized": False}
    if type(now) is not datetime or now.tzinfo is None:
        return {"status": "unverified", "reason_code": "CLOCK_UNVERIFIED",
                "dispatch_authorized": False}

    def outcome(state: str, reason: str) -> dict[str, Any]:
        return {"status": state, "reason_code": reason, "dispatch_authorized": False,
                "verification_kind": "attested_offline_operator_preflight"}

    owner = _auth(approval, owner_key)
    if owner is None:
        return outcome("unverified", "APPROVAL_SIGNATURE_INVALID")
    error = _approval_valid(owner, now.astimezone(timezone.utc))
    if error:
        return outcome("blocked", error)
    witness = _auth(preflight, observer_key)
    if witness is None:
        return outcome("unverified", "PREFLIGHT_SIGNATURE_INVALID")
    if type(witness) is not dict or set(witness) != {
        "schema", "source", "run_id", "hermes_sha", "case_id",
        "captured_at", "account_plan", "model", "remaining_neurons",
        "h01_burnin_active", "os_isolation_checked", "egress_guard_checked",
        "free_only_no_fallback", "host_capacity_checked",
    } or witness.get("schema") != PREFLIGHT_SCHEMA or witness.get("source") != SOURCE:
        return outcome("unverified", "PREFLIGHT_SCHEMA_INVALID")
    if (witness.get("run_id") != owner["run_id"] or
            witness.get("hermes_sha") != owner["hermes_sha"] or
            witness.get("case_id") != owner["case_id"] or
            witness.get("model") != owner["model"] or
            owner["provider"] != PROVIDER or owner["model"] != MODEL):
        return outcome("blocked", "PREFLIGHT_IDENTITY_MISMATCH")
    moment = _timestamp(witness.get("captured_at"))
    if moment is None:
        return outcome("unverified", "PREFLIGHT_TIMESTAMP_INVALID")
    age = (now.astimezone(timezone.utc) - moment).total_seconds()
    if not 0 <= age <= MAX_QUOTA_AGE_SECONDS:
        return outcome("blocked", "PREFLIGHT_STALE")
    if witness.get("account_plan") != "workers-free":
        return outcome("blocked", "PLAN_NOT_FREE")
    remaining = witness.get("remaining_neurons")
    if type(remaining) is not int or not 0 <= remaining <= 10000:
        return outcome("unverified", "QUOTA_NOT_MEASURED")
    # A conservative availability hint, NOT a provider-enforced neutron cost cap.
    if remaining < MIN_NEURONS_HEADROOM:
        return outcome("blocked", "QUOTA_HEADROOM_LOW")
    if witness.get("h01_burnin_active") is not False:
        return outcome("blocked", "H01_BURNIN_ACTIVE_OR_UNKNOWN")
    for field in ("os_isolation_checked", "egress_guard_checked",
                  "free_only_no_fallback", "host_capacity_checked"):
        if witness.get(field) is not True:
            return outcome("blocked", "RUNTIME_GUARD_UNVERIFIED")
    return outcome("ready_for_operator_review", "EXTERNAL_LIVE_GO_REQUIRED")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify signed preflight; NEVER dispatch AI or authorize live models.")
    parser.add_argument("--approval", required=True, type=Path)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--owner-key-file", required=True, type=Path)
    parser.add_argument("--observer-key-file", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = assess(_read_json(args.approval), _read_json(args.preflight),
                        owner_key=_private_key(args.owner_key_file),
                        observer_key=_private_key(args.observer_key_file),
                        now=datetime.now(timezone.utc))
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        result = {"status": "unverified", "reason_code": "INPUT_UNAVAILABLE",
                  "dispatch_authorized": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "ready_for_operator_review" else 1


if __name__ == "__main__":
    raise SystemExit(main())
