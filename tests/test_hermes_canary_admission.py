"""Offline read-only operator-preflight contracts, no inference/side effects."""
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import socket
import subprocess
import unittest
from unittest.mock import patch

from hermes_benchmark import canary, canary_admission
from hermes_benchmark.core import canonical, digest

NOW = datetime(2026, 10, 18, 8, 0, tzinfo=timezone.utc)
OWNER = b"synthetic-owner-independent-key-at-least-32-bytes"
OBSERVER = b"synthetic-independent-observer-key-more-than-32-bytes"


def signed(payload, key):
    return {"payload": payload,
            "signature": hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()}


def fixtures():
    a = {
        "schema": canary.SCHEMA,
        "run_id": "a" * 32,
        "approval_id": "explicit-owner-01",
        "case_id": "quota-denial",
        "fixture_hash": digest(canary.CASES["quota-denial"]),
        "hermes_sha": "b" * 40,
        "provider": canary.PROVIDER,
        "model": canary.MODEL,
        "effort": None,
        "scope": "read_only",
        "allowed_tools": [],
        "max_calls": 1,
        "max_total_tokens": 128,
        "max_cost_usd": "0.00",
        "issued_at": (NOW - timedelta(minutes=2)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=20)).isoformat(),
    }
    w = {
        "schema": canary_admission.PREFLIGHT_SCHEMA,
        "source": canary_admission.SOURCE,
        "run_id": a["run_id"],
        "hermes_sha": a["hermes_sha"],
        "case_id": a["case_id"],
        "captured_at": NOW.isoformat(),
        "account_plan": "workers-free",
        "model": a["model"],
        "remaining_neurons": 9000,
        "h01_burnin_active": False,
        "os_isolation_checked": True,
        "egress_guard_checked": True,
        "free_only_no_fallback": True,
        "host_capacity_checked": True,
    }
    return a, w


def assess(a=None, w=None, *, now=NOW):
    origin_a, origin_w = fixtures()
    return canary_admission.assess(
        signed(origin_a if a is None else a, OWNER),
        signed(origin_w if w is None else w, OBSERVER),
        owner_key=OWNER, observer_key=OBSERVER, now=now)


class CanaryAdmissionTests(unittest.TestCase):
    def test_ready_is_review_only_never_dispatch_permission(self):
        result = assess()
        self.assertEqual(result["status"], "ready_for_operator_review")
        self.assertEqual(result["reason_code"], "EXTERNAL_LIVE_GO_REQUIRED")
        self.assertIs(result["dispatch_authorized"], False)

    def test_h01_burnin_is_hard_block(self):
        a, w = fixtures()
        w["h01_burnin_active"] = True
        self.assertEqual(assess(a, w)["reason_code"], "H01_BURNIN_ACTIVE_OR_UNKNOWN")
        w["h01_burnin_active"] = None
        self.assertEqual(assess(a, w)["reason_code"], "H01_BURNIN_ACTIVE_OR_UNKNOWN")

    def test_stale_or_future_quota_attestation_blocks(self):
        a, w = fixtures()
        w["captured_at"] = (NOW - timedelta(minutes=6)).isoformat()
        self.assertEqual(assess(a, w)["reason_code"], "PREFLIGHT_STALE")
        w["captured_at"] = (NOW + timedelta(minutes=1)).isoformat()
        self.assertEqual(assess(a, w)["reason_code"], "PREFLIGHT_STALE")

    def test_plan_changed_or_neurons_unknown_blocks(self):
        a, w = fixtures()
        w["account_plan"] = "workers-paid"
        self.assertEqual(assess(a, w)["reason_code"], "PLAN_NOT_FREE")
        w["account_plan"] = "workers-free"
        w["remaining_neurons"] = None
        self.assertEqual(assess(a, w)["reason_code"], "QUOTA_NOT_MEASURED")
        w["remaining_neurons"] = 500
        self.assertEqual(assess(a, w)["reason_code"], "QUOTA_HEADROOM_LOW")
        w["remaining_neurons"] = True
        self.assertEqual(assess(a, w)["reason_code"], "QUOTA_NOT_MEASURED")

    def test_runtime_guards_checked_individually(self):
        for field in ("os_isolation_checked", "egress_guard_checked",
                      "free_only_no_fallback", "host_capacity_checked"):
            with self.subTest(field=field):
                a, w = fixtures()
                w[field] = False
                self.assertEqual(assess(a, w)["reason_code"],
                                 "RUNTIME_GUARD_UNVERIFIED")

    def test_mismatch_run_sha_case_model_blocks(self):
        for field in ("run_id", "hermes_sha", "case_id", "model"):
            with self.subTest(field=field):
                a, w = fixtures()
                w[field] = "different"
                self.assertEqual(assess(a, w)["reason_code"],
                                 "PREFLIGHT_IDENTITY_MISMATCH")

    def test_expired_approval_blocks(self):
        a, w = fixtures()
        self.assertEqual(assess(a, w, now=NOW + timedelta(hours=1))["reason_code"],
                         "APPROVAL_EXPIRED")

    def test_tampered_signature_does_not_grant_readiness(self):
        a, w = fixtures()
        witness = signed(w, OBSERVER)
        witness["payload"]["remaining_neurons"] = 9999
        r = canary_admission.assess(signed(a, OWNER), witness,
                                    owner_key=OWNER, observer_key=OBSERVER,
                                    now=NOW)
        self.assertEqual(r["reason_code"], "PREFLIGHT_SIGNATURE_INVALID")

    def test_refuses_unsigned_or_malformed_inputs(self):
        a, w = fixtures()
        r = canary_admission.assess(signed(a, OWNER),
                                    {"payload": {"oops": "bad"}, "signature": "x"},
                                    owner_key=OWNER, observer_key=OBSERVER,
                                    now=NOW)
        self.assertEqual(r["status"], "unverified")
        self.assertIs(r["dispatch_authorized"], False)

    def test_cli_never_returns_shell_success_on_only_attested_readiness(self):
        a, w = fixtures()
        from io import StringIO
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for filename, payload in (("approval.json", signed(a, OWNER)),
                                      ("preflight.json", signed(w, OBSERVER))):
                (root / filename).write_text(json.dumps(payload))
            for filename, key in (("owner.key", OWNER), ("observer.key", OBSERVER)):
                target = root / filename
                target.write_bytes(key)
                target.chmod(0o600)
            args = [
                "--approval", str(root / "approval.json"),
                "--preflight", str(root / "preflight.json"),
                "--owner-key-file", str(root / "owner.key"),
                "--observer-key-file", str(root / "observer.key"),
            ]
            with patch("hermes_benchmark.canary_admission.datetime") as clock:
                clock.now.return_value = NOW
                with patch("sys.stdout", new_callable=StringIO) as output:
                    exit_code = canary_admission.main(args)
            self.assertNotEqual(exit_code, 0)
            self.assertEqual(json.loads(output.getvalue())["dispatch_authorized"], False)

    def test_no_network_and_no_subprocess_even_when_ready(self):
        with patch.object(socket.socket, "connect",
                          side_effect=AssertionError("network called")), \
             patch.object(subprocess, "Popen",
                          side_effect=AssertionError("process called")):
            self.assertEqual(assess()["status"], "ready_for_operator_review")


if __name__ == "__main__":
    unittest.main()
