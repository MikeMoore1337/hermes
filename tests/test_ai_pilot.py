"""Offline tests for the bounded Hermes AI quality pilot."""
from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from ops_watch.incident_advisor import SCENARIOS, mock_result, prepare_context

from agent_budget.pilot import (
    PRIMARY_MODEL,
    CloudflareFreeProvider,
    ModelResponse,
    PilotError,
    case_names,
    load_account_status,
    run_pilot,
    status,
)


ACCOUNT_ID = "0123456789abcdef0123456789abcdef"
TOKEN = "synthetic-token-with-no-network"


def account_status(*, remaining: int = 9_000, gateway: bool = False) -> dict[str, object]:
    return {
        "schema": "hermes-cloudflare-account-status-v1",
        "plan": "WORKERS_FREE",
        "account_id_sha256": hashlib.sha256(ACCOUNT_ID.encode()).hexdigest(),
        "model": PRIMARY_MODEL,
        "daily_neurons_remaining": remaining,
        "ai_gateway_unified_billing": gateway,
        "checked_at": "2026-10-15T12:00:00Z",
    }


class _Response:
    status = 200

    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = json.dumps(payload).encode()

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.payload[:limit]


class _Opener:
    def __init__(self, response: object) -> None:
        self.response = response
        self.requests = []

    def open(self, request: object, *, timeout: int) -> object:
        self.requests.append((request, timeout))
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


class _NoCostProvider:
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, _: str) -> ModelResponse:
        self.calls += 1
        return ModelResponse(
            content=json.dumps(mock_result(prepare_context(SCENARIOS["provider_http_429"]))),
            http_status=200,
            attempts=1,
            duration_seconds=0.001,
        )


class PilotTests(unittest.TestCase):
    def test_status_is_closed_until_account_proof_and_owner_approval(self) -> None:
        current = status()
        self.assertEqual(current["account_status"], "ACCOUNT_FREE_UNVERIFIED")
        self.assertEqual(current["automatic_retries"], 0)
        self.assertFalse(current["automatic_fallback"])

    def test_case_catalog_has_twelve_ops_and_eight_research_cases(self) -> None:
        names = case_names()
        self.assertEqual(len(names), 20)
        self.assertEqual(len([name for name in names if name.startswith("ops:")]), 12)
        self.assertEqual(len([name for name in names if name.startswith("research:")]), 8)
        self.assertIn("ops:contradictory_state", names)
        self.assertIn("ops:unknown_error_code", names)
        self.assertIn("ops:prompt_injection", names)

    def test_mock_comparison_saves_no_live_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records = run_pilot(
                engine="mock",
                cases=["ops:provider_http_429", "research:whey_gut_brain"],
                output=Path(directory) / "results.json",
            )
            saved = json.loads((Path(directory) / "results.json").read_text(encoding="utf-8"))
        self.assertEqual([record["status"] for record in records], ["PASS", "PASS"])
        self.assertTrue(all(record["model_execution"] == "MOCK_ONLY" for record in records))
        self.assertTrue(all(record["model"] == "local-deterministic-mock" for record in records))
        self.assertEqual(len(saved), 2)

    def test_live_mode_denies_before_network_without_both_gates(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(PilotError, "live_owner_approval_required"):
                run_pilot(
                    engine="live",
                    cases=["ops:provider_http_429"],
                    account_status=Path(directory) / "status.json",
                )

    def test_account_status_rejects_paid_gateway_and_low_reserve(self) -> None:
        for payload in (
            account_status(gateway=True),
            account_status(remaining=999),
        ):
            with self.subTest(payload=payload):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "status.json"
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaises(PilotError):
                        load_account_status(path)

    def test_cloudflare_request_is_one_fixed_non_redirecting_call(self) -> None:
        opener = _Opener(_Response({
            "success": True,
            "choices": [{"message": {"content": "{}"}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7, "neurons": 19},
        }))
        provider = CloudflareFreeProvider(
            token=TOKEN,
            base_url=f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/ai/v1",
            account_status=account_status(),
            opener=opener,
        )
        result = provider.complete("проверка")
        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.provider_neurons, 19)
        self.assertEqual(len(opener.requests), 1)
        request = opener.requests[0][0]
        body = json.loads(request.data)
        self.assertEqual(body["model"], PRIMARY_MODEL)
        self.assertTrue(body["options"]["rejectIfBusy"])
        with self.assertRaisesRegex(PilotError, "model_call_limit_exceeded"):
            provider.complete("второй вызов")

    def test_cloudflare_429_stops_without_retry_or_body_leak(self) -> None:
        opener = _Opener(HTTPError(
            f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/ai/v1/chat/completions",
            429,
            "quota",
            {},
            io.BytesIO(b"Bearer secret-body"),
        ))
        provider = CloudflareFreeProvider(
            token=TOKEN,
            base_url=f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/ai/v1",
            account_status=account_status(),
            opener=opener,
        )
        with self.assertRaisesRegex(PilotError, "provider_http_429") as caught:
            provider.complete("проверка")
        self.assertEqual(len(opener.requests), 1)
        self.assertNotIn("secret-body", str(caught.exception))

    def test_live_success_without_observed_cost_is_blocked_without_next_call(self) -> None:
        fake = _NoCostProvider()
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"HERMES_AI_LIVE_APPROVED": "1"}, clear=True
        ), patch("agent_budget.pilot.CloudflareFreeProvider.from_environment", return_value=fake):
            account_path = Path(directory) / "status.json"
            account_path.write_text(json.dumps(account_status()), encoding="utf-8")
            records = run_pilot(
                engine="live",
                cases=["ops:provider_http_429", "research:whey_gut_brain"],
                owner_approved=True,
                account_status=account_path,
                output=Path(directory) / "results.json",
                state=Path(directory) / "state.json",
            )
        self.assertEqual(records[0]["status"], "BLOCKED")
        self.assertEqual(records[0]["reason"], "COST_NOT_VERIFIED")
        self.assertEqual(records[0]["validation_status"], "PASS")
        self.assertEqual(records[0]["model_execution"], "LIVE_OBSERVED_COST_NOT_VERIFIED")
        self.assertEqual(records[0]["model_result"]["status"], "active")
        self.assertTrue(records[0]["quality"]["deterministic_invariants"]["evidence_from_input"])
        self.assertEqual(fake.calls, 1)
        self.assertEqual(len(records), 1)


if __name__ == "__main__":
    unittest.main()
