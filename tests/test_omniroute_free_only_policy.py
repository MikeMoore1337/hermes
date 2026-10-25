"""#572: synthetic no-billing admission oracle for OmniRoute evaluation ONLY.

Not an inference router, gateway, quota monitor, billing attestation, or
production guard. No requests, files, credentials, model calls, or imports.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import unittest


@dataclass(frozen=True)
class Hop:
    provider: str = "synthetic-free-provider"
    model: str = "synthetic-free-model"
    egress: str = "free.invalid"
    free_account_attested: bool = True
    nonbillable_route_proven: bool = True
    quota_remaining: int | None = 5
    quota_age_seconds: int | None = 30
    retry_count: int = 0


APPROVED = {("synthetic-free-provider", "synthetic-free-model", "free.invalid")}
def offline_admission(
    hops: tuple[Hop, ...],
    *,
    http_codes: tuple[int, ...] = (),
    trace_fields: tuple[str, ...] = (),
    payload_is_synthetic: bool = True,
) -> str:
    """Return a fixture verdict, never permission to execute a real request."""
    if type(payload_is_synthetic) is not bool or not payload_is_synthetic:
        return "DENY"
    if not hops or len(hops) > 4:
        return "DENY"
    if any(type(code) is not int or code not in (200, 201, 204)
           for code in http_codes):
        return "DENY"
    if any(key.lower() in {"authorization", "cookie", "api_key",
                           "token", "prompt", "body", "raw_chat"}
           for key in trace_fields):
        return "DENY"
    identities = set()
    for hop in hops:
        if type(hop) is not Hop:
            return "DENY"
        identity = (hop.provider, hop.model, hop.egress)
        if identity not in APPROVED or identity in identities:
            return "DENY"
        identities.add(identity)
        if (hop.free_account_attested is not True
                or hop.nonbillable_route_proven is not True
                or type(hop.quota_remaining) is not int
                or hop.quota_remaining <= 0
                or type(hop.quota_age_seconds) is not int
                or not 0 <= hop.quota_age_seconds <= 300
                or type(hop.retry_count) is not int
                or hop.retry_count != 0):
            return "DENY"
    return "SYNTHETIC_ORACLE_ACCEPTS_SHAPE_ONLY"


class OmniRouteOfflinePolicyMatrix(unittest.TestCase):
    """All inputs below are fictional; no provider identities or URLs are live."""

    def setUp(self):
        self.ok = Hop()

    def test_synthetic_allowlist_baseline_is_not_live_approval(self):
        self.assertEqual(
            offline_admission((self.ok,)),
            "SYNTHETIC_ORACLE_ACCEPTS_SHAPE_ONLY",
        )

    def test_unknown_or_spoofed_provider_and_model_denied(self):
        for mutation in (
            {"provider": "unapproved"},
            {"provider": "Synthetic-Free-Provider"},
            {"model": "synthetic-paid-model"},
            {"egress": "unexpected.invalid"},
        ):
            with self.subTest(mutation=mutation):
                self.assertEqual(offline_admission((replace(self.ok, **mutation),)), "DENY")

    def test_unverified_free_or_billing_denied(self):
        for mutation in (
            {"free_account_attested": False},
            {"free_account_attested": None},
            {"nonbillable_route_proven": False},
            {"nonbillable_route_proven": None},
        ):
            with self.subTest(mutation=mutation):
                self.assertEqual(offline_admission((replace(self.ok, **mutation),)), "DENY")

    def test_quota_exhaustion_unknown_stale_or_invalid_denied(self):
        for mutation in (
            {"quota_remaining": 0},
            {"quota_remaining": -1},
            {"quota_remaining": None},
            {"quota_remaining": True},
            {"quota_age_seconds": 301},
            {"quota_age_seconds": -1},
            {"quota_age_seconds": None},
            {"quota_age_seconds": False},
        ):
            with self.subTest(mutation=mutation):
                self.assertEqual(offline_admission((replace(self.ok, **mutation),)), "DENY")

    def test_auth_billing_rate_limit_and_server_errors_denied(self):
        for code in (401, 402, 403, 429, 500, 502, 503):
            with self.subTest(code=code):
                self.assertEqual(offline_admission((self.ok,), http_codes=(code,)), "DENY")

    def test_no_retries_after_rejections(self):
        for count in (1, 2, -1, None, True):
            with self.subTest(count=count):
                self.assertEqual(offline_admission((replace(self.ok, retry_count=count),)), "DENY")

    def test_paid_fallback_and_unknown_hop_denied_even_when_not_selected(self):
        paid = replace(self.ok, provider="paid", nonbillable_route_proven=False)
        unknown = replace(self.ok, provider="unverified")
        self.assertEqual(offline_admission((self.ok, paid)), "DENY")
        self.assertEqual(offline_admission((self.ok, unknown)), "DENY")

    def test_fallback_cycles_and_unbounded_hops_denied(self):
        self.assertEqual(offline_admission((self.ok, self.ok)), "DENY")
        self.assertEqual(offline_admission((self.ok,) * 5), "DENY")
        self.assertEqual(offline_admission(()), "DENY")

    def test_suspicious_trace_fields_and_real_payload_denied(self):
        for key in ("Authorization", "cookie", "API_KEY", "token", "prompt", "raw_chat"):
            with self.subTest(key=key):
                self.assertEqual(offline_admission((self.ok,), trace_fields=(key,)), "DENY")
        self.assertEqual(offline_admission((self.ok,), payload_is_synthetic=False), "DENY")

    def test_bad_http_and_untyped_inputs_denied(self):
        for code in (0, 199, 300, 400, 418, True, "200"):
            with self.subTest(code=code):
                self.assertEqual(offline_admission((self.ok,), http_codes=(code,)), "DENY")
        self.assertEqual(offline_admission((self.ok,), payload_is_synthetic=None), "DENY")

    def test_results_do_not_echo_secrets_or_create_side_effects(self):
        result = offline_admission((self.ok,), trace_fields=("token",))
        self.assertEqual(result, "DENY")
        self.assertNotIn("token", result.lower())


if __name__ == "__main__":
    unittest.main()
