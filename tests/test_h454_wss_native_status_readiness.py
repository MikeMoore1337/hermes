"""#454: bounded TLS sidecar startup readiness without masking security drift.

Pure Python tests only; no Docker, WSS service, host network or keys accessed.
"""
from __future__ import annotations

import ssl
import unittest
from unittest import mock

from scripts import h454_wss_native_status_sidecar_cutover as tx


class StartedWssReadinessTests(unittest.TestCase):
    def setUp(self):
        self.wss = mock.Mock(name="synthetic-wss")
        self.pins = {"relay_id": "a" * 64}
        self.relay_id = "a" * 64

    def test_transient_connection_refused_and_reset_then_verified(self):
        failures = [
            ConnectionRefusedError("socket not yet bound"),
            ConnectionResetError("service still starting"),
            None,
        ]
        with mock.patch.object(tx, "verify_live", side_effect=failures) as verify, \
             mock.patch.object(tx.time, "monotonic",
                               side_effect=[0.0, 0.1, 0.2]) as clock, \
             mock.patch.object(tx.time, "sleep") as sleep:
            tx.verify_started_sidecar(self.wss, self.pins, self.relay_id)
        self.assertEqual(verify.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(sleep.call_args_list, [
            mock.call(0.5), mock.call(0.5),
        ])
        verify.assert_called_with(self.wss, self.pins, self.relay_id, status=True)
        self.assertEqual(clock.call_count, 3)

    def test_unresponsive_started_service_fails_after_bounded_deadline(self):
        with mock.patch.object(tx, "verify_live",
                               side_effect=ConnectionRefusedError("not bound")) as verify, \
             mock.patch.object(tx.time, "monotonic", side_effect=[0.0, 12.001]), \
             mock.patch.object(tx.time, "sleep") as sleep:
            with self.assertRaisesRegex(tx.Refused, "^NEW_WSS_READINESS_TIMEOUT$"):
                tx.verify_started_sidecar(self.wss, self.pins, self.relay_id)
        verify.assert_called_once()
        sleep.assert_not_called()

    def test_short_remaining_time_never_sleeps_past_deadline(self):
        with mock.patch.object(tx, "verify_live", side_effect=[
            TimeoutError("temporary TCP timeout"), None,
        ]), mock.patch.object(tx.time, "monotonic",
                              side_effect=[0.0, 11.9]), \
             mock.patch.object(tx.time, "sleep") as sleep:
            tx.verify_started_sidecar(self.wss, self.pins, self.relay_id)
        self.assertEqual(sleep.call_count, 1)
        self.assertGreater(sleep.call_args.args[0], 0)
        self.assertLess(sleep.call_args.args[0], 0.5)

    def test_tls_identity_and_certificate_failures_not_retried(self):
        for failure in (
            ssl.SSLCertVerificationError("certificate mismatch"),
            tx.Refused("SIDECAR_PROFILE_CHANGED"),
            tx.Refused("PRIVATE_STATUS_NOT_DENIED"),
            PermissionError("untrusted mount"),
            ValueError("unexpected response"),
        ):
            with self.subTest(type=type(failure).__name__), \
                 mock.patch.object(tx, "verify_live", side_effect=failure) as verify, \
                 mock.patch.object(tx.time, "monotonic", return_value=0.0), \
                 mock.patch.object(tx.time, "sleep") as sleep:
                with self.assertRaises(type(failure)):
                    tx.verify_started_sidecar(self.wss, self.pins, self.relay_id)
                verify.assert_called_once()
                sleep.assert_not_called()

    def test_readiness_retry_never_writes_or_starts_another_container(self):
        with mock.patch.object(tx, "verify_live", return_value=None), \
             mock.patch.object(tx.stage1, "docker") as docker, \
             mock.patch.object(tx.stage1, "replace_pins") as replace_pins, \
             mock.patch.object(tx, "replace_proxy") as replace_proxy:
            tx.verify_started_sidecar(self.wss, self.pins, self.relay_id)
        docker.assert_not_called()
        replace_pins.assert_not_called()
        replace_proxy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
