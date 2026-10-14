"""No-network incident preview formatting; never echo private incident data."""
from __future__ import annotations

import unittest
from ops_watch.core import INCIDENT_CODES, InputError
from ops_watch.incident_preview import TITLES, ACTIONS, render


class FixedNotificationPreviewTests(unittest.TestCase):
    def test_every_code_has_a_fixed_reviewed_title_and_action(self) -> None:
        self.assertEqual(set(TITLES), INCIDENT_CODES)
        self.assertEqual(set(ACTIONS), INCIDENT_CODES)

    def test_new_warning_is_rendered_with_fixed_text(self) -> None:
        current = [{"code": "outbox_backlog", "fingerprint": "ops:outbox_backlog",
                    "observed_value": 100, "body": "Bearer PRIVATE_VALUE"}]
        result = render({"raised": ["ops:outbox_backlog"], "resolved": []}, current)
        self.assertEqual(result[0]["title"], "Накопилась очередь новостей")
        self.assertEqual(result[0]["severity"], "warning")
        self.assertNotIn("PRIVATE_VALUE", str(result))
        self.assertNotIn("100", str(result))

    def test_recovery_is_not_sent_as_an_active_failure(self) -> None:
        result = render({"raised": [], "resolved": ["ops:timer_inactive"]}, [])
        self.assertEqual(result[0]["phase"], "resolved")
        self.assertEqual(result[0]["severity"], "resolved")

    def test_no_changes_means_no_preview(self) -> None:
        self.assertEqual(render({"raised": [], "resolved": []}, []), [])

    def test_unknown_fingerprint_is_denied(self) -> None:
        for code in ("ops:unknown", "ops:__proto__", "abc", 42, ["ops:timer_inactive"]):
            with self.subTest(code=code), self.assertRaises(InputError):
                render({"raised": [code], "resolved": []}, [])

    def test_transition_must_match_actual_active_state(self) -> None:
        with self.assertRaisesRegex(InputError, "transition_state_mismatch"):
            render({"raised": ["ops:timer_inactive"], "resolved": []}, [])
        with self.assertRaisesRegex(InputError, "transition_state_mismatch"):
            render({"raised": [], "resolved": ["ops:timer_inactive"]},
                   [{"code": "timer_inactive", "fingerprint": "ops:timer_inactive"}])

    def test_dual_open_and_resolved_transition_rejected(self) -> None:
        with self.assertRaises(InputError):
            render({"raised": ["ops:ci_failed"], "resolved": ["ops:ci_failed"]},
                   [{"code": "ci_failed", "fingerprint": "ops:ci_failed"}])

    def test_duplicate_transitions_rejected(self) -> None:
        with self.assertRaises(InputError):
            render({"raised": ["ops:ci_failed", "ops:ci_failed"], "resolved": []},
                   [{"code": "ci_failed", "fingerprint": "ops:ci_failed"}])

    def test_extra_keys_and_raw_output_never_pass(self) -> None:
        with self.assertRaises(InputError):
            render({"raised": [], "resolved": [], "token": "secret"}, [])

    def test_corrupted_current_findings_never_look_healthy(self) -> None:
        with self.assertRaises(InputError):
            render({"raised": [], "resolved": []},
                   [{"code": {"danger": True}, "fingerprint": "ops:none"}])

    def test_preview_never_contains_external_link_or_private_payload(self) -> None:
        current = [{"code": "ci_failed", "fingerprint": "ops:ci_failed",
                    "details": "https://private.example/?token=secret"}]
        result = render({"raised": ["ops:ci_failed"], "resolved": []}, current)
        self.assertNotIn("private.example", str(result))
        self.assertNotIn("secret", str(result))
        self.assertNotIn("https://", str(result))


if __name__ == "__main__":
    unittest.main()
