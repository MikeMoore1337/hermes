"""Regression: corrective H455 cutover never reuses prior live rollback slots."""
import unittest
from unittest.mock import patch
from scripts import h455_brc_observer_refresh_cutover as operator

class CorrectiveCutoverTests(unittest.TestCase):
    def test_new_checkpoint_uses_same_owner_operator(self):
        original = operator.gated.CHECKPOINT
        try:
            with patch.object(operator.gated, "main", return_value=0) as main:
                self.assertEqual(operator.main(["plan"]), 0)
                main.assert_called_once_with(["plan"])
                self.assertEqual(operator.gated.CHECKPOINT,
                    "hermes-brc-relay-h455-refresh-rollback")
        finally:
            operator.gated.CHECKPOINT = original

    def test_upstream_checkpoint_drift_denied(self):
        original = operator.gated.CHECKPOINT
        try:
            operator.gated.CHECKPOINT = "foreign-checkpoint"
            with self.assertRaises(operator.gated.CutoverDenied):
                operator.main(["cutover", "--execute"])
        finally:
            operator.gated.CHECKPOINT = original

if __name__ == "__main__":
    unittest.main()
