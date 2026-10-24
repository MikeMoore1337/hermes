"""#455 observer transactional cutover selects new checkpoint, not legacy H454."""
import unittest
from unittest.mock import patch
from scripts import h455_brc_observer_cutover as operator

class ObserverCutoverTests(unittest.TestCase):
    def test_uses_new_checkpoint_and_reuses_existing_owner_operator(self):
        with patch.object(operator.gated, "main", return_value=0) as main:
            original = operator.gated.CHECKPOINT
            try:
                self.assertEqual(operator.main(["plan"]), 0)
                main.assert_called_once_with(["plan"])
                self.assertEqual(operator.gated.CHECKPOINT,
                                 "hermes-brc-relay-h455-rollback")
            finally:
                operator.gated.CHECKPOINT = original

    def test_changed_upstream_checkpoint_is_denied(self):
        original = operator.gated.CHECKPOINT
        try:
            operator.gated.CHECKPOINT = "foreign-container"
            with self.assertRaises(operator.gated.CutoverDenied):
                operator.main(["cutover", "--execute"])
        finally:
            operator.gated.CHECKPOINT = original

if __name__ == "__main__":
    unittest.main()
