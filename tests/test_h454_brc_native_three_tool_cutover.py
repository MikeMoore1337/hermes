"""H454 native-three-tool owner cutover wrapper: no real Docker/host actions."""
import unittest
from unittest.mock import patch

from scripts import h454_brc_native_three_tool_cutover as operator


class ThreeToolCutoverTests(unittest.TestCase):
    def test_checkpoint_is_unique_and_preserves_prior_history(self):
        self.assertEqual(operator.CHECKPOINT, "hermes-brc-relay-h454-native3-rollback")
        self.assertNotIn(operator.CHECKPOINT, {
            "hermes-brc-relay-h454-rollback",
            "hermes-brc-relay-h455-rollback",
            "hermes-brc-relay-h455-refresh-rollback",
        })

    def test_owner_operator_receives_same_arguments_with_new_checkpoint(self):
        with patch.object(operator.gated, "CHECKPOINT", "hermes-brc-relay-h454-rollback"):
            with patch.object(operator.gated, "main", return_value=0) as downstream:
                args = ["plan", "--bundle-dir", "/bounded/ci-artifact"]
                self.assertEqual(operator.main(args), 0)
                self.assertEqual(operator.gated.CHECKPOINT, operator.CHECKPOINT)
                downstream.assert_called_once_with(args)

    def test_other_checkpoint_is_never_overwritten(self):
        with patch.object(operator.gated, "CHECKPOINT", "hermes-brc-relay-h455-refresh-rollback"):
            with patch.object(operator.gated, "main") as downstream:
                with self.assertRaisesRegex(
                    operator.gated.CutoverDenied, "UNEXPECTED_UPSTREAM_CHECKPOINT"
                ):
                    operator.main(["cutover", "--execute"])
                downstream.assert_not_called()


if __name__ == "__main__":
    unittest.main()
