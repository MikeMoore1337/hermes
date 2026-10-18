"""Production-safe #294 hook into the EXISTING snapshot timer."""
import contextlib
import io
from pathlib import Path
import unittest
from unittest.mock import patch

from control_center import snapshot


class InfrastructureSnapshotTimerTests(unittest.TestCase):
    @patch("sys.argv", ["snapshot", "--output", "/tmp/example-overview.json"])
    @patch("control_center.snapshot.save_host_metrics")
    @patch("control_center.snapshot.collect_host_metrics")
    @patch("control_center.snapshot.save_snapshot")
    @patch("control_center.snapshot.collect")
    def test_overview_first_and_local_hermes_saved(self, overview, save, collect, store):
        order = []
        overview.side_effect = lambda: {"schema": 1}
        save.side_effect = lambda data, path: order.append("overview")
        collect.side_effect = lambda host: order.append("metrics") or {"host": host}
        store.side_effect = lambda snap, group: order.append("persist")
        snapshot.main()
        self.assertEqual(order, ["overview", "metrics", "persist"])
        self.assertEqual(collect.call_args.args, ("hermes",))
        self.assertEqual(store.call_args.kwargs, {"group": "hermes-control"})
        self.assertEqual(save.call_args.args[1], Path("/tmp/example-overview.json"))

    @patch("sys.argv", ["snapshot"])
    @patch("control_center.snapshot.save_host_metrics")
    @patch("control_center.snapshot.collect_host_metrics")
    @patch("control_center.snapshot.save_snapshot")
    @patch("control_center.snapshot.collect")
    def test_host_failure_does_not_break_overview(self, overview, save, collect, store):
        overview.return_value = {"schema": 1}
        collect.side_effect = OSError("private path /secret/DO-NOT-LOG")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            snapshot.main()
        save.assert_called_once()
        store.assert_not_called()
        self.assertIn("category=OSError", stderr.getvalue())
        self.assertNotIn("DO-NOT-LOG", stderr.getvalue())

    @patch("sys.argv", ["snapshot"])
    @patch("control_center.snapshot.save_host_metrics")
    @patch("control_center.snapshot.collect_host_metrics")
    @patch("control_center.snapshot.save_snapshot")
    @patch("control_center.snapshot.collect")
    def test_existing_overview_failure_is_not_masked(self, overview, save, collect, store):
        overview.return_value = {"schema": 1}
        save.side_effect = PermissionError("overview path denied")
        with self.assertRaises(PermissionError):
            snapshot.main()
        collect.assert_not_called()
        store.assert_not_called()


if __name__ == "__main__":
    unittest.main()
