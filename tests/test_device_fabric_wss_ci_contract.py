"""Ensure optional WSS integration tests cannot poison stdlib-only VPS release checks."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WssSplitCiContract(unittest.TestCase):
    def test_pinned_external_dependency_only_in_isolated_ci(self):
        self.assertFalse((ROOT / "tests/test_device_fabric_presence.py").exists())
        integration = ROOT / "evals/device_fabric_wss/presence_integration.py"
        self.assertTrue(integration.is_file())
        self.assertIn("class PresenceWssTests", integration.read_text())
        workflow = (ROOT / ".github/workflows/device-fabric-wss.yml").read_text()
        self.assertIn("websockets==16.0", workflow)
        self.assertIn("-s evals/device_fabric_wss -p 'presence_integration.py'", workflow)
        self.assertNotIn("-s tests -p 'test_device_fabric_presence.py'", workflow)


if __name__ == "__main__":
    unittest.main()
