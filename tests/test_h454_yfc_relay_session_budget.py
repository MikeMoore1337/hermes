"""The relay must not outlive the native reader's bounded call budget."""
from pathlib import Path
import re
import unittest

from device_fabric.linux_native_outbound import MAX_TOOL_CALLS


class YfcRelaySessionBudgetTests(unittest.TestCase):
    def test_relay_budget_matches_linux_native_reader(self):
        template = (Path(__file__).resolve().parents[1] /
                    'deploy/h454/hermes-native-three-read.template.ts').read_text(encoding='utf-8')
        matches = re.findall(r'const YFC_SESSION_CALLS\s*=\s*(\d+)\s*;', template)
        self.assertEqual(len(matches), 1)
        self.assertEqual(int(matches[0]), MAX_TOOL_CALLS)


if __name__ == '__main__':
    unittest.main()
