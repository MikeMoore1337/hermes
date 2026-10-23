"""#454: cross-component native Windows device contract, source-only."""
from pathlib import Path
import re
import unittest
from scripts.h15_native_windows_outbound import DEVICE_NAME, hello, parse_settings
from scripts.h15_native_windows_mcp_stdio import TOOLS


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "deploy/h15/hermes-native-read-gate.template.ts"
RELAY = ROOT / "deploy/h15/hermes-native-read.template.ts"
GATEWAY = ROOT / "scripts/h15_brc_native_read_gateway.py"


class NativeContractTests(unittest.TestCase):
    def test_native_identity_matches_both_relay_templates(self):
        self.assertEqual(DEVICE_NAME, "H15 Windows native read-only")
        for file, symbol in ((GATE, "EXPECTED_NAME"), (RELAY, "DEVICE_NAME")):
            text = file.read_text(encoding="utf-8")
            literal = re.search(r"const " + symbol + r" = '([^']+)';", text)
            self.assertIsNotNone(literal, str(file))
            self.assertEqual(literal.group(1), DEVICE_NAME, str(file))

    def test_native_hello_exposes_exact_two_operations(self):
        conf = parse_settings("wss://hermes.mikemoore.top/ws",
                              "h15-native-ci-read-123456", "a" * 48)
        frame = hello(conf)
        self.assertEqual(frame["device"]["name"], DEVICE_NAME)
        self.assertEqual(frame["device"]["platform"], "win32")
        self.assertEqual([tool["name"] for tool in frame["tools"]],
                         ["native_file_stat", "native_file_read"])
        self.assertEqual(frame["tools"], list(TOOLS))

    def test_native_dispatch_uses_isolated_non_generic_route(self):
        relay = RELAY.read_text(encoding="utf-8")
        gateway = GATEWAY.read_text(encoding="utf-8")
        self.assertIn("export const NATIVE_TOOLS", relay)
        self.assertIn("...NATIVE_TOOLS", gateway)
        self.assertIn("NATIVE_CALL + CALL", gateway)
        self.assertIn("...pinnedToolCatalog()", (ROOT / "scripts/h15_brc_workspace_gateway.py").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
