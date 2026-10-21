"""Development-only read-only design orchestration guard."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DesignOrchestraTest(unittest.TestCase):
    def test_control_center_scope(self):
        s = (ROOT / ".agents/skills/ux-ui-design-orchestra/SKILL.md").read_text(encoding="utf-8")
        d = (ROOT / "docs/ux/ux-ui-design-orchestra.md").read_text(encoding="utf-8")
        for token in ("name: ux-ui-design-orchestra", "control_center/frontend", "READ_ONLY",
                      "SEQUENTIAL", "Принимаю", "resident Hermes Agent"):
            self.assertIn(token, s)
        self.assertIn("VISUAL_PACKAGE_MISSING", d)


if __name__ == "__main__":
    unittest.main()
