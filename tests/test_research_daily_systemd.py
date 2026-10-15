"""H-03: operating budget and no-private-data boundaries of daily research job."""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class ResearchSystemdContractTests(unittest.TestCase):
    def test_service_only_public_metadata_no_extra_privileges(self):
        service=(ROOT/"deploy/hermes-research-scout.service").read_text()
        for keyword in (
            "StateDirectory=hermes-research-scout",
            "StateDirectoryMode=0700",
            "ReadWritePaths=/var/lib/hermes-research-scout",
            "InaccessiblePaths=/var/lib/hermes /var/lib/hermes-agent /var/lib/hermes-qa-watch /etc/hermes-agent",
            "CapabilityBoundingSet=\n", "NoNewPrivileges=yes",
            "ProtectSystem=strict", "PrivateDevices=yes",
            "MemoryMax=96M","CPUQuota=10%", "TimeoutStartSec=48s",
            "ExecStart=/usr/bin/python3 -m research_scout.daily_digest --execute",
        ):
            with self.subTest(keyword=keyword):
                self.assertIn(keyword,service)
        for forbidden in (
            "EnvironmentFile=", "Restart=always", "CAP_DAC_READ_SEARCH",
            "HERMES_ALERT_BOT_TOKEN","telegram_sender","docker ",
            "hermes-discovery.service","your-fitness-coach",
        ):
            self.assertNotIn(forbidden,service)

    def test_calendar_daily_plus_only_initial_activation_no_catchup(self):
        timer=(ROOT/"deploy/hermes-research-scout.timer").read_text()
        self.assertIn("OnActiveSec=2min",timer)
        self.assertIn("OnCalendar=*-*-* 19:30:00",timer)
        self.assertIn("Persistent=false",timer)
        self.assertNotIn("OnUnitActiveSec=1min",timer)

    def test_installer_does_not_affect_news_or_ops_units(self):
        installer=(ROOT/"deploy/install-research-scout.sh").read_text()
        for required in (
            "hermes-discovery.timer", "hermes-ops-watch.timer",
            "hermes-ops-alerts.timer", "hermes-qa-watch.timer",
            "python3 -m research_scout.daily_digest",
            "systemctl start hermes-research-scout.service",
            "systemctl enable --now hermes-research-scout.timer",
        ):
            self.assertIn(required,installer)
        for denied in (
            "systemctl disable hermes-discovery",
            "systemctl restart hermes-discovery",
            "systemctl restart hermes-ops-watch",
            "curl ","docker run","telegram_sender",
        ):
            self.assertNotIn(denied,installer)


if __name__=="__main__":
    unittest.main()
