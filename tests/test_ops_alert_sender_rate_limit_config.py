"""Guard #295 Ops Watch Telegram systemd timer/start-limit consistency.

Static contract: bounded 10-minute sender, one delivered outbox event per
invocation, no automatic retry loop, and explicit room for owner inspections.
All checks are offline; no systemctl, Telegram credentials or network.
"""
from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "deploy" / "hermes-ops-alerts.service"
TIMER = ROOT / "deploy" / "hermes-ops-alerts.timer"


def directives(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for row in path.read_text(encoding="utf-8").splitlines():
        row = row.strip()
        if not row or row.startswith(("#", "[")):
            continue
        if "=" not in row:
            raise ValueError("malformed_systemd_unit")
        key, value = row.split("=", 1)
        # systemd allows repeating AssertPathExists for independent prerequisites.
        if key in result and key != "AssertPathExists":
            raise ValueError("duplicate_systemd_directive")
        result[key] = value
    return result


def as_minutes(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)(min|h)", value)
    if match is None:
        raise ValueError("invalid_unit_duration")
    size = int(match.group(1))
    return size * (60 if match.group(2) == "h" else 1)


class TelegramSenderRateLimitTests(unittest.TestCase):
    def test_normal_ten_minute_timer_has_bounded_start_headroom(self):
        service = directives(SERVICE)
        timer = directives(TIMER)
        self.assertEqual(timer["Unit"], "hermes-ops-alerts.service")
        self.assertEqual(timer["OnUnitActiveSec"], "10min")
        self.assertEqual(timer["OnActiveSec"], "2min")
        self.assertEqual(timer["RandomizedDelaySec"], "20s")
        self.assertEqual(timer["Persistent"], "false")
        hour = as_minutes(service["StartLimitIntervalSec"])
        burst = int(service["StartLimitBurst"])
        self.assertEqual(hour, 60)
        self.assertGreaterEqual(burst, 10)
        self.assertLessEqual(burst, 12)
        # At most approximately six routine activations in one hour. The
        # historical 6-per-hour start-limit left zero reserve and blocked
        # real notifications after safe manual diagnostics.
        self.assertGreater(burst, hour // as_minutes(timer["OnUnitActiveSec"]))
        self.assertEqual(service["Type"], "oneshot")

    def test_keep_sender_sandbox_and_one_event_contract(self):
        service = directives(SERVICE)
        self.assertEqual(service["User"], "root")
        self.assertEqual(service["NoNewPrivileges"], "yes")
        self.assertEqual(service["ProtectSystem"], "strict")
        self.assertEqual(service["ProtectHome"], "yes")
        self.assertEqual(service["PrivateDevices"], "yes")
        self.assertEqual(service["MemoryMax"], "96M")
        self.assertEqual(service["ExecStart"],
                         "/usr/bin/python3 -m ops_watch.telegram_dispatch --execute")
        self.assertEqual(service["TimeoutStartSec"], "35s")
        self.assertEqual(service["ReadWritePaths"], "/run/hermes-ops-alerts/outbox")
        self.assertEqual(service["CapabilityBoundingSet"], "")


if __name__ == "__main__":
    unittest.main()
