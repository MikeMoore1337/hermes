"""Читаемые сценарии отказа в запуске при нехватке ресурсов Hermes."""

from __future__ import annotations

import unittest

from scripts.host_capacity import HostFacts, evaluate, parse_meminfo


class HostCapacityTests(unittest.TestCase):
    """Результат решения проверяется без внешних команд и доступа к VPS."""

    def setUp(self) -> None:
        self.facts = HostFacts(
            available_mib=1100,
            swap_used_mib=700,
            load1=0.5,
            disk_free_mib=15000,
            news_phase_active=False,
        )

    def decide(self, facts: HostFacts, *, reserve: int = 128) -> dict[str, object]:
        return evaluate(facts, reserve_mib=reserve, margin_mib=32)

    def test_available_memory_and_idle_news_allows_short_smoke(self) -> None:
        self.assertEqual(self.decide(self.facts)["status"], "ready")

    def test_insufficient_memory_reserve_rejects_agent_without_affecting_news(self) -> None:
        low = HostFacts(available_mib=920, swap_used_mib=700, load1=0.5,
                        disk_free_mib=15000, news_phase_active=False)
        result = self.decide(low)
        self.assertEqual(result["status"], "skipped")
        self.assertIn("insufficient_news_memory_headroom", result["blockers"])

    def test_swap_added_does_not_bypass_existing_used_swap_pressure(self) -> None:
        high = HostFacts(available_mib=1200, swap_used_mib=1100, load1=0.5,
                         disk_free_mib=15000, news_phase_active=False)
        self.assertIn("existing_news_swap_pressure", self.decide(high)["blockers"])

    def test_active_news_phase_blocks_agent(self) -> None:
        busy = HostFacts(available_mib=1200, swap_used_mib=700, load1=0.5,
                         disk_free_mib=15000, news_phase_active=True)
        self.assertIn("news_phase_active", self.decide(busy)["blockers"])

    def test_underlying_load_or_disk_pressure_blocks_agent(self) -> None:
        busy = HostFacts(available_mib=1200, swap_used_mib=700, load1=1.6,
                         disk_free_mib=5000, news_phase_active=False)
        result = self.decide(busy)
        self.assertIn("existing_news_load_pressure", result["blockers"])
        self.assertIn("existing_news_disk_pressure", result["blockers"])

    def test_capacity_limit_cannot_be_zero_or_negative(self) -> None:
        with self.assertRaises(ValueError):
            evaluate(self.facts, reserve_mib=0, margin_mib=32)
        with self.assertRaises(ValueError):
            evaluate(self.facts, reserve_mib=128, margin_mib=-1)

    def test_parse_meminfo_uses_available_not_free(self) -> None:
        raw = "MemFree: 200000 kB\nMemAvailable: 1024000 kB\nSwapTotal: 4194304 kB\nSwapFree: 3145728 kB\n"
        self.assertEqual(parse_meminfo(raw), (1000, 1024))


if __name__ == "__main__":
    unittest.main()
