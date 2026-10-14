"""NCBI pacing regression cases without external API calls."""
from __future__ import annotations

import fcntl
import os
import tempfile
import unittest
from pathlib import Path

from research_scout.ncbi_rate_limit import (
    MIN_GAP_NS, NCBIRateGateError, reserve_request,
)


class SharedNCBIRateGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "ncbi.rate"

    def reserve(self, now):
        reserve_request(path=self.path, clock_ns=lambda: now)

    def test_first_request_and_spacing(self):
        self.reserve(1_000_000_000)
        with self.assertRaisesRegex(NCBIRateGateError, "ncbi_rate_limited"):
            self.reserve(1_000_000_000)
        with self.assertRaisesRegex(NCBIRateGateError, "ncbi_rate_limited"):
            self.reserve(1_000_000_000 + MIN_GAP_NS - 1)
        self.reserve(1_000_000_000 + MIN_GAP_NS)
        self.reserve(1_000_000_000 + 2 * MIN_GAP_NS)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_denial_does_not_consume_new_slot(self):
        self.reserve(1_000_000_000)
        before = self.path.read_bytes()
        with self.assertRaises(NCBIRateGateError):
            self.reserve(1_000_000_001)
        self.assertEqual(self.path.read_bytes(), before)
        self.reserve(1_000_000_000 + MIN_GAP_NS)

    def test_corruption_weak_perms_and_symlink_fail_closed(self):
        self.path.write_text("garbage", encoding="ascii")
        self.path.chmod(0o600)
        with self.assertRaisesRegex(NCBIRateGateError, "ncbi_rate_state_invalid"):
            self.reserve(1_000_000_000)
        self.path.write_text("1", encoding="ascii")
        self.path.chmod(0o644)
        with self.assertRaisesRegex(NCBIRateGateError, "ncbi_rate_state_unsafe"):
            self.reserve(1_000_000_000)
        self.path.unlink()
        target = Path(self.tmp.name) / "target"
        target.write_text("preserve", encoding="ascii")
        self.path.symlink_to(target)
        with self.assertRaisesRegex(NCBIRateGateError, "ncbi_rate_storage_unavailable"):
            self.reserve(1_000_000_000)
        self.assertEqual(target.read_text(encoding="ascii"), "preserve")

    def test_backward_clock_or_missing_storage_fails_closed(self):
        self.reserve(2_000_000_000)
        with self.assertRaisesRegex(NCBIRateGateError, "ncbi_rate_clock_invalid"):
            self.reserve(1_000_000_000)
        with self.assertRaisesRegex(NCBIRateGateError, "ncbi_rate_storage_unavailable"):
            reserve_request(path=self.path / "missing", clock_ns=lambda: 3_000_000_000)

    def test_second_open_fd_refuses_busy_lock(self):
        self.reserve(1_000_000_000)
        fd = os.open(self.path, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(NCBIRateGateError, "ncbi_rate_lock_busy"):
                self.reserve(1_000_000_000 + MIN_GAP_NS)
        finally:
            os.close(fd)
        self.reserve(1_000_000_000 + MIN_GAP_NS)

    def test_invalid_clock_inputs_leave_state_unchanged(self):
        self.reserve(1_000_000_000)
        before = self.path.read_bytes()
        for value in (0, -1, True, 1.5, None):
            with self.subTest(value=value), self.assertRaises(NCBIRateGateError):
                reserve_request(path=self.path, clock_ns=lambda: value)
        self.assertEqual(self.path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
