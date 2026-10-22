"""Issue #483: no real /tmp writes, Docker changes, process launches or secrets."""
from __future__ import annotations

import contextlib
import io
import json
import unittest
from unittest.mock import patch

from scripts import h15_brc_tmp_preflight as gate


def sample():
    return {
        "uid": 65534, "owner": 65534, "mode": 0o700,
        "is_dir": True, "is_symlink": False, "filesystem": "tmpfs",
        "free_bytes": 64 * 1024 * 1024, "free_inodes": 512,
        "memory_max": 512 * 1024 * 1024,
        "memory_current": 128 * 1024 * 1024,
        "environment_ok": True,
    }


class TmpPreflightTests(unittest.TestCase):
    def test_valid_snapshot_reports_space_only_without_authorizing_execution(self):
        result = gate.validate(sample())
        self.assertEqual("SPACE_OK_NOT_AUTHORIZED", result["status"])
        self.assertEqual(0, result["actions_executed"])
        self.assertFalse(result["concurrency_limit_verified"])
        self.assertFalse(result["host_docker_config_verified"])

    def test_zero_space_rejects_current_real_failure(self):
        data = sample()
        data["free_bytes"] = 0
        with self.assertRaisesRegex(gate.TempPreflightDenied, "TMP_SPACE_EXHAUSTED"):
            gate.validate(data)

    def test_one_byte_below_threshold_refused(self):
        data = sample()
        data["free_bytes"] = gate.MIN_FREE_BYTES - 1
        with self.assertRaisesRegex(gate.TempPreflightDenied, "TMP_SPACE_EXHAUSTED"):
            gate.validate(data)
        data["free_bytes"] += 1
        self.assertEqual("SPACE_OK_NOT_AUTHORIZED", gate.validate(data)["status"])

    def test_low_inodes_refused(self):
        data = sample()
        data["free_inodes"] = 63
        with self.assertRaisesRegex(gate.TempPreflightDenied, "TMP_INODES_EXHAUSTED"):
            gate.validate(data)

    def test_wrong_mount_type_refused(self):
        data = sample()
        data["filesystem"] = "ext4"
        with self.assertRaisesRegex(gate.TempPreflightDenied, "NOT_PINNED_TMPFS"):
            gate.validate(data)

    def test_nonprivate_root_group_access_and_symlinks_refused(self):
        for patching in (
            {"owner": 0},
            {"mode": 0o777},
            {"mode": 0o750},
            {"is_dir": False},
            {"is_symlink": True},
        ):
            with self.subTest(patching=patching):
                data = {**sample(), **patching}
                with self.assertRaisesRegex(gate.TempPreflightDenied, "TMP_ACCESS_NOT_PRIVATE"):
                    gate.validate(data)

    def test_untrusted_env_refused(self):
        data = sample()
        data["environment_ok"] = False
        with self.assertRaisesRegex(gate.TempPreflightDenied, "TMP_ENV_NOT_PINNED"):
            gate.validate(data)

    def test_low_memory_headroom_refused(self):
        data = sample()
        data["memory_current"] = data["memory_max"] - gate.MIN_MEMORY_HEADROOM + 1
        with self.assertRaisesRegex(gate.TempPreflightDenied, "MEMORY_HEADROOM_LOW"):
            gate.validate(data)
        data["memory_current"] -= 1
        self.assertEqual("SPACE_OK_NOT_AUTHORIZED", gate.validate(data)["status"])

    def test_missing_or_unbounded_memory_contract_refused(self):
        for maximum, current in (
            (0, 0), (2**41, 1), (512 * 1024 * 1024, 513 * 1024 * 1024),
        ):
            with self.subTest(maximum=maximum):
                data = {**sample(), "memory_max": maximum, "memory_current": current}
                with self.assertRaisesRegex(gate.TempPreflightDenied, "MEMORY_LIMIT_UNVERIFIED"):
                    gate.validate(data)

    def test_invalid_schema_and_types_refused(self):
        for mutation in (
            {"uid": True}, {"memory_current": -1}, {"free_bytes": "10000000"},
            {"environment_ok": "true"}, {"filesystem": None},
            {"is_symlink": 0},
        ):
            with self.subTest(mutation=mutation):
                data = {**sample(), **mutation}
                with self.assertRaisesRegex(gate.TempPreflightDenied, "MEASUREMENT_INVALID"):
                    gate.validate(data)
        with self.assertRaisesRegex(gate.TempPreflightDenied, "MEASUREMENT_INVALID"):
            gate.validate({**sample(), "extra_key": "secret"})

    def test_cli_no_secret_or_tmp_write_on_denial(self):
        data = sample()
        data["free_bytes"] = 0
        output = io.StringIO()
        with patch.object(gate, "collect", return_value=data), contextlib.redirect_stdout(output):
            self.assertEqual(2, gate.main())
        response = json.loads(output.getvalue())
        self.assertEqual("TMP_SPACE_EXHAUSTED", response["reason"])
        self.assertEqual(0, response["actions_executed"])
        self.assertNotIn("uid", response)
        self.assertNotIn("/workspace", output.getvalue())

    def test_cli_no_false_authorization_on_success(self):
        output = io.StringIO()
        with patch.object(gate, "collect", return_value=sample()), contextlib.redirect_stdout(output):
            self.assertEqual(0, gate.main())
        response = json.loads(output.getvalue())
        self.assertEqual("SPACE_OK_NOT_AUTHORIZED", response["status"])
        self.assertFalse(response["identity_persistence_verified"])
        self.assertFalse(response["concurrency_limit_verified"])


if __name__ == "__main__":
    unittest.main()
