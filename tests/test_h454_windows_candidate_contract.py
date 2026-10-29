"""Offline H454 candidate parity tests; only synthetic Docker metadata.

No credentials, network, Docker process, real workspace, or host mutations.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import h454_windows_candidate_contract as contract  # noqa: E402


def pair():
    original = {
        "Id": contract.ORIGINAL_ID,
        "Name": contract.ORIGINAL_NAME,
        "Image": contract.IMAGE_ID,
        "State": {"Running": True, "Status": "running"},
        "Config": {
            "User": "65534:65534",
            "Image": "hermes-h15-brc-agent-pinned:20261021",
            "Hostname": "original",
            "Env": ["NODE_ENV=production", "BRC_HOME=/run/brc", "HOME=/workspace"],
            "Cmd": None,
            "Entrypoint": ["/bin/sh", "/usr/local/bin/h15-entry.sh"],
            "WorkingDir": "/workspace",
            "Labels": {"com.hermes.scope": contract.SCOPE},
        },
        "HostConfig": {
            "Init": False,
            "PidsLimit": 128,
            "Memory": 536870912,
            "ReadonlyRootfs": True,
            "Privileged": False,
            "NetworkMode": "bridge",
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "Tmpfs": {
                "/run/brc": "rw,nosuid,nodev,noexec,uid=65534,gid=65534,mode=0700,size=8m",
                "/tmp": "rw,nosuid,nodev,noexec,uid=65534,gid=65534,mode=0700,size=64m",
            },
        },
        "Mounts": [{
            "Type": "bind",
            "Name": "",
            "Source": "/synthetic/allowed-workspace",
            "Destination": "/workspace",
            "Driver": "",
            "Mode": "",
            "RW": True,
            "Propagation": "rprivate",
        }],
    }
    candidate = copy.deepcopy(original)
    candidate["Id"] = "b" * 64
    candidate["Name"] = contract.CANDIDATE_NAME
    candidate["State"] = {"Running": False, "Status": "created"}
    candidate["Config"]["Image"] = contract.IMAGE_ID
    candidate["Config"]["Hostname"] = "candidate"
    candidate["HostConfig"]["Init"] = True
    return original, candidate


class TestH454Contract(unittest.TestCase):
    def check_hold(self, reason, mutation):
        original, candidate = pair()
        mutation(original, candidate)
        with self.assertRaises(contract.ContractHold) as exc:
            contract.verify(original, candidate)
        self.assertEqual(str(exc.exception), reason)

    def test_valid_candidate_only_passes_metadata(self):
        original, candidate = pair()
        self.assertEqual(contract.verify(original, candidate), "PASS")

    def test_second_candidate_can_be_validated_without_deleting_retained_candidate(self):
        old, new = pair()
        new["Name"] = contract.CANDIDATE_V2_NAME
        self.assertEqual(contract.verify(old, new, expected_candidate_name=contract.CANDIDATE_V2_NAME), "PASS")

    def test_unapproved_candidate_selector_fails_closed(self):
        old, new = pair()
        with self.assertRaises(contract.ContractHold) as exc:
            contract.verify(old, new, expected_candidate_name="/foreign-container")
        self.assertEqual(str(exc.exception), "CANDIDATE_SELECTOR")

    def test_docker_create_stdout_stderr_attach_defaults_are_accepted(self):
        original, candidate = pair()
        original["Config"].update(AttachStdout=False, AttachStderr=False)
        candidate["Config"].update(AttachStdout=True, AttachStderr=True)
        self.assertEqual(contract.verify(original, candidate), "PASS")

    def test_stdin_or_tty_differences_remain_denied(self):
        for key in ("AttachStdin", "OpenStdin", "StdinOnce", "Tty"):
            with self.subTest(key=key):
                original, candidate = pair()
                original["Config"][key] = False
                candidate["Config"][key] = True
                with self.assertRaises(contract.ContractHold) as exc:
                    contract.verify(original, candidate)
                self.assertEqual(str(exc.exception), "CONFIG_DRIFT")

    def test_other_config_field_changes_still_denied(self):
        self.check_hold(
            "CONFIG_DRIFT",
            lambda old, new: new["Config"].update(StopSignal="SIGKILL"),
        )

    def test_safe_diagnose_outputs_only_field_names(self):
        original, candidate = pair()
        original["Config"].update(AttachStdout=False, AttachStderr=False)
        candidate["Config"].update(AttachStdout=True, AttachStderr=True)
        original["HostConfig"]["ConsoleSize"] = [0, 0]
        candidate["HostConfig"]["ConsoleSize"] = None
        result = contract.diagnose(original, candidate, contract.CANDIDATE_NAME)
        self.assertIn("H454_CONFIG_DIFF_KEYS=AttachStderr,AttachStdout", result)
        self.assertIn("H454_HOST_DIFF_KEYS=ConsoleSize", result)
        self.assertNotIn("SIGKILL", str(result))
        self.assertIn("H454_CHANGES_APPLIED=FALSE", result)

    def test_diagnose_requires_preserved_original_and_stopped_candidate(self):
        original, candidate = pair()
        original["State"]["Running"] = False
        with self.assertRaises(contract.ContractHold) as exc:
            contract.diagnose(original, candidate, contract.CANDIDATE_NAME)
        self.assertEqual(str(exc.exception), "ORIGINAL_NOT_RUNNING")

    def test_diagnose_candidate_identity_and_state(self):
        original, candidate = pair()
        candidate["State"]["Status"] = "exited"
        with self.assertRaises(contract.ContractHold) as exc:
            contract.diagnose(original, candidate, contract.CANDIDATE_NAME)
        self.assertEqual(str(exc.exception), "CANDIDATE_NOT_CREATED")

    def test_diagnostic_field_name_sanitization(self):
        names = contract._safe_diff_keys(
            {"UNSAFE_PRIVATE_PATH": 1},
            {"UNSAFE_PRIVATE_PATH": 2},
            frozenset(),
        )
        self.assertEqual(names, ["OTHER"])

    def test_missing_tmpfs_not_masked_by_single_mount(self):
        self.check_hold("TMPFS", lambda old, new: new["HostConfig"]["Tmpfs"].pop("/run/brc"))

    def test_tmpfs_flags_must_match_not_just_paths(self):
        self.check_hold("TMPFS", lambda old, new: new["HostConfig"]["Tmpfs"].__setitem__("/tmp", "rw,size=64m"))

    def test_readiness_staging_never_inferred_from_init(self):
        self.check_hold("CANDIDATE_NOT_CREATED", lambda old, new: new["State"].update(Running=True, Status="running"))

    def test_init_mandatory(self):
        self.check_hold("INIT_MISSING", lambda old, new: new["HostConfig"].update(Init=None))

    def test_lifecycle_original_must_remain_running(self):
        self.check_hold("ORIGINAL_NOT_RUNNING", lambda old, new: old["State"].update(Running=False))

    def test_pids_128_explicit(self):
        self.check_hold("PIDS_LIMIT", lambda old, new: new["HostConfig"].update(PidsLimit=96))

    def test_security_isolation(self):
        for field, value in (("ReadonlyRootfs", False), ("Privileged", True), ("NetworkMode", "host")):
            with self.subTest(field=field):
                self.check_hold("HOST_DRIFT", lambda old, new: new["HostConfig"].update({field: value}))

    def test_original_isolation_cannot_be_unsafe(self):
        self.check_hold("ISOLATION", lambda old, new: old["HostConfig"].update(Privileged=True))

    def test_namespace_capability_drift(self):
        self.check_hold("HOST_DRIFT", lambda old, new: new["HostConfig"].update(CapDrop=[]))

    def test_environment_drift_even_secret_values_not_echoed(self):
        self.check_hold("CONFIG_DRIFT", lambda old, new: new["Config"]["Env"].append("MY_SECRET=placeholder"))

    def test_entrypoint_drift(self):
        self.check_hold("CONFIG_DRIFT", lambda old, new: new["Config"].update(Entrypoint=["/bin/sh", "/different-entry.sh"]))

    def test_bind_source_changed(self):
        self.check_hold("MOUNT_DRIFT", lambda old, new: new["Mounts"][0].update(Source="/synthetic/elsewhere"))

    def test_wrong_image(self):
        self.check_hold("IMAGE", lambda old, new: new.update(Image="sha256:" + "a" * 64))

    def test_wrong_candidate_name(self):
        self.check_hold("NAME", lambda old, new: new.update(Name="/unsafe-new-name"))

    def test_config_image_tag_can_differ_if_immutable_image_same(self):
        old, new = pair()
        new["Config"]["Image"] = "unknown-alias"
        self.assertEqual(contract.verify(old, new), "PASS")

    def test_no_extra_host_config(self):
        self.check_hold("HOST_DRIFT", lambda old, new: new["HostConfig"].update(Devices=[{"PathOnHost": "/dev/test"}]))

    def test_unexpected_mount(self):
        self.check_hold("MOUNTS", lambda old, new: new["Mounts"].append({
            "Type": "bind", "Source": "/synthetic/private", "Destination": "/private", "RW": True,
        }))


if __name__ == "__main__":
    unittest.main()