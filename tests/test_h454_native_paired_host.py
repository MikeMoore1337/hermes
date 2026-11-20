"""Synthetic paired-upgrade host admission; no real host or credential."""
from types import SimpleNamespace
from contextlib import ExitStack
import fcntl
from pathlib import Path
import hashlib
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_native_paired_host as host
from scripts import h454_native_paired_staging as staging
from scripts import h454_native_paired_apply as apply_tx
from scripts.h454_native_paired_rebind import RebindDenied
from tests.test_h454_native_paired_rebind import OLD, NEW, TOKEN, snapshots
from scripts.h454_native_paired_rebind import rebind


def properties(*, active="failed"):
    return {
        "FragmentPath": "/etc/systemd/system/hermes-commander-native.service",
        "LoadState": "loaded", "ActiveState": active, "UnitFileState": "disabled",
        "User": "hermes-commander-native", "Group": "hermes-commander-native",
        "DropInPaths": "", "NeedDaemonReload": "no", "RestrictSUIDSGID": "no",
        "NoNewPrivileges": "yes", "ProtectSystem": "strict", "PrivateNetwork": "no",
        "IPAddressDeny": "::/0 0.0.0.0/0", "IPAddressAllow": "172.29.251.2/32",
    }


class PairedHostAdmissionTests(unittest.TestCase):
    def test_operation_holds_lock_for_staging_and_switch_and_rejects_unknown_mode(self):
        from contextlib import contextmanager
        events = []
        @contextmanager
        def locked():
            events.append("lock")
            yield
            events.append("unlock")
        with patch.object(apply_tx, "host_lock", locked), \
             patch.object(staging, "stage", side_effect=lambda: events.append("stage") or "plan"), \
             patch.object(apply_tx, "apply_staged", side_effect=lambda plan: events.append(plan)):
            self.assertEqual(apply_tx.operate("install-off"), "INSTALLED_DISABLED_PAIRED")
            self.assertEqual(events, ["lock", "stage", "plan", "unlock"])
            with self.assertRaises(RebindDenied):
                apply_tx.operate("unexpected")
        with patch.object(apply_tx, "host_lock", locked), \
             patch.object(staging, "stage", side_effect=ValueError("private detail")):
            with self.assertRaises(apply_tx.ApplyHold) as error:
                apply_tx.operate("install-off")
            self.assertEqual(error.exception.phase, "STAGE")
            self.assertNotIn("private detail", str(error.exception))

    def test_frozen_recovery_thaws_only_after_old_state_and_units_verify(self):
        trust, ca, unit = b"old-trust", b"old-ca", b"old-unit"
        record = {"uid": 972, "gid": 968}
        events = []

        def callback(name, result=None, fail=False):
            def run(*args, **kwargs):
                events.append(name)
                if fail:
                    raise ValueError("synthetic-secret")
                return result
            return run

        def checked(path, *args, **kwargs):
            if path.name == "private-relay.json": return trust
            if path.name == "ca.crt": return ca
            return unit

        def run(fail):
            events.clear()
            with ExitStack() as stack:
                stack.enter_context(patch.object(apply_tx.os, "geteuid", return_value=0))
                stack.enter_context(patch.object(apply_tx.socket, "gethostname", return_value="vps1777112993"))
                stack.enter_context(patch.object(Path, "exists", lambda path: path.name == "prepared"))
                stack.enter_context(patch.object(Path, "is_symlink", return_value=False))
                stack.enter_context(patch.object(Path, "lstat", return_value=SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o700, st_uid=0)))
                stack.enter_context(patch.object(apply_tx, "_record", return_value=record))
                stack.enter_context(patch.object(apply_tx, "_inert", side_effect=callback("inert")))
                stack.enter_context(patch.object(apply_tx.systemd_tx, "recover", side_effect=callback("units")))
                stack.enter_context(patch.object(apply_tx.state_tx, "recover", side_effect=callback("state", fail=fail)))
                stack.enter_context(patch.object(apply_tx, "_old_pair_matches", side_effect=callback("pair")))
                stack.enter_context(patch.object(apply_tx, "_reload", side_effect=callback("reload")))
                stack.enter_context(patch.object(apply_tx, "checked_file", side_effect=checked))
                stack.enter_context(patch.object(host, "TRUST_SHA", hashlib.sha256(trust).hexdigest()))
                stack.enter_context(patch.object(host, "CA_SHA", hashlib.sha256(ca).hexdigest()))
                stack.enter_context(patch.object(host, "UNIT_SHA", {name: hashlib.sha256(unit).hexdigest()
                    for name in ("hermes-commander-native.service", "hermes-commander-native-preflight.service")}))
                stack.enter_context(patch.object(apply_tx, "load_private_relay", side_effect=callback(
                    "trust", SimpleNamespace(relay_ipv4="172.29.251.2"))))
                stack.enter_context(patch.object(host, "_check_unit", side_effect=callback("unit_check")))
                stack.enter_context(patch.object(apply_tx, "_no_service_process", side_effect=callback("no_process")))
                stack.enter_context(patch.object(apply_tx.freeze, "restore_owner", side_effect=callback("thaw")))
                stack.enter_context(patch.object(apply_tx, "_mark", side_effect=callback("receipt")))
                if fail:
                    with self.assertRaisesRegex(RebindDenied, "^native_paired_recovery_hold$"):
                        apply_tx.recover_frozen()
                else:
                    apply_tx.recover_frozen()
            return list(events)

        success = run(False)
        for event in ("units", "state", "pair", "reload", "trust", "unit_check", "no_process"):
            self.assertLess(success.index(event), success.index("thaw"))
        self.assertEqual(success[-1], "receipt")
        failed = run(True)
        self.assertNotIn("thaw", failed)
        self.assertNotIn("reload", failed)
        self.assertNotIn("receipt", failed)

    def test_coordinator_thaws_only_after_both_journals_and_manager_verify(self):
        transition = SimpleNamespace(trust=b"new-trust", manifest=b"new-manifest",
                                     device=b"synthetic-secret", active_unit=b"new-active",
                                     preflight_unit=b"new-preflight")
        plan = host.HostPlan(transition, b"old-manifest", b"old-synthetic-secret", b"old-trust",
            {"hermes-commander-native.service": b"old-active",
             "hermes-commander-native-preflight.service": b"old-preflight"},
            b"bundle", b"receipt", b"wheel", 972, 968)

        def run(fail):
            events = []
            def callback(name, result=None):
                def invoke(*args, **kwargs):
                    events.append(name)
                    if name == fail:
                        raise ValueError("synthetic-sensitive-error")
                    return result
                return invoke
            with ExitStack() as stack:
                stack.enter_context(patch.object(host, "inspect", return_value=plan))
                stack.enter_context(patch.object(apply_tx, "_receipt", side_effect=callback("receipt", Path("/synthetic"))))
                stack.enter_context(patch.object(apply_tx, "_stopped", side_effect=callback("stopped")))
                stack.enter_context(patch.object(apply_tx, "_frozen_matches", side_effect=callback("matches")))
                stack.enter_context(patch.object(apply_tx, "_reload", side_effect=callback("reload")))
                stack.enter_context(patch.object(apply_tx, "_no_service_process", side_effect=callback("no_process")))
                stack.enter_context(patch.object(apply_tx, "_mark", side_effect=callback("finish")))
                stack.enter_context(patch.object(apply_tx, "load_private_relay", side_effect=callback("trust", SimpleNamespace(relay_ipv4="172.29.251.2"))))
                stack.enter_context(patch.object(host, "_check_unit", side_effect=callback("unit_check")))
                stack.enter_context(patch.object(apply_tx.freeze, "freeze", side_effect=callback("freeze")))
                stack.enter_context(patch.object(apply_tx.freeze, "restore_owner", side_effect=callback("thaw")))
                for module, operation, name in ((apply_tx.systemd_tx, "prepare", "unit_prepare"),
                        (apply_tx.systemd_tx, "switch", "unit_switch"),
                        (apply_tx.systemd_tx, "verify_new", "unit_verify"),
                        (apply_tx.state_tx, "prepare", "state_prepare"),
                        (apply_tx.state_tx, "switch", "state_switch"),
                        (apply_tx.state_tx, "verify_new", "state_verify")):
                    stack.enter_context(patch.object(module, operation, side_effect=callback(name)))
                if fail:
                    with self.assertRaises(apply_tx.ApplyHold) as caught:
                        apply_tx.apply_staged(plan)
                    self.assertEqual(caught.exception.phase, "UNIT_SWITCH")
                    self.assertNotIn("synthetic-sensitive", str(caught.exception))
                else:
                    apply_tx.apply_staged(plan)
            return events

        success = run(None)
        self.assertLess(success.index("state_verify"), success.index("thaw"))
        self.assertLess(success.index("unit_verify"), success.index("thaw"))
        self.assertLess(success.index("reload"), success.index("thaw"))
        self.assertEqual(success[-1], "finish")
        failed = run("unit_switch")
        self.assertNotIn("thaw", failed)
        self.assertNotIn("reload", failed)
        self.assertNotIn("finish", failed)

    def test_staging_requires_unchanged_reinspection_and_never_starts_service(self):
        plan = host.HostPlan(None, b"m", b"synthetic-bearer", b"t", {},
                             b"bundle", b"receipt", b"wheel", 972, 968)
        with patch.object(host, "inspect", side_effect=[plan, plan]) as inspect, \
             patch.object(staging, "stage_source") as source, \
             patch.object(staging, "stage_wheel") as wheel, \
             patch.object(staging, "_normalize_dirs") as normalize:
            self.assertIs(staging.stage(), plan)
            self.assertEqual(inspect.call_count, 2)
            self.assertEqual(inspect.call_args.kwargs, {"staged": True})
            source.assert_called_once()
            wheel.assert_called_once()
            normalize.assert_called_once()

        changed = host.HostPlan(None, b"different", b"synthetic-bearer", b"t", {},
                                b"bundle", b"receipt", b"wheel", 972, 968)
        with patch.object(host, "inspect", side_effect=[plan, changed]), \
             patch.object(staging, "stage_source"), patch.object(staging, "stage_wheel"), \
             patch.object(staging, "_normalize_dirs"), \
             self.assertRaisesRegex(RebindDenied, "^native_paired_stage_denied$"):
            staging.stage()

    def test_failed_admission_never_stages_source_or_wheel(self):
        with patch.object(host, "inspect", side_effect=RebindDenied("synthetic")), \
             patch.object(staging, "stage_source") as source, \
             patch.object(staging, "stage_wheel") as wheel, \
             self.assertRaises(RebindDenied):
            staging.stage()
        source.assert_not_called()
        wheel.assert_not_called()
    @unittest.skipUnless(os.name == "posix", "Linux staged-tree admission only")
    def test_staged_tree_checks_empty_files_and_rejects_extra_or_symlink(self):
        with tempfile.TemporaryDirectory(prefix="h454-tree-synthetic-") as temp, \
             patch.object(host, "owned_directory"):
            root = Path(temp)
            (root / "pkg").mkdir(mode=0o755)
            (root / "pkg").chmod(0o755)
            files = {"pkg/empty": b"", "pkg/source.py": b"synthetic"}
            for name, data in files.items():
                path = root / name
                path.write_bytes(data)
                path.chmod(0o444)
            host._verified_tree(root, files, trusted_uid=os.geteuid())
            extra = root / "pkg/extra"
            extra.write_bytes(b"foreign")
            with self.assertRaises(RebindDenied):
                host._verified_tree(root, files, trusted_uid=os.geteuid())
            extra.unlink()
            target = root / "pkg/source.py"
            target.unlink()
            target.symlink_to(root / "pkg/empty")
            with self.assertRaises(RebindDenied):
                host._verified_tree(root, files, trusted_uid=os.geteuid())

    def test_failed_disabled_service_with_complete_deny_is_inert(self):
        with patch.object(host, "raw_show", return_value=properties()), \
             patch.object(host.subprocess, "run", return_value=SimpleNamespace(
                 returncode=0, stdout=b"MainPID=0\nSubState=failed\n")):
            host._check_unit("hermes-commander-native.service", "172.29.251.2")

    def test_running_weakened_or_widened_service_is_rejected(self):
        cases = (
            {"ActiveState": "active"}, {"UnitFileState": "enabled"},
            {"DropInPaths": "/unexpected"}, {"NeedDaemonReload": "yes"},
            {"IPAddressDeny": "0.0.0.0/0"}, {"IPAddressAllow": "172.29.251.2/32 8.8.8.8/32"},
            {"NoNewPrivileges": "no"},
        )
        for change in cases:
            with self.subTest(change=change), patch.object(host, "raw_show",
                    return_value={**properties(), **change}), \
                 patch.object(host.subprocess, "run", return_value=SimpleNamespace(
                     returncode=0, stdout=b"MainPID=0\nSubState=failed\n")), \
                 self.assertRaises(RebindDenied):
                host._check_unit("hermes-commander-native.service", "172.29.251.2")
        with patch.object(host, "raw_show", return_value=properties()), \
             patch.object(host.subprocess, "run", return_value=SimpleNamespace(
                 returncode=0, stdout=b"MainPID=123\nSubState=failed\n")), \
             self.assertRaises(RebindDenied):
            host._check_unit("hermes-commander-native.service", "172.29.251.2")

    def test_plan_repr_never_discloses_secret_values(self):
        plan = host.HostPlan(None, b"private-path", b"synthetic-bearer", b"private-trust",
                             {}, b"bundle", b"receipt", b"wheel", 972, 968)
        self.assertEqual(repr(plan), "HostPlan([REDACTED])")

    @unittest.skipUnless(os.name == "posix", "Linux host admission only")
    def test_inspection_binds_snapshots_and_fails_on_service_user_process(self):
        import pwd
        manifest, device, trust, ca, unit = (b"synthetic-manifest", b"synthetic-device",
                                             b"synthetic-trust", b"synthetic-ca", b"synthetic-unit")
        values = {
            "manifest.json": manifest, "device.json": device, "private-relay.json": trust,
            "ca.crt": ca, "h454-native-linux-readonly.tar.gz": b"bundle",
            "h454-native-bundle-receipt.json": b"receipt", "websockets-17.2-py3-none-any.whl": b"wheel",
            "hermes-commander-native.service": unit,
            "hermes-commander-native-preflight.service": unit,
            "synthetic.py": b"source",
        }
        uid, gid = 12345, 12346
        meta = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=uid, st_gid=gid)
        transition = object()
        def get_file(path, *args, **kwargs):
            return values[path.name]
        def patches(stack, pgrep_result):
            stack.enter_context(patch.object(host.os, "geteuid", return_value=0))
            stack.enter_context(patch.object(host.socket, "gethostname", return_value="vps1777112993"))
            stack.enter_context(patch.object(pwd, "getpwnam", return_value=SimpleNamespace(
                pw_uid=uid, pw_gid=gid, pw_shell="/usr/sbin/nologin")))
            stack.enter_context(patch.object(Path, "lstat", return_value=meta))
            stack.enter_context(patch.object(Path, "exists", return_value=False))
            stack.enter_context(patch.object(Path, "is_symlink", return_value=False))
            stack.enter_context(patch.object(host, "owned_directory"))
            stack.enter_context(patch.object(host, "checked_file", side_effect=get_file))
            stack.enter_context(patch.object(host, "MANIFEST_SHA", hashlib.sha256(manifest).hexdigest()))
            stack.enter_context(patch.object(host, "TRUST_SHA", hashlib.sha256(trust).hexdigest()))
            stack.enter_context(patch.object(host, "CA_SHA", hashlib.sha256(ca).hexdigest()))
            stack.enter_context(patch.object(host, "WHEEL_SHA", hashlib.sha256(b"wheel").hexdigest()))
            stack.enter_context(patch.object(host, "OLD_BLOBS", {"device_fabric/synthetic.py": host._blob(b"source")}))
            stack.enter_context(patch.object(host, "UNIT_SHA", {name: hashlib.sha256(unit).hexdigest()
                for name in ("hermes-commander-native.service", "hermes-commander-native-preflight.service")}))
            stack.enter_context(patch.object(host, "load_private_relay", return_value=SimpleNamespace(relay_ipv4="172.29.251.2")))
            stack.enter_context(patch.object(host, "_check_unit"))
            stack.enter_context(patch.object(host.subprocess, "run", return_value=SimpleNamespace(returncode=pgrep_result)))
            stack.enter_context(patch.object(host, "verify_wheel"))
            stack.enter_context(patch.object(host, "build_transition", return_value=transition))
        with ExitStack() as stack:
            patches(stack, 1)
            plan = host.inspect()
            self.assertIs(plan.transition, transition)
            self.assertNotIn("synthetic-device", repr(plan))
        with ExitStack() as stack:
            patches(stack, 0)
            with self.assertRaisesRegex(RebindDenied, "^native_paired_host_denied$"):
                host.inspect()


@unittest.skipUnless(os.name == "posix", "Linux synthetic transaction")
class PairedTransactionIntegrationTests(unittest.TestCase):
    def test_host_lock_cooperates_with_upgrade_and_enrollment_writers(self):
        if os.geteuid() != 0:
            with self.assertRaises(RebindDenied):
                with apply_tx.host_lock():
                    pass
            return
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root = Path(temp)
            locks, state = root / "locks", root / "state"
            locks.mkdir(mode=0o777); locks.chmod(0o1777)
            state.mkdir(mode=0o700); os.chown(state, 65534, 65534)
            lock = locks / "upgrade.lock"
            lock.touch(mode=0o600)
            stack.enter_context(patch.object(apply_tx, "LOCK", lock))
            stack.enter_context(patch.object(apply_tx, "STATE", state))
            stack.enter_context(patch.object(apply_tx, "owned_directory"))
            stack.enter_context(patch.object(apply_tx.socket, "gethostname", return_value="vps1777112993"))
            stack.enter_context(patch.object(apply_tx.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=65534)))
            upgrade_fd = os.open(lock, os.O_RDWR)
            state_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
            stack.callback(os.close, upgrade_fd); stack.callback(os.close, state_fd)
            with apply_tx.host_lock():
                for fd in (upgrade_fd, state_fd):
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(upgrade_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                with apply_tx.host_lock():
                    pass
            fcntl.flock(upgrade_fd, fcntl.LOCK_UN)
            lock.unlink()
            lock.symlink_to(state)
            with self.assertRaises(OSError):
                with apply_tx.host_lock():
                    pass

    def test_real_files_survive_interrupted_switch_and_completed_rollback(self):
        if os.geteuid() != 0:
            for operation in (apply_tx.recover_frozen, apply_tx.rollback_disabled):
                with self.assertRaises(RebindDenied):
                    operation()
            return
        for scenario in ("completed", "freeze_interrupted", "state_interrupted", "unit_interrupted",
                         "reload_interrupted", "verify_interrupted", "thaw_interrupted", "receipt_interrupted"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                root = Path(temp)
                base, state, units = root / "base", root / "state", root / "units"
                base.mkdir(); state.mkdir(mode=0o700); units.mkdir()
                (base / "receipts").mkdir(); (base / "trust").mkdir()
                manifest, device = snapshots()
                for name, raw in (("manifest.json", manifest), ("device.json", device)):
                    path = state / name
                    path.write_bytes(raw); path.chmod(0o600); os.chown(path, 65534, 65534)
                os.chown(state, 65534, 65534)
                old_trust, new_trust, ca = b"old trust", b"new trust", b"synthetic ca"
                for name, raw in (("private-relay.json", old_trust), ("ca.crt", ca)):
                    path = base / "trust" / name
                    path.write_bytes(raw); path.chmod(0o444)
                old_units = {name: ("old " + name).encode() for name in host.UNIT_SHA}
                for name, raw in old_units.items():
                    path = units / name
                    path.write_bytes(raw); path.chmod(0o644)
                bound = rebind(manifest, device, old_release=OLD, new_release=NEW, bundle_sha256="e" * 64)
                transition = SimpleNamespace(manifest=bound.manifest, device=bound.device, trust=new_trust,
                    active_unit=b"new active", preflight_unit=b"new preflight")
                plan = host.HostPlan(transition, manifest, device, old_trust, old_units,
                                     b"bundle", b"receipt", b"wheel", 65534, 65534)
                directories = {"trust": base / "trust", "active": units, "preflight": units}
                for obj, name, value in ((apply_tx, "BASE", base), (apply_tx, "STATE", state),
                        (apply_tx, "UNIT_DIRS", directories), (host, "OLD", OLD), (host, "NEW", NEW),
                        (host, "BUNDLE_SHA", "e" * 64), (host, "MANIFEST_SHA", hashlib.sha256(manifest).hexdigest()),
                        (host, "TRUST_SHA", hashlib.sha256(old_trust).hexdigest()),
                        (host, "CA_SHA", hashlib.sha256(ca).hexdigest()),
                        (host, "UNIT_SHA", {k: hashlib.sha256(v).hexdigest() for k, v in old_units.items()})):
                    stack.enter_context(patch.object(obj, name, value))
                stack.enter_context(patch.object(apply_tx.socket, "gethostname", return_value="vps1777112993"))
                stack.enter_context(patch.object(apply_tx.pwd, "getpwnam", return_value=SimpleNamespace(
                    pw_uid=65534, pw_gid=65534, pw_shell="/usr/sbin/nologin")))
                stack.enter_context(patch.object(apply_tx, "owned_directory"))
                stack.enter_context(patch.object(host, "inspect", return_value=plan))
                for name in ("_stopped", "_inert", "_no_service_process", "_reload"):
                    stack.enter_context(patch.object(apply_tx, name))
                stack.enter_context(patch.object(host, "_check_unit"))
                stack.enter_context(patch.object(apply_tx, "load_private_relay", return_value=SimpleNamespace(relay_ipv4="127.0.0.1")))
                if scenario in ("state_interrupted", "unit_interrupted", "thaw_interrupted"):
                    module, operation = {
                        "state_interrupted": (apply_tx.state_tx, "replace_frozen_state"),
                        "unit_interrupted": (apply_tx.systemd_tx, "replace_trusted_file"),
                        "thaw_interrupted": (apply_tx.freeze, "restore_owner"),
                    }[scenario]
                    real = getattr(module, operation)
                    def fail_after_replace(*args, **kwargs):
                        real(*args, **kwargs)
                        raise OSError("synthetic interruption")
                    with patch.object(module, operation, side_effect=fail_after_replace):
                        with self.assertRaises(apply_tx.ApplyHold):
                            apply_tx.apply_staged(plan)
                    if scenario == "thaw_interrupted":
                        self.assertEqual(state.stat().st_uid, 65534)
                        apply_tx.rollback_disabled()
                    else:
                        self.assertEqual(state.stat().st_uid, 0)
                        apply_tx.recover_frozen()
                elif scenario == "freeze_interrupted":
                    real = apply_tx.freeze._create
                    def fail_after_chown(fd, name, data):
                        if name == "frozen":
                            raise OSError("synthetic interruption")
                        return real(fd, name, data)
                    with patch.object(apply_tx.freeze, "_create", side_effect=fail_after_chown):
                        with self.assertRaises(apply_tx.ApplyHold):
                            apply_tx.apply_staged(plan)
                    self.assertEqual(state.stat().st_uid, 0)
                    apply_tx.recover_frozen()
                elif scenario in ("reload_interrupted", "verify_interrupted"):
                    module, operation = ((apply_tx, "_reload") if scenario == "reload_interrupted"
                                         else (apply_tx.state_tx, "verify_new"))
                    with patch.object(module, operation, side_effect=OSError("synthetic interruption")):
                        with self.assertRaises(apply_tx.ApplyHold):
                            apply_tx.apply_staged(plan)
                    self.assertEqual(state.stat().st_uid, 0)
                    apply_tx.recover_frozen()
                elif scenario == "receipt_interrupted":
                    with patch.object(apply_tx, "_mark", side_effect=OSError("synthetic interruption")):
                        with self.assertRaises(apply_tx.ApplyHold) as caught:
                            apply_tx.apply_staged(plan)
                        self.assertEqual(caught.exception.phase, "RECEIPT_FINISH")
                    self.assertEqual(state.stat().st_uid, 65534)
                    apply_tx.rollback_disabled()
                else:
                    apply_tx.apply_staged(plan)
                    self.assertEqual(state.stat().st_uid, 65534)
                    apply_tx.rollback_disabled()
                self.assertEqual(state.stat().st_uid, 65534)
                self.assertEqual((state / "manifest.json").read_bytes(), manifest)
                self.assertEqual((state / "device.json").read_bytes(), device)
                self.assertEqual((base / "trust" / "private-relay.json").read_bytes(), old_trust)
                for name, raw in old_units.items():
                    self.assertEqual((units / name).read_bytes(), raw)
                receipt = base / "receipts" / ("h454-paired-upgrade-" + NEW)
                for path in receipt.rglob("*"):
                    if path.is_file():
                        self.assertNotIn(TOKEN.encode(), path.read_bytes())


if __name__ == "__main__":
    unittest.main()
