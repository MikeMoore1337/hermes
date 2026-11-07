"""Offline contract tests for live BRC relay transactional replacement."""
from contextlib import nullcontext
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from scripts import h15_brc_transactional_upgrade as m
from scripts.h15_brc_upgrade_preflight import PINNED_REGISTRY_SOURCE, REGISTRY_TARGET

NEW="sha256:"+"2"*64
OLD="sha256:"+"1"*64
CID="a"*64
RUNTIME="sha256:"+"3"*64
def old():
    return {"Mounts": [{"Type":"bind","Source":"/var/lib/hermes-brc-relay",
                        "Destination":"/state","RW":True}],
            "Image": OLD, "Config": {"User": "979:975",
            "Labels": {"com.hermes.scope": "h15-brc-owner-relay"}}}
def new():
    return {"Mounts": [{"Type":"bind","Source":"/var/lib/hermes-brc-relay",
                        "Destination":"/state","RW":True}],
            "Image": NEW, "Config": {"User": "979:975",
            "Labels": {"com.hermes.scope": "h15-brc-owner-relay"}}}

class CutoverContracts(unittest.TestCase):
    def test_approval_identity_exact(self):
        doc={"schema":1,"decision":"OWNER_APPROVED_LIVE_BRC_RELAY_CUTOVER",
             "scope":"EXISTING_PAIRED_DEVICES_NO_HOST_PERMISSION_CHANGE",
             "image_id":NEW,"previous_image_id":OLD,"archive_sha256":"b"*64,
             "hermes_commit":"a"*40}
        m.approve(doc,NEW,OLD,"b"*64,"a"*40)
        for key,val in [("scope","HOST"),("image_id",OLD),("previous_image_id",NEW),
                        ("archive_sha256","c"*64),("decision","CI_APPROVED")]:
            with self.subTest(key=key), self.assertRaises(m.CutoverDenied):
                m.approve(dict(doc,**{key:val}),NEW,OLD,"b"*64,"a"*40)
    def test_execute_flag_required_before_preflight(self):
        with patch.object(m.os,"geteuid",return_value=0),patch.object(m,"admit") as admit:
            rc=m.main(["cutover","--bundle-dir","/x","--image",NEW,
                       "--archive-sha","b"*64,"--hermes-sha","a"*40])
            self.assertEqual(rc,2)
            admit.assert_not_called()
    def test_plan_is_read_only(self):
        with patch.object(m.os,"geteuid",return_value=0), \
             patch.object(m,"require_unpaired_wss"), \
             patch.object(m,"lock",return_value=nullcontext()), \
             patch.object(m,"admit",return_value={"current_image":OLD,"candidate_image":RUNTIME}), \
             patch.object(m,"docker") as docker,patch.object(m,"approval_file") as approval:
            self.assertEqual(m.main(["plan","--bundle-dir","/x","--image",NEW,
                            "--archive-sha","b"*64,"--hermes-sha","a"*40]),0)
            approval.assert_not_called()
            docker.assert_not_called()
    def test_cutover_uses_attested_runtime_id_but_approves_config_pin(self):
        with patch.object(m.os,"geteuid",return_value=0), \
             patch.object(m,"require_unpaired_wss"), \
             patch.object(m,"lock",return_value=nullcontext()), \
             patch.object(m,"admit",return_value={"current_image":OLD,"candidate_image":RUNTIME}), \
             patch.object(m,"approval_file") as approval, \
             patch.object(m,"check_files"), \
             patch.object(m,"devices",return_value=2), \
             patch.object(m,"snapshot"), \
             patch.object(m,"swap",return_value={"status":"SWITCHED_PENDING_LIVE_CLIENT_E2E"}) as switched:
            self.assertEqual(m.main(["cutover","--bundle-dir","/x","--image",NEW,
                             "--archive-sha","b"*64,"--hermes-sha","a"*40,
                             "--execute"]),0)
        approval.assert_called_once_with(NEW,OLD,"b"*64,"a"*40)
        switched.assert_called_once_with(RUNTIME,OLD,2)

    def test_paired_wss_pins_deny_even_readonly_plan_before_admit(self):
        with tempfile.TemporaryDirectory() as tmp:
            pins = Path(tmp) / "pins.json"
            pins.write_text("{}", encoding="ascii")
            with patch.object(m, "WSS_PAIR_PINS", pins), \
                 patch.object(m.os, "geteuid", return_value=0), \
                 patch.object(m, "admit") as admit, \
                 patch.object(m.subprocess, "run") as docker:
                rc = m.main(["plan", "--bundle-dir", "/x", "--image", NEW,
                             "--archive-sha", "b"*64, "--hermes-sha", "a"*40])
            self.assertEqual(rc, 2)
            admit.assert_not_called()
            docker.assert_not_called()

    def test_wss_proxy_container_deny_even_if_pin_file_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "pins.json"
            with patch.object(m, "WSS_PAIR_PINS", missing), \
                 patch.object(m.subprocess, "run", return_value=SimpleNamespace(
                     returncode=0, stdout="hermes-h454-wss-proxy\n")) as docker:
                with self.assertRaisesRegex(
                        m.CutoverDenied, "PAIRED_WSS_REQUIRES_ATOMIC_CUTOVER"):
                    m.require_unpaired_wss()
                self.assertIn("name=^/hermes-h454-wss-proxy$",
                              docker.call_args.args[0])

    def test_unavailable_wss_discovery_does_not_allow_crossover(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(m, "WSS_PAIR_PINS", Path(tmp) / "pins.json"), \
                 patch.object(m.subprocess, "run", side_effect=OSError("synthetic")):
                with self.assertRaisesRegex(
                        m.CutoverDenied, "WSS_PROXY_DISCOVERY_UNAVAILABLE"):
                    m.require_unpaired_wss()

    def test_malformed_wss_discovery_output_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(m, "WSS_PAIR_PINS", Path(tmp) / "pins.json"), \
                 patch.object(m.subprocess, "run", return_value=SimpleNamespace(
                     returncode=0, stdout=None)):
                with self.assertRaisesRegex(
                        m.CutoverDenied, "WSS_PROXY_DISCOVERY_UNAVAILABLE"):
                    m.require_unpaired_wss()

    def test_genuinely_unpaired_relay_still_allows_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(m, "WSS_PAIR_PINS", Path(tmp) / "pins.json"), \
                 patch.object(m.subprocess, "run", return_value=SimpleNamespace(
                     returncode=0, stdout="")) as docker:
                m.require_unpaired_wss()
            docker.assert_called_once()

    def test_health_probe_is_direct_not_proxy_routed(self):
        from unittest.mock import MagicMock
        with patch.object(m,"build_opener") as factory:
            response=MagicMock()
            response.__enter__.return_value=response
            response.status=200
            response.read.return_value=b'{"ok":true,"devices":3}'
            factory.return_value.open.return_value=response
            self.assertEqual(m.devices(),3)
            self.assertEqual(factory.call_args.args[0].proxies,{})
            self.assertEqual(factory.return_value.open.call_args.args[0],
                             "http://172.29.251.2:3000/health")

    def test_no_host_paths_or_secrets_in_run(self):
        args=m.run_args(NEW,"979:975")
        for token in ("--read-only","--cap-drop","no-new-privileges",
                      "hermes-brc-internal","--env-file"):
            self.assertIn(token,args)
        self.assertNotIn("--privileged",args)
        self.assertNotIn("--publish",args)
        self.assertNotIn("/var/run/docker.sock"," ".join(args))
        self.assertNotIn("BRC_ADMIN_PASSWORD="," ".join(args))
    def test_unpinned_registry_path_is_denied_before_docker(self):
        with self.assertRaisesRegex(m.CutoverDenied, "UNPINNED_WORKSPACE_REGISTRY_SOURCE"):
            m.run_args(NEW, "979:975", "/var/run/docker.sock")

    def test_run_args_preserves_readonly_catalog_and_original_env(self):
        src = str(PINNED_REGISTRY_SOURCE)
        args = m.run_args(NEW, "979:975", src)
        self.assertEqual(args.count("--mount"), 2)
        self.assertIn("type=bind,src=" + src + ",dst=" + REGISTRY_TARGET
                      + ",readonly", args)
        for expected in ("BRC_WORKSPACE_REGISTRY=" + REGISTRY_TARGET,
                         "BRC_DB=/state/relay.sqlite", "HOME=/tmp"):
            self.assertEqual(args.count(expected), 1)
        self.assertNotIn("--publish", args)
        self.assertNotIn("--privileged", args)

    def test_swap_keeps_verified_registry_mount_and_env(self):
        events = []
        src = str(PINNED_REGISTRY_SOURCE)
        def command(*args, **kwargs):
            events.append(args)
            return CID if args[0] == "run" else ""
        with patch.object(m, "inspect", side_effect=[old(),new(),new()]), \
             patch.object(m, "registry_mount_source", return_value=src) as verified, \
             patch.object(m, "current_gate", return_value=NEW), \
             patch.object(m, "exists", return_value=False), \
             patch.object(m, "healthy", return_value=True), \
             patch.object(m, "docker", side_effect=command):
            self.assertEqual(m.swap(NEW, OLD, 2)["status"],
                             "SWITCHED_PENDING_LIVE_CLIENT_E2E")
        self.assertEqual(verified.call_count, 2)
        args = next(args for args in events if args[0] == "run")
        self.assertEqual(args.count("--mount"), 2)
        self.assertIn("type=bind,src=" + src + ",dst=" + REGISTRY_TARGET
                      + ",readonly", args)
        self.assertIn("BRC_WORKSPACE_REGISTRY=" + REGISTRY_TARGET, args)

    def test_dropped_catalog_rolls_back_old_relay(self):
        src = str(PINNED_REGISTRY_SOURCE)
        commands = []
        def docker(*args, **kwargs):
            commands.append(args)
            return CID if args[0] == "run" else ""
        with patch.object(m, "inspect", side_effect=[old(),new(),new()]), \
             patch.object(m, "registry_mount_source", side_effect=[src,None]), \
             patch.object(m, "exists", side_effect=lambda n: n==m.NAME), \
             patch.object(m, "healthy", return_value=True), \
             patch.object(m, "docker", side_effect=docker):
            with self.assertRaisesRegex(m.CutoverDenied, "SWITCH_FAILED_OLD_RELAY_RESTORED"):
                m.swap(NEW, OLD, 2)
        self.assertIn(("rename", m.CHECKPOINT, m.NAME), commands)
        self.assertIn(("start", m.NAME), commands)

    def test_collision_never_stops_owner(self):
        with patch.object(m,"inspect",return_value=old()), \
             patch.object(m,"exists",return_value=True), patch.object(m,"docker") as docker:
            with self.assertRaisesRegex(m.CutoverDenied,"CHECKPOINT_ALREADY_EXISTS"):
                m.swap(NEW,OLD,3)
            docker.assert_not_called()
    def test_old_unhealthy_refuses_before_stop(self):
        with patch.object(m,"inspect",return_value=old()), \
             patch.object(m,"exists",return_value=False), \
             patch.object(m,"healthy",return_value=False), patch.object(m,"docker") as docker:
            with self.assertRaisesRegex(m.CutoverDenied,"OLD_RELAY_UNHEALTHY"):
                m.swap(NEW,OLD,3)
            docker.assert_not_called()
    def test_happy_path_keeps_old_checkpoint(self):
        commands=[]
        def command(*a,**kw):
            commands.append(a)
            return CID if a[0]=="run" else ""
        with patch.object(m,"inspect",side_effect=[old(),new(),new()]), \
             patch.object(m,"current_gate",return_value=NEW), \
             patch.object(m,"exists",return_value=False), \
             patch.object(m,"healthy",return_value=True), \
             patch.object(m,"docker",side_effect=command):
            result=m.swap(NEW,OLD,3)
        self.assertEqual(result["status"],"SWITCHED_PENDING_LIVE_CLIENT_E2E")
        self.assertIn(("rename",m.NAME,m.CHECKPOINT),commands)
        self.assertIn(("update","--restart","unless-stopped",m.NAME),commands)
    def test_failed_health_restores_prior_container(self):
        commands=[]
        alive={"current":False}
        def command(*a,**kw):
            commands.append(a)
            if a[0]=="run":
                alive["current"]=True
                return CID
            if a[:2]==("rm","-f"):
                alive["current"]=False
            return ""
        def lookup(args):
            return old() if not commands else new()
        with patch.object(m,"inspect",side_effect=lookup), \
             patch.object(m,"exists",side_effect=lambda name:alive["current"] if name==m.NAME else False), \
             patch.object(m,"healthy",side_effect=[True,False,True]), \
             patch.object(m,"docker",side_effect=command):
            with self.assertRaisesRegex(m.CutoverDenied,"OLD_RELAY_RESTORED"):
                m.swap(NEW,OLD,3)
        self.assertIn(("rm","-f",m.NAME),commands)
        self.assertIn(("rename",m.CHECKPOINT,m.NAME),commands)
        self.assertIn(("start",m.NAME),commands)
    def test_rename_reply_lost_detects_owner_checkpoint_and_restores(self):
        calls=[]
        checkpoint={"Image":OLD,"Config":{"User":"979:975",
                    "Labels":{"com.hermes.scope":"h15-brc-owner-relay"}}}
        def command(*args,**kwargs):
            calls.append(args)
            if args[:2]==("rename",m.NAME):
                raise m.CutoverDenied("DOCKER_OPERATION_UNAVAILABLE")
            return ""
        def lookup(args):
            if args[-1]==m.CHECKPOINT:
                return checkpoint
            return old()
        state={"checkpoint_checks":0}
        def present(name):
            if name==m.CHECKPOINT:
                state["checkpoint_checks"]+=1
                return state["checkpoint_checks"]>1
            return False
        with patch.object(m,"inspect",side_effect=lookup), \
             patch.object(m,"exists",side_effect=present), \
             patch.object(m,"healthy",return_value=True), \
             patch.object(m,"docker",side_effect=command):
            with self.assertRaisesRegex(m.CutoverDenied,"OLD_RELAY_RESTORED"):
                m.swap(NEW,OLD,3)
        self.assertIn(("rename",m.CHECKPOINT,m.NAME),calls)
        self.assertIn(("start",m.NAME),calls)

    def test_foreign_container_never_deleted(self):
        calls=[]
        def cmd(*a,**kw):
            calls.append(a)
            if a[0]=="run":return CID
            return ""
        foreign={"Image":OLD,"Config":{"Labels":{"com.hermes.scope":"other"}}}
        with patch.object(m,"inspect",side_effect=[old(),foreign,foreign]), \
             patch.object(m,"exists",side_effect=[False,True]), \
             patch.object(m,"healthy",return_value=True), \
             patch.object(m,"docker",side_effect=cmd):
            with self.assertRaisesRegex(m.CutoverDenied,"ROLLBACK_INCOMPLETE"):
                m.swap(NEW,OLD,3)
        self.assertNotIn(("rm","-f",m.NAME),calls)

if __name__=="__main__":
    unittest.main()
