"""Offline refusal/approval contracts for owner-host BRC handoff."""
from pathlib import Path
from tempfile import TemporaryDirectory
from contextlib import nullcontext
import json
import unittest
from unittest.mock import patch
from scripts import h15_brc_owner_handoff as h

NEW = "sha256:" + "a" * 64
OLD = "sha256:" + "b" * 64
SHA = "c" * 40
ARCHIVE = "d" * 64
PREPARED = {"status":"IMAGE_LOADED_PREFLIGHT_PASS_NO_CUTOVER",
            "image_id":NEW,"source_sha":SHA,"archive_sha256":ARCHIVE,
            "staging_dir":"/owner/oci/main-demo","live_relay_changed":False}


class HandoffTests(unittest.TestCase):
    def test_approval_exact_scope_and_pins(self):
        self.assertEqual(h.make_approval(PREPARED,OLD),{
            "schema":1,"decision":h.DECISION,"scope":h.SCOPE,
            "image_id":NEW,"previous_image_id":OLD,
            "archive_sha256":ARCHIVE,"hermes_commit":SHA})

    def test_refuse_unattended_before_any_stage(self):
        with patch.object(h.sys.stdin,"isatty",return_value=False),\
             patch.object(h,"prepare") as prepare:
            with self.assertRaisesRegex(h.HandoffDenied,"tty_required"):
                h.execute()
            prepare.assert_not_called()

    def test_prepare_is_never_cutover(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"stage";p.mkdir()
            with patch.object(h,"check_host"),patch.object(h,"STAGING",p),\
                 patch.object(h,"APPROVAL",Path(d)/"absent-approval"),\
                 patch.object(h,"private_root_directory"),\
                 patch.object(h,"discover",return_value={"sha":SHA}),\
                 patch.object(h,"stage",return_value=dict(PREPARED)) as stage,\
                 patch.object(h,"transactional_main") as cutover:
                result=h.prepare()
                self.assertFalse(result["cutover_approved"])
                self.assertEqual(stage.call_args.kwargs["load"],True)
                cutover.assert_not_called()

    def test_wrong_confirmation_never_authorizes(self):
        with patch.object(h.sys.stdin,"isatty",return_value=True),\
             patch.object(h.sys.stdout,"isatty",return_value=True),\
             patch.object(h,"check_host"),\
             patch.object(h,"prepare",return_value=dict(PREPARED)),\
             patch.object(h,"admit",return_value={"status":"PREFLIGHT_PASS","current_image":OLD}),\
             patch("builtins.input",return_value="NO"),\
             patch.object(h,"temporary_approval") as approval,\
             patch.object(h,"transactional_main") as cutover:
            with self.assertRaisesRegex(h.HandoffDenied,"confirmation_denied"):
                h.execute()
            approval.assert_not_called()
            cutover.assert_not_called()

    def test_confirmed_operator_receives_exact_pins(self):
        with patch.object(h.sys.stdin,"isatty",return_value=True),\
             patch.object(h.sys.stdout,"isatty",return_value=True),\
             patch.object(h,"check_host"),\
             patch.object(h,"prepare",return_value=dict(PREPARED)),\
             patch.object(h,"admit",return_value={"status":"PREFLIGHT_PASS","current_image":OLD}),\
             patch("builtins.input",return_value="APPLY BRC "+NEW[-12:]),\
             patch.object(h,"temporary_approval",return_value=nullcontext()) as approval,\
             patch.object(h,"transactional_main",return_value=0) as operator:
            result=h.execute()
            self.assertFalse(result["actual_chatgpt_codex_mcp_verified"])
            self.assertEqual(operator.call_args.args[0],[
                "cutover","--bundle-dir",PREPARED["staging_dir"],
                "--image",NEW,"--archive-sha",ARCHIVE,"--hermes-sha",SHA,"--execute"])
            self.assertEqual(approval.call_args.args[0]["previous_image_id"],OLD)

    def test_approval_is_single_use_and_removed_on_exception(self):
        with TemporaryDirectory() as d:
            target=Path(d)/"approval.json"
            with patch.object(h,"APPROVAL",target),patch.object(h,"private_root_directory"):
                with h.temporary_approval({"proof":"safe"}):
                    self.assertEqual(json.loads(target.read_text())["proof"],"safe")
                self.assertFalse(target.exists())
                with self.assertRaisesRegex(RuntimeError,"boom"):
                    with h.temporary_approval({"again":True}):
                        raise RuntimeError("boom")
                self.assertFalse(target.exists())

    def test_preexisting_approval_not_overwritten(self):
        with TemporaryDirectory() as d:
            target=Path(d)/"approval.json";target.write_text("keep")
            with patch.object(h,"APPROVAL",target),patch.object(h,"private_root_directory"):
                with self.assertRaisesRegex(h.HandoffDenied,"not_overwritten"):
                    with h.temporary_approval({"secret":"no"}): pass
            self.assertEqual(target.read_text(),"keep")

    def test_invalid_receipt_cannot_create_approval(self):
        for x in (dict(PREPARED,status="NOT_VERIFIED"),
                  dict(PREPARED,live_relay_changed=True)):
            with self.assertRaisesRegex(h.HandoffDenied,"untrusted_approval_request"):
                h.make_approval(x,OLD)

    def test_root_check_refuses_sandbox_without_docker(self):
        with patch.object(h.os,"geteuid",return_value=65534):
            with self.assertRaisesRegex(h.HandoffDenied,"root_required"):
                h.check_host()

    def test_doctor_never_crashes_on_private_owner_permission_denial(self):
        class NotTraversable:
            def exists(self):
                raise PermissionError("root-owned secrets are private")
            def is_symlink(self):
                raise PermissionError("root-owned secrets are private")
        with patch.object(h, "APPROVAL", NotTraversable()), \
             patch.object(h, "prepare") as prepare, \
             patch.object(h, "transactional_main") as upgrade:
            out=h.doctor()
            self.assertEqual(out["status"], "READ_ONLY_HOST_DIAGNOSTIC")
            self.assertEqual(out["checks"]["existing_approval"], "inaccessible")
            self.assertFalse(out["service_changed"])
            prepare.assert_not_called()
            upgrade.assert_not_called()

    def test_inaccessible_host_socket_does_not_attempt_docker(self):
        with patch.object(h.Path, "is_socket", side_effect=PermissionError("denied")), \
             patch.object(h.os, "geteuid", return_value=0), \
             patch.object(h.shutil, "which", return_value="/usr/bin/docker"), \
             patch.object(h.subprocess, "run") as dock:
            out=h.doctor()
            self.assertEqual(out["checks"]["host_docker_socket"], "inaccessible")
            self.assertFalse(out["checks"]["docker_reachable"])
            dock.assert_not_called()

    def test_doctor_never_changes_relay(self):
        with patch.object(h,"prepare") as p,patch.object(h,"transactional_main") as t,\
             patch.object(h.subprocess,"run") as runner:
            result=h.doctor()
            self.assertFalse(result["service_changed"])
            p.assert_not_called();t.assert_not_called()
            for c in runner.call_args_list:
                self.assertEqual(c.args[0][:2],["docker","info"])

if __name__=="__main__":
    unittest.main()
