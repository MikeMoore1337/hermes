"""Offline source and Docker-identity refusal tests for H15 upgrade gate."""
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from scripts.h15_brc_upgrade_preflight import UpgradeDenied, admit, candidate_gate, current_gate, inspect, candidate_runtime_image

NEW="sha256:"+"2"*64
OLD="sha256:"+"1"*64
MANIFEST="sha256:"+"3"*64
COMMIT="b"*40
TAG="hermes-brc-relay-eval:"+COMMIT[:12]
def image():
    return {"Id":NEW,"Os":"linux","Architecture":"amd64", "RepoTags":[TAG],
            "Config":{"User":"65534:65534","Cmd":["node","packages/relay/dist/cli.js"],
              "Labels":{"org.opencontainers.image.revision":"cbe511702dd0147650353c29ac6ab1decd8afda1",
                        "org.opencontainers.image.licenses":"MIT"},
              "Env":["NODE_ENV=production"]}}
def current():
    return {"Name":"/hermes-brc-relay","Image":OLD,
            "State":{"Running":True,"Status":"running"},
            "Config":{"User":"979:975","Labels":{"com.hermes.scope":"h15-brc-owner-relay"},
                      "Env":["BRC_ADMIN_PASSWORD=must-not-leak"]},
            "HostConfig":{"NetworkMode":"hermes-brc-internal","Privileged":False,
                          "ReadonlyRootfs":True,"CapDrop":["ALL"],"CapAdd":None,
                          "PortBindings":{},"RestartPolicy":{"Name":"unless-stopped"},
                          "SecurityOpt":["no-new-privileges"],"PidsLimit":80,"Memory":536870912,
                          "Devices":None,"Binds":None},
            "NetworkSettings":{"Networks":{"hermes-brc-internal":{"IPAddress":"172.29.251.2"}}},
            "Mounts":[{"Type":"bind","Source":"/var/lib/hermes-brc-relay",
                       "Destination":"/state","RW":True}]}

class GateTests(unittest.TestCase):
    def test_good_old_and_new(self):
        self.assertEqual(current_gate(current(),NEW),OLD)
        candidate_gate(image(),NEW)
    def test_classic_config_id_is_pinned_without_archive_redecompression(self):
        with patch("scripts.h15_brc_upgrade_preflight.inspect",return_value=image()) as docker, \
             patch("scripts.h15_brc_upgrade_preflight.subprocess.Popen") as unzip:
            loaded, identity=candidate_runtime_image(Path("/safe"),NEW,COMMIT)
        self.assertEqual(identity,NEW)
        self.assertEqual(loaded["Id"],NEW)
        docker.assert_called_once_with(["image","inspect",TAG])
        unzip.assert_not_called()

    def test_containerd_manifest_id_must_match_verified_oci_archive(self):
        from unittest.mock import MagicMock
        stored={**image(),"Id":MANIFEST,
                "Descriptor":{"digest":MANIFEST,
                              "mediaType":"application/vnd.oci.image.manifest.v1+json"}}
        subprocess_result=MagicMock()
        subprocess_result.stdout=io.BytesIO(b"synthetic-oci-archive")
        subprocess_result.wait.return_value=0
        subprocess_result.poll.return_value=0
        with patch("scripts.h15_brc_upgrade_preflight.inspect",return_value=stored), \
             patch("scripts.h15_brc_upgrade_preflight.subprocess.Popen",return_value=subprocess_result) as p, \
             patch("scripts.h15_brc_upgrade_preflight.verify_loaded_tar",
                   return_value=(MANIFEST,"containerd_manifest")) as verifier:
            loaded, identity=candidate_runtime_image(Path("/trusted"),NEW,COMMIT)
        self.assertEqual(identity,MANIFEST)
        self.assertEqual(loaded["Id"],MANIFEST)
        self.assertEqual(p.call_args.args[0],
                         ["zstd","-dc","/trusted/brc-relay.docker.tar.zst"])
        self.assertEqual(verifier.call_args.args[2:],(NEW,TAG))

    def test_unverified_containerd_runtime_digest_cannot_pass(self):
        from unittest.mock import MagicMock
        stored={**image(),"Id":MANIFEST}
        p=MagicMock()
        p.stdout=io.BytesIO(b"synthetic-oci-archive")
        p.wait.return_value=0
        p.poll.return_value=0
        with patch("scripts.h15_brc_upgrade_preflight.inspect",return_value=stored), \
             patch("scripts.h15_brc_upgrade_preflight.subprocess.Popen",return_value=p), \
             patch("scripts.h15_brc_upgrade_preflight.verify_loaded_tar",
                   return_value=(NEW,"classic_config")):
            with self.assertRaisesRegex(UpgradeDenied,"runtime_oci_attestation_failed"):
                candidate_runtime_image(Path("/trusted"),NEW,COMMIT)

    def test_untrusted_runtime_tag_fails_before_archive_open(self):
        for actual in (None,"sha256:"+"c"*64):
            record={**image(),"RepoTags":["foreign:latest"],"Id":actual}
            with self.subTest(actual=actual), \
                 patch("scripts.h15_brc_upgrade_preflight.inspect",return_value=record), \
                 patch("scripts.h15_brc_upgrade_preflight.subprocess.Popen") as p:
                with self.assertRaisesRegex(UpgradeDenied,"candidate_runtime_tag_or_id_mismatch"):
                    candidate_runtime_image(Path("/trusted"),NEW,COMMIT)
                p.assert_not_called()

    def test_preflight_containerd_runtime_must_use_manifest_for_old_container_check(self):
        with patch("scripts.h15_brc_upgrade_preflight.verify",
                   return_value={"owner_agents_paired":False,"production_mcp_enabled":False}), \
             patch("scripts.h15_brc_upgrade_preflight.candidate_runtime_image",
                   return_value=({**image(),"Id":MANIFEST},MANIFEST)), \
             patch("scripts.h15_brc_upgrade_preflight.inspect",return_value=current()), \
             patch("scripts.h15_brc_upgrade_preflight.current_gate",return_value=OLD) as old_gate:
            result=admit(Path("/trusted"),NEW,"a"*64,COMMIT)
        self.assertEqual(result["candidate_image"],MANIFEST)
        self.assertEqual(result["ci_config_image_id"],NEW)
        self.assertEqual(old_gate.call_args.args[1],MANIFEST)

    def test_unowned_container(self):
        c=current();c["Config"]["Labels"]={}
        with self.assertRaisesRegex(UpgradeDenied,"foreign_container"):current_gate(c,NEW)
    def test_stopped_relay(self):
        c=current();c["State"]["Running"]=False
        with self.assertRaisesRegex(UpgradeDenied,"not_running"):current_gate(c,NEW)
    def test_same_image(self):
        with self.assertRaisesRegex(UpgradeDenied,"not_replaceable"):current_gate(current(),OLD)
    def test_extra_mount_denied(self):
        c=current();c["Mounts"].append({"Type":"bind","Source":"/root","Destination":"/host"})
        with self.assertRaisesRegex(UpgradeDenied,"mounts_not_single"):current_gate(c,NEW)
    def test_docker_real_no_new_privileges_true_accepted(self):
        c=current()
        c["HostConfig"]["SecurityOpt"]=["no-new-privileges:true"]
        self.assertEqual(current_gate(c,NEW),OLD)

    def test_disabled_no_new_privileges_denied(self):
        c=current()
        c["HostConfig"]["SecurityOpt"]=["no-new-privileges:false"]
        with self.assertRaisesRegex(UpgradeDenied,"security_contract"):
            current_gate(c,NEW)

    def test_privileged_denied(self):
        c=current();c["HostConfig"]["Privileged"]=True
        with self.assertRaisesRegex(UpgradeDenied,"security_contract"):current_gate(c,NEW)
    def test_wrong_network_denied(self):
        c=current();c["NetworkSettings"]["Networks"]["other"]={}
        with self.assertRaisesRegex(UpgradeDenied,"network_mismatch"):current_gate(c,NEW)
    def test_root_user_denied(self):
        c=current();c["Config"]["User"]="0:0"
        with self.assertRaisesRegex(UpgradeDenied,"host_scope"):current_gate(c,NEW)
    def test_candidate_revision_denied(self):
        c=image();c["Config"]["Labels"]["org.opencontainers.image.revision"]="random"
        with self.assertRaisesRegex(UpgradeDenied,"provenance"):candidate_gate(c,NEW)
    def test_baked_secret_denied(self):
        c=image();c["Config"]["Env"].append("BRC_TOKEN=bad")
        with self.assertRaisesRegex(UpgradeDenied,"baked_secret"):candidate_gate(c,NEW)
    def test_host_pid_or_ipc_namespace_denied(self):
        for field, value in (("PidMode", "host"), ("IpcMode", "host"), ("UsernsMode", "host")):
            with self.subTest(field=field):
                c=current();c["HostConfig"][field]=value
                with self.assertRaisesRegex(UpgradeDenied,"host_scope"):
                    current_gate(c,NEW)
    def test_untrusted_pins_before_docker(self):
        with patch("scripts.h15_brc_upgrade_preflight.inspect") as docker:
            with self.assertRaisesRegex(UpgradeDenied,"untrusted_pins"):
                admit(Path("/none"),"latest","a"*64,"b"*40)
            docker.assert_not_called()
    def test_unverified_archive_before_docker(self):
        with patch("scripts.h15_brc_upgrade_preflight.verify",side_effect=ValueError("bad")), \
             patch("scripts.h15_brc_upgrade_preflight.inspect") as docker:
            with self.assertRaisesRegex(UpgradeDenied,"bundle_not_verified"):
                admit(Path("/none"),NEW,"a"*64,"b"*40)
            docker.assert_not_called()
    def test_attested_read_only_pipeline_redacts_secrets(self):
        with patch("scripts.h15_brc_upgrade_preflight.verify",
                   return_value={"owner_agents_paired":False,"production_mcp_enabled":False}), \
             patch("scripts.h15_brc_upgrade_preflight.inspect",
                   side_effect=[image(),current()]) as docker:
            output=admit(Path("/none"),NEW,"a"*64,"b"*40)
            self.assertEqual(output["status"],"PREFLIGHT_PASS")
            self.assertFalse(output["changes_performed"])
            self.assertFalse(output["deployment_approved"])
            self.assertEqual(docker.call_count,2)
            self.assertNotIn("must-not-leak",json.dumps(output))
    def test_malformed_docker_inspection(self):
        p=type("Output",(),{"returncode":0,"stdout":"invalid","stderr":""})()
        with patch("scripts.h15_brc_upgrade_preflight.subprocess.run",return_value=p):
            with self.assertRaisesRegex(UpgradeDenied,"docker_inspect_malformed"):
                inspect(["container","inspect","x"])

if __name__=="__main__":unittest.main()
