"""Offline source and Docker-identity refusal tests for H15 upgrade gate."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from scripts.h15_brc_upgrade_preflight import UpgradeDenied, admit, candidate_gate, current_gate, inspect

NEW="sha256:"+"2"*64
OLD="sha256:"+"1"*64
def image():
    return {"Id":NEW,"Os":"linux","Architecture":"amd64",
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
