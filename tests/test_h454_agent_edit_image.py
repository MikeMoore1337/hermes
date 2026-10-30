"""Offline invariants for one-layer image preparation; no live Docker calls."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_agent_edit_image as image

BEFORE = b"""function edit() {
    if (count > 0 && count !== expectedReplacements) {
        return {
            content: [{type: 'text', text: 'mismatch'}],
        };
    }
    return writeReplacement();
}
"""


class AgentEditImageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / ".artifacts/candidate"
        root_patch = patch.object(image, "ROOT", self.root)
        hash_patch = patch.object(image, "BEFORE_SHA256", hashlib.sha256(BEFORE).hexdigest())
        root_patch.start()
        hash_patch.start()
        self.addCleanup(root_patch.stop)
        self.addCleanup(hash_patch.stop)
        self.after = image.patched_module(BEFORE)
        self.labels = image.patch_labels(self.after)
        self.base = {"Id": image.BASE_IMAGE, "Config": {
            "User": "65534:65534", "Env": ["BRC_HOME=/run/brc"],
            "Entrypoint": ["/usr/local/bin/h15-agent-entrypoint.sh"],
            "Cmd": ["agent"], "WorkingDir": "/app", "Labels": {"scope": "preserve"},
        }, "RootFS": {"Layers": ["sha256:" + "1" * 64]}}
        self.candidate = copy.deepcopy(self.base)
        self.candidate["Id"] = "sha256:" + "2" * 64
        self.candidate["Config"]["Labels"].update(self.labels)
        self.candidate["RootFS"]["Layers"].append("sha256:" + "3" * 64)

    def test_unknown_module_bytes_are_refused(self):
        with self.assertRaisesRegex(image.ImageHold, "BASE_MODULE_HASH"):
            image.patched_module(BEFORE + b"unreviewed")

    def test_only_the_conflict_flag_changes(self):
        self.assertEqual(self.after, BEFORE.replace(
            b"        return {\n", b"        return {\n            isError: true,\n"))
        self.assertIn(b"return writeReplacement();", self.after)

    def test_inherited_runtime_config_and_one_layer_are_required(self):
        image.verify_image(self.base, self.candidate, self.labels)
        for key in ("User", "Env", "Entrypoint", "Cmd", "WorkingDir", "Healthcheck"):
            changed = copy.deepcopy(self.candidate)
            changed["Config"][key] = "unapproved"
            with self.subTest(key=key), self.assertRaisesRegex(image.ImageHold, "IMAGE_CONFIG_DRIFT"):
                image.verify_image(self.base, changed, self.labels)

    def test_changed_base_layers_and_extra_layers_are_refused(self):
        for layers in (["wrong", "extra"], self.candidate["RootFS"]["Layers"] + ["extra"]):
            changed = copy.deepcopy(self.candidate)
            changed["RootFS"]["Layers"] = layers
            with self.assertRaisesRegex(image.ImageHold, "IMAGE_LAYER_DRIFT"):
                image.verify_image(self.base, changed, self.labels)

    def test_unapproved_labels_and_invalid_image_id_are_refused(self):
        changed = copy.deepcopy(self.candidate)
        changed["Config"]["Labels"]["unapproved"] = "value"
        with self.assertRaisesRegex(image.ImageHold, "IMAGE_CONFIG_DRIFT"):
            image.verify_image(self.base, changed, self.labels)
        changed = copy.deepcopy(self.candidate)
        changed["Id"] = "--privileged"
        with self.assertRaisesRegex(image.ImageHold, "CANDIDATE_ID"):
            image.verify_image(self.base, changed, self.labels)

    def test_existing_output_and_outside_workspace_are_refused(self):
        self.output.mkdir(parents=True)
        marker = self.output / "preserve.txt"
        marker.write_text("preserve")
        with self.assertRaisesRegex(image.ImageHold, "OUTPUT_EXISTS"):
            image.output_directory(self.output)
        with self.assertRaisesRegex(image.ImageHold, "OUTPUT_SCOPE"):
            image.output_directory(self.root / "outside")
        self.assertEqual(marker.read_text(), "preserve")

    def test_reparse_output_is_refused_before_resolution(self):
        with patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaisesRegex(image.ImageHold, "OUTPUT_REPARSE"):
                image.output_directory(self.output)

    def invoke(self, *, build, tags="", pipe=image.PIPE):
        calls = []
        def docker(_binary, *args, **_kwargs):
            calls.append(args)
            if args[:2] == ("context", "inspect"):
                return json.dumps([{"Endpoints": {"docker": {"Host": pipe}}}]).encode()
            if args[:2] == ("image", "ls"):
                return tags.encode()
            if args[0] == "build":
                return b""
            self.fail("unexpected Docker operation")
        with patch.object(image, "docker", side_effect=docker), \
             patch.object(image, "inspect", side_effect=lambda _b, target: self.base if target == image.BASE_TAG else self.candidate), \
             patch.object(image, "read_module", side_effect=lambda _b, target: BEFORE if target == image.BASE_IMAGE else self.after), \
             patch.object(image, "smoke") as smoke:
            result = image.prepare(Path("fixture-docker.exe"), self.output, build=build)
        return result, calls, smoke

    def test_plan_has_no_build_or_output_mutation(self):
        result, calls, smoke = self.invoke(build=False)
        self.assertEqual(result["status"], "PLAN")
        self.assertFalse(result["activation_performed"])
        self.assertFalse(self.output.exists())
        self.assertFalse(any(call[0] == "build" for call in calls))
        smoke.assert_not_called()

    def test_build_writes_only_one_copy_and_preserves_no_activation(self):
        result, calls, smoke = self.invoke(build=True)
        self.assertEqual(result["status"], "CANDIDATE_BUILT_AND_TESTED")
        self.assertFalse(result["activation_performed"])
        self.assertEqual((self.output / "edit.js").read_bytes(), self.after)
        dockerfile = (self.output / "Dockerfile").read_text()
        self.assertEqual(dockerfile.count("COPY "), 1)
        self.assertNotIn("RUN ", dockerfile)
        self.assertNotIn("USER ", dockerfile)
        self.assertNotIn("ENTRYPOINT ", dockerfile)
        self.assertNotIn("ENV ", dockerfile)
        self.assertIn("--pull=false", next(call for call in calls if call[0] == "build"))
        smoke.assert_called_once()

    def test_occupied_candidate_tag_is_not_overwritten(self):
        with self.assertRaisesRegex(image.ImageHold, "CANDIDATE_TAG_OCCUPIED"):
            self.invoke(build=True, tags=image.CANDIDATE_TAG)
        self.assertFalse(self.output.exists())

    def test_remote_context_is_refused_before_build(self):
        with self.assertRaisesRegex(image.ImageHold, "LOCAL_DOCKER_REQUIRED"):
            self.invoke(build=True, pipe="tcp://example.invalid:2375")
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
