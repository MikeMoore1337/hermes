"""Prepare/test one local immutable agent layer; never activate a device."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from scripts.h15_brc_apply_policy_patch import edit_conflict_errors
from scripts.h15_remote_commander_candidate_audit import AuditError

ROOT = Path(__file__).resolve().parents[1]
SMOKE = Path(__file__).with_name("h454_agent_edit_image_smoke.mjs")
BASE_IMAGE = "sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3"
BASE_TAG = "hermes-h15-brc-devtools:20261021"
CANDIDATE_TAG = "hermes-h454-edit-candidate:01b9573b"
MODULE = "/app/dist/core/tools/edit.js"
BEFORE_SHA256 = "45e3aaf22d1d06e657903cd0da90c9c350277e4a0be0dc610b7074a6287a50e7"
FIX_SOURCE = "01b9573b36ed3c192ad0a761de0b9480e6d07815"
CONTEXT = "desktop-linux"
PIPE = "npipe:////./pipe/dockerDesktopLinuxEngine"


class ImageHold(ValueError):
    pass


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise ImageHold(reason)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patched_module(data: bytes) -> bytes:
    need(digest(data) == BEFORE_SHA256, "BASE_MODULE_HASH")
    return edit_conflict_errors(data.decode("utf-8")).encode("utf-8")


def patch_labels(after: bytes) -> dict[str, str]:
    return {"com.hermes.h454.edit-source": FIX_SOURCE,
            "com.hermes.h454.edit-before": BEFORE_SHA256,
            "com.hermes.h454.edit-after": digest(after)}


def verify_image(base: dict, candidate: dict, labels: dict) -> None:
    need(base.get("Id") == BASE_IMAGE, "BASE_ID")
    need(isinstance(candidate.get("Id"), str) and
         re.fullmatch(r"sha256:[0-9a-f]{64}", candidate["Id"]) is not None and candidate["Id"] != BASE_IMAGE,
         "CANDIDATE_ID")
    expected = copy.deepcopy(base.get("Config"))
    need(isinstance(expected, dict), "IMAGE_CONFIG")
    inherited = expected.get("Labels") or {}
    need(not (set(inherited) & set(labels)), "PATCH_LABEL_COLLISION")
    expected["Labels"] = {**inherited, **labels}
    need(candidate.get("Config") == expected, "IMAGE_CONFIG_DRIFT")
    old_layers = (base.get("RootFS") or {}).get("Layers")
    new_layers = (candidate.get("RootFS") or {}).get("Layers")
    need(isinstance(old_layers, list) and bool(old_layers) and
         isinstance(new_layers, list) and len(new_layers) == len(old_layers) + 1
         and new_layers[:-1] == old_layers, "IMAGE_LAYER_DRIFT")


def output_directory(path: Path) -> Path:
    for item in (path, *path.parents):
        need(not item.is_symlink() and not (
            hasattr(item, "is_junction") and item.is_junction()), "OUTPUT_REPARSE")
    resolved = path.resolve()
    need(resolved.is_relative_to((ROOT / ".artifacts").resolve())
         and resolved != (ROOT / ".artifacts").resolve(), "OUTPUT_SCOPE")
    need(not resolved.exists(), "OUTPUT_EXISTS")
    return resolved


def docker(binary: Path, *arguments: str, timeout: int = 20) -> bytes:
    env = dict(os.environ)
    for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        env.pop(key, None)
    result = subprocess.run([str(binary), "--context", CONTEXT, *arguments],
                            capture_output=True, timeout=timeout, check=False, env=env)
    need(result.returncode == 0, "DOCKER_COMMAND_REFUSED")
    need(len(result.stdout) < 2_097_152, "DOCKER_OUTPUT_LIMIT")
    return result.stdout


def inspect(binary: Path, image: str) -> dict:
    values = json.loads(docker(binary, "image", "inspect", image))
    need(isinstance(values, list) and len(values) == 1 and isinstance(values[0], dict), "IMAGE_INSPECT")
    return values[0]


def read_module(binary: Path, image: str) -> bytes:
    program = ("import base64,json;from pathlib import Path;"
               f"p=Path({MODULE!r});s=p.stat();"
               "assert not p.is_symlink() and (s.st_uid,s.st_gid,s.st_mode&511)==(65534,65534,420);"
               "print(json.dumps({'data':base64.b64encode(p.read_bytes()).decode()}))")
    raw = docker(binary, "run", "--rm", "--pull", "never", "--network", "none", "--init",
                 "--read-only", "--user", "65534:65534", "--cap-drop", "ALL",
                 "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "128m",
                 "--cpus", "1", "--entrypoint", "/usr/bin/python3", image, "-I", "-B", "-c", program)
    value = json.loads(raw)
    need(isinstance(value, dict) and set(value) == {"data"}, "MODULE_RECEIPT")
    return base64.b64decode(value["data"], validate=True)


def smoke(binary: Path, image: str) -> None:
    source = SMOKE.read_text(encoding="utf-8")
    output = docker(binary, "run", "--rm", "--pull", "never", "--network", "none", "--init",
                    "--read-only", "--user", "65534:65534", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "512m",
                    "--cpus", "1", "--tmpfs", "/workspace:rw,nosuid,nodev,noexec,uid=65534,gid=65534,mode=0700,size=8m",
                    "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,uid=65534,gid=65534,mode=0700,size=16m",
                    "--env", "BRC_HOME=/workspace/.h454-smoke", "--workdir", "/workspace",
                    "--entrypoint", "/usr/local/bin/node", image, "--input-type=module", "-e", source,
                    timeout=40)
    need(b"H454_EDIT_IMAGE_SMOKE=PASS" in output.splitlines(), "IMAGE_SMOKE")


def prepare(binary: Path, output: Path, *, build: bool) -> dict:
    contexts = json.loads(docker(binary, "context", "inspect", CONTEXT))
    need(isinstance(contexts, list) and len(contexts) == 1 and
         contexts[0].get("Endpoints", {}).get("docker", {}).get("Host") == PIPE, "LOCAL_DOCKER_REQUIRED")
    base = inspect(binary, BASE_TAG)
    need(base.get("Id") == BASE_IMAGE, "BASE_TAG_DRIFT")
    before = read_module(binary, BASE_IMAGE)
    after = patched_module(before)
    receipt = {"status": "PLAN", "base_image": BASE_IMAGE, "fix_source": FIX_SOURCE,
               "module": MODULE, "before_sha256": digest(before), "after_sha256": digest(after),
               "builder_sha256": digest(Path(__file__).read_bytes()),
               "policy_patch_sha256": digest(Path(__file__).with_name("h15_brc_apply_policy_patch.py").read_bytes()),
               "smoke_sha256": digest(SMOKE.read_bytes()), "activation_performed": False}
    if not build:
        return receipt
    destination = output_directory(output)
    # Refuse an occupied candidate tag, rather than replacing somebody's build.
    tags = docker(binary, "image", "ls", "--format", "{{.Repository}}:{{.Tag}}").decode().splitlines()
    need(CANDIDATE_TAG not in tags, "CANDIDATE_TAG_OCCUPIED")
    destination.mkdir(parents=True)
    (destination / "edit.js").write_bytes(after)
    labels = patch_labels(after)
    dockerfile = (f"FROM {BASE_TAG}\n" +
                  f"COPY --chown=65534:65534 --chmod=0644 edit.js {MODULE}\n" +
                  "".join(f'LABEL {key}="{value}"\n' for key, value in labels.items()))
    (destination / "Dockerfile").write_text(dockerfile, encoding="utf-8")
    docker(binary, "build", "--pull=false", "--network", "none", "--tag", CANDIDATE_TAG,
           str(destination), timeout=90)
    candidate = inspect(binary, CANDIDATE_TAG)
    verify_image(base, candidate, labels)
    need(read_module(binary, candidate["Id"]) == after, "BUILT_MODULE_DRIFT")
    smoke(binary, candidate["Id"])
    receipt.update(status="CANDIDATE_BUILT_AND_TESTED", image_id=candidate["Id"],
                   smoke="PASS", config_parity="PASS", inherited_layers="PASS")
    (destination / "manifest.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / ".artifacts/h454-edit-image-01b9573b")
    args = parser.parse_args()
    try:
        need(os.name == "nt", "OWNER_WINDOWS_REQUIRED")
        binary = Path(os.environ.get("ProgramFiles", "")) / "Docker/Docker/resources/bin/docker.exe"
        need(binary.is_file() and not binary.is_symlink(), "DOCKER_UNAVAILABLE")
        print(json.dumps(prepare(binary, args.output, build=args.build)))
    except (ImageHold, AuditError, OSError, ValueError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, (ImageHold, AuditError)) else "PREPARATION_UNAVAILABLE"
        print(json.dumps({"status": "HOLD", "reason": reason, "activation_performed": False}))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
