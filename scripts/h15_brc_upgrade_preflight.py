#!/usr/bin/env python3
"""H15 #454. Read-only, fail-closed BRC owner relay OCI upgrade preflight."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import subprocess
from scripts.h15_brc_offline_image_bundle import verify, BundleDenied

IMAGE = re.compile(r"sha256:[a-f0-9]{64}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
COMMIT = re.compile(r"[a-f0-9]{40}\Z")
UPSTREAM = "cbe511702dd0147650353c29ac6ab1decd8afda1"

class UpgradeDenied(ValueError):
    pass

def deny(code: str):
    raise UpgradeDenied(code)

def inspect(command: list[str]) -> dict:
    # The docker inspect JSON contains production environment secrets. NEVER print.
    try:
        process = subprocess.run(["docker", *command], capture_output=True,
                                 text=True, check=False, timeout=12)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpgradeDenied("docker_unavailable") from exc
    if process.returncode or len(process.stdout) > 250000:
        deny("docker_inspect_failed")
    try:
        result = json.loads(process.stdout)
    except ValueError as exc:
        raise UpgradeDenied("docker_inspect_malformed") from exc
    if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
        deny("docker_inspect_shape")
    return result[0]

def candidate_gate(image: dict, expected: str):
    if (image.get("Id") != expected or image.get("Os") != "linux"
            or image.get("Architecture") != "amd64"):
        deny("candidate_image_mismatch")
    cfg = image.get("Config") or {}
    labels = cfg.get("Labels") or {}
    if (labels.get("org.opencontainers.image.revision") != UPSTREAM
            or labels.get("org.opencontainers.image.licenses") != "MIT"
            or cfg.get("User") != "65534:65534"
            or cfg.get("Cmd") != ["node", "packages/relay/dist/cli.js"]):
        deny("candidate_runtime_or_provenance")
    env = cfg.get("Env")
    secrets = {"BRC_ADMIN_PASSWORD", "BRC_SESSION_SECRET", "BRC_TOKEN", "BRC_DEVICE_ID", "GH_TOKEN", "GITHUB_TOKEN"}
    if not isinstance(env, list) or any(not isinstance(s, str) or "=" not in s
            or s.split("=", 1)[0].upper() in secrets for s in env):
        deny("candidate_baked_secret_or_env")

def current_gate(container: dict, candidate_id: str) -> str:
    cfg = container.get("Config") or {}
    host = container.get("HostConfig") or {}
    nets = (container.get("NetworkSettings") or {}).get("Networks") or {}
    state = container.get("State") or {}
    mounts = container.get("Mounts")
    old = container.get("Image")
    if (container.get("Name") != "/hermes-brc-relay"
            or (cfg.get("Labels") or {}).get("com.hermes.scope") != "h15-brc-owner-relay"):
        deny("foreign_container")
    if state.get("Running") is not True or state.get("Status") != "running":
        deny("relay_not_running")
    if not isinstance(old, str) or not IMAGE.fullmatch(old) or old == candidate_id:
        deny("relay_image_not_replaceable")
    if (host.get("NetworkMode") != "hermes-brc-internal"
            or host.get("Privileged") is not False or host.get("ReadonlyRootfs") is not True
            or host.get("CapDrop") != ["ALL"] or host.get("CapAdd") not in (None, [])
            or host.get("PortBindings") not in (None, {})
            or (host.get("RestartPolicy") or {}).get("Name") != "unless-stopped"
            or "no-new-privileges" not in (host.get("SecurityOpt") or [])):
        deny("relay_security_contract_mismatch")
    if (set(nets) != {"hermes-brc-internal"}
            or nets["hermes-brc-internal"].get("IPAddress") != "172.29.251.2"):
        deny("relay_network_mismatch")
    if not isinstance(mounts, list) or len(mounts) != 1:
        deny("relay_mounts_not_single")
    m = mounts[0]
    if (m.get("Type") != "bind" or m.get("Source") != "/var/lib/hermes-brc-relay"
            or m.get("Destination") != "/state" or m.get("RW") is not True):
        deny("relay_state_mount_mismatch")
    if (not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", str(cfg.get("User", "")))
            or host.get("Devices") not in (None, [])
            or host.get("Binds") not in (None, [])
            or host.get("PidMode") not in (None, "")
            or host.get("IpcMode") == "host"
            or host.get("UsernsMode") == "host"):
        deny("relay_host_scope_mismatch")
    if (type(host.get("PidsLimit")) is not int or not 1 <= host["PidsLimit"] <= 128
            or type(host.get("Memory")) is not int or not 128*1024*1024 <= host["Memory"] <= 1024*1024*1024):
        deny("relay_resource_scope_mismatch")
    return old

def admit(bundle: Path, image: str, archive_sha: str, hermes_sha: str) -> dict:
    if not IMAGE.fullmatch(image) or not HEX.fullmatch(archive_sha) or not COMMIT.fullmatch(hermes_sha):
        deny("untrusted_pins")
    try:
        receipt = verify(directory=bundle, expected_archive_sha=archive_sha,
                         expected_image_id=image, expected_hermes_sha=hermes_sha)
    except (BundleDenied, OSError, ValueError, KeyError) as exc:
        raise UpgradeDenied("bundle_not_verified") from exc
    candidate_gate(inspect(["image", "inspect", image]), image)
    old = current_gate(inspect(["container", "inspect", "hermes-brc-relay"]), image)
    if receipt.get("owner_agents_paired") is not False or receipt.get("production_mcp_enabled") is not False:
        deny("offline_receipt_wrong_scope")
    return {"status":"PREFLIGHT_PASS", "current_image": old, "candidate_image": image,
            "hermes_commit": hermes_sha, "bundle_verified":True,
            "secrets_displayed":False, "live_rollback_tested":False,
            "changes_performed":False, "deployment_approved":False}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bundle-dir",type=Path,required=True)
    p.add_argument("--candidate-image",required=True)
    p.add_argument("--expected-archive-sha",required=True)
    p.add_argument("--expected-hermes-sha",required=True)
    args=p.parse_args(argv)
    try:
        result=admit(args.bundle_dir,args.candidate_image,args.expected_archive_sha,args.expected_hermes_sha)
    except UpgradeDenied as exc:
        print(json.dumps({"status":"REFUSED","reason":str(exc)}))
        return 2
    print(json.dumps(result,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
