#!/usr/bin/env python3
"""H15 #454. Read-only, fail-closed BRC owner relay OCI upgrade preflight."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import subprocess
import tarfile
from scripts.h15_brc_offline_image_bundle import verify, BundleDenied
from scripts.h15_brc_loaded_identity import verify_loaded_tar, LoadedImageDenied

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

def candidate_runtime_image(bundle: Path, config_id: str, hermes_sha: str) -> tuple[dict, str]:
    """Resolve verified Docker runtime ID from independently pinned OCI config.

    Classic Docker uses the config digest; containerd may use the manifest
    digest. In the latter case, reverify the imported tag, config, descriptors
    and rootfs layers against the independently pinned offline OCI archive.
    """
    tag = f"hermes-brc-relay-eval:{hermes_sha[:12]}"
    image = inspect(["image", "inspect", tag])
    actual = image.get("Id")
    if image.get("RepoTags") != [tag] or not isinstance(actual, str) or not IMAGE.fullmatch(actual):
        deny("candidate_runtime_tag_or_id_mismatch")
    if actual == config_id:
        return image, actual

    try:
        proc = subprocess.Popen(
            ["zstd", "-dc", str(bundle / "brc-relay.docker.tar.zst")],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise UpgradeDenied("runtime_oci_attestation_unavailable") from exc
    try:
        if proc.stdout is None:
            deny("runtime_oci_attestation_unavailable")
        verified_id, style = verify_loaded_tar(proc.stdout, image, config_id, tag)
        if proc.wait(timeout=60) != 0:
            deny("runtime_oci_attestation_failed")
        if verified_id != actual or style != "containerd_manifest":
            deny("runtime_oci_attestation_failed")
    except (LoadedImageDenied, KeyError, OSError, ValueError, tarfile.TarError,
            subprocess.TimeoutExpired) as exc:
        raise UpgradeDenied("runtime_oci_attestation_failed") from exc
    finally:
        if proc.stdout is not None:
            proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
        proc.wait()
    return image, actual


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
            or not isinstance(host.get("SecurityOpt"), list)
            or not host["SecurityOpt"]
            or any(flag not in ("no-new-privileges", "no-new-privileges:true")
                   for flag in host["SecurityOpt"])):
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
    imported, runtime_id = candidate_runtime_image(bundle, image, hermes_sha)
    candidate_gate(imported, runtime_id)
    old = current_gate(inspect(["container", "inspect", "hermes-brc-relay"]), runtime_id)
    if receipt.get("owner_agents_paired") is not False or receipt.get("production_mcp_enabled") is not False:
        deny("offline_receipt_wrong_scope")
    return {"status":"PREFLIGHT_PASS", "current_image": old, "candidate_image": runtime_id,
            "ci_config_image_id": image, "hermes_commit": hermes_sha, "bundle_verified":True,
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
