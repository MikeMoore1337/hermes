"""Import one public GitHub repository into the Windows sandbox without sandbox egress."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
from urllib.request import Request, urlopen

OWNER = "MikeMoore1337"
SCOPE = "h15-windows-owner-permanent"
MAX_BUNDLE = 100 * 1024 * 1024
MAX_REPOSITORY_SIZE_KB = 100 * 1024


def run(*args: str, timeout: int = 120) -> str:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update(GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="Never", GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0")
    p = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       env=env, timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if p.returncode:
        raise ValueError("command_failed: " + args[0])
    return p.stdout.decode("utf-8", "strict").strip()


def repository_parts(value: str) -> tuple[str, str]:
    parts = value.split('/') if isinstance(value, str) else []
    if len(parts) == 1:
        parts.insert(0, OWNER)
    if (len(parts) != 2 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", parts[0])
            or '--' in parts[0] or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,99}", parts[1])
            or '..' in parts[1] or parts[1].lower().endswith('.git')):
        raise ValueError("invalid_repository_name")
    return parts[0], parts[1]


def workspace_name(repository: str, requested: str | None = None) -> str:
    name = requested if requested is not None else re.sub(r'[^a-z0-9-]+', '-', repository.lower()).strip('-')
    if requested is None and name and not name[0].isalpha():
        name = 'project-' + name
    if not re.fullmatch(r'[a-z][a-z0-9-]{1,79}', name):
        raise ValueError('invalid_workspace_name')
    return name


def public_repository(value: str) -> tuple[str, str]:
    owner, name = repository_parts(value)
    request = Request(f"https://api.github.com/repos/{owner}/{name}", headers={"User-Agent": "Hermes-Commander-offline-import"})
    with urlopen(request, timeout=20) as response:
        metadata = json.loads(response.read(1024 * 1024))
    if metadata.get("private") is not False or metadata.get("full_name", "").lower() != f"{owner}/{name}".lower():
        raise ValueError("repository_not_public_owner")
    if (type(metadata.get('size')) is not int or not 0 <= metadata['size'] <= MAX_REPOSITORY_SIZE_KB):
        raise ValueError('repository_size_not_allowed')
    branch = metadata.get("default_branch")
    if not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", branch) or ".." in branch:
        raise ValueError("invalid_default_branch")
    return f"https://github.com/{owner}/{name}.git", branch


def sandbox() -> str:
    ids = run("docker", "ps", "-q", "--filter", f"label=com.hermes.scope={SCOPE}").splitlines()
    if len(ids) != 1:
        raise ValueError("sandbox_not_unique")
    container = json.loads(run("docker", "inspect", ids[0]))[0]
    if (not container["State"]["Running"] or container["Config"]["User"] != "65534:65534"
            or container["Config"]["Labels"].get("com.hermes.scope") != SCOPE
            or not any(m.get("Destination") == "/workspace" and m.get("RW") for m in container["Mounts"])):
        raise ValueError("sandbox_contract_invalid")
    return container["Id"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repository", help="Public GitHub repository as owner/name (or existing owner repository name)")
    ap.add_argument("--workspace", help="Optional sandbox workspace name")
    args = ap.parse_args()
    try:
        _owner, repository = repository_parts(args.repository)
        name = workspace_name(repository, args.workspace)
        origin, branch = public_repository(args.repository)
        container = sandbox()
        nonce = secrets.token_hex(16)
        stage = "/workspace/.h454-import-" + nonce
        with tempfile.TemporaryDirectory(prefix="h454-public-import-") as temp:
            repo, bundle = Path(temp) / "source.git", Path(temp) / "repo.bundle"
            git = lambda *a: run("git", "-c", "core.fsmonitor=false", "-c", "credential.helper=", *map(str, a))
            git("clone", "--bare", "--single-branch", "--branch", branch, "--", origin, repo)
            head = git("-C", repo, "rev-parse", "refs/heads/" + branch)
            if not re.fullmatch(r"[0-9a-f]{40}", head) or git("ls-remote", "--exit-code", "--", origin, "refs/heads/" + branch).split()[0] != head:
                raise ValueError("remote_changed")
            git("-C", repo, "bundle", "create", bundle, "refs/heads/" + branch)
            git("-C", repo, "bundle", "verify", bundle)
            size = bundle.stat().st_size
            if size > MAX_BUNDLE:
                raise ValueError("bundle_too_large")
            with bundle.open("rb") as f:
                checksum = hashlib.file_digest(f, "sha256").hexdigest()
            prepare = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.mkdir(mode=0o700); (p/'marker').write_text(sys.argv[2])"
            run("docker", "exec", "--user", "65534:65534", container, "python3", "-c", prepare, stage, nonce)
            run("docker", "cp", str(bundle), container + ":" + stage + "/repo.bundle")
            installer = Path(__file__).with_name("h15_offline_project_install.py")
            run("docker", "cp", str(installer), container + ":" + stage + "/install.py")
            args = json.dumps(dict(stage=stage, name=name, branch=branch, head=head, sha256=checksum,
                                   size=size, origin=origin, nonce=nonce), separators=(",", ":"))
            output = run("docker", "exec", "--user", "65534:65534", container, "python3", stage + "/install.py", args)
            result = json.loads(output)
            if result.get("status") != "INSTALLED":
                raise ValueError("installation_not_verified")
            cleanup = "import pathlib,sys; p=pathlib.Path(sys.argv[1]); (p/'install.py').unlink(); p.rmdir()"
            run("docker", "exec", "--user", "65534:65534", container, "python3", "-c", cleanup, stage)
            print(json.dumps(result, sort_keys=True))
            return 0
    except (OSError, ValueError, KeyError, IndexError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "HOLD", "reason": str(exc) if type(exc) is ValueError else type(exc).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
