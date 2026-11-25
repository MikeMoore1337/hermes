"""Offline onboarding creates only the requested new sandbox project."""
import hashlib
import io
import json
from pathlib import Path
import subprocess

import pytest

from scripts.h15_offline_project_install import install
from scripts import h15_offline_project_import as importer
from scripts.h15_offline_project_import import public_repository


def git(*args):
    p = subprocess.run(["git", *map(str, args)], check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return p.stdout.decode().strip()


@pytest.fixture
def package(tmp_path):
    parent = tmp_path / "projects"
    parent.mkdir()
    stage = tmp_path / ".h454-import-fixture"
    stage.mkdir()
    nonce = "a" * 32
    (stage / "marker").write_text(nonce)
    src = tmp_path / "source"
    src.mkdir()
    git("init", "-b", "main", src)
    git("-C", src, "config", "user.email", "fixture@example.invalid")
    git("-C", src, "config", "user.name", "Fixture")
    (src / "README").write_text("synthetic project")
    git("-C", src, "add", "README")
    git("-C", src, "commit", "-m", "fixture")
    head = git("-C", src, "rev-parse", "HEAD")
    bundle = stage / "repo.bundle"
    git("-C", src, "bundle", "create", bundle, "refs/heads/main")
    return dict(stage=stage, parent=parent, name="fixture", branch="main", head=head,
                checksum=hashlib.sha256(bundle.read_bytes()).hexdigest(), size=bundle.stat().st_size,
                origin="https://github.com/MikeMoore1337/fixture.git", nonce=nonce)


def test_verified_bundle_installs_clean_project(package):
    result = install(**package)
    target = package["parent"] / "fixture"
    assert result["status"] == "INSTALLED"
    assert git("-C", target, "rev-parse", "HEAD") == package["head"]
    assert git("-C", target, "status", "--porcelain") == ""
    assert git("-C", target, "remote", "get-url", "origin") == package["origin"]
    assert not (package["stage"] / "repo.bundle").exists()


def test_existing_project_is_never_overwritten(package):
    target = package["parent"] / "fixture"
    target.mkdir()
    (target / "existing").write_text("keep")
    with pytest.raises(FileExistsError):
        install(**package)
    assert (target / "existing").read_text() == "keep"


def test_corrupt_bundle_rejected_before_target_created(package):
    package["checksum"] = "0" * 64
    with pytest.raises(ValueError, match="bundle_checksum_invalid"):
        install(**package)
    assert not (package["parent"] / "fixture").exists()


@pytest.mark.parametrize("name", ["../vault", "repo.git", "-bad", "has space"])
def test_invalid_repository_name_rejected_without_network(name):
    with pytest.raises(ValueError, match="invalid_repository_name"):
        public_repository(name)


def test_private_repository_rejected(monkeypatch):
    payload = {"full_name": "MikeMoore1337/fixture", "private": True, "default_branch": "main"}
    monkeypatch.setattr(importer, "urlopen", lambda *args, **kwargs: io.BytesIO(json.dumps(payload).encode()))
    with pytest.raises(ValueError, match="repository_not_public_owner"):
        public_repository("fixture")


def test_multiple_windows_sandboxes_are_rejected(monkeypatch):
    monkeypatch.setattr(importer, "run", lambda *args, **kwargs: "container1\ncontainer2")
    with pytest.raises(ValueError, match="sandbox_not_unique"):
        importer.sandbox()
