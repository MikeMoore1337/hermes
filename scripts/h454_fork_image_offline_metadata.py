#!/usr/bin/env python3
"""H-454: source-only contract for a pinned fork relay OCI image record.

Inspect a supplied Docker image JSON record *without* opening Docker, files,
credentials or the production relay. This checks metadata consistency only;
it cannot independently attest build provenance, authorize a new runtime,
migrate SQLite or enable the legacy Hermes cutover operator.
"""
from __future__ import annotations

import re

IMAGE_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
SOURCE = "https://github.com/MikeMoore1337/hermes-remote-commander"
REQUIRED_ENV = {
    "NODE_ENV": "production",
    "PORT": "3000",
    "HOST": "0.0.0.0",
    "BRC_DB": "/data/relay.sqlite",
}
SECRET_ENV = frozenset({
    "BRC_ADMIN_PASSWORD", "BRC_SESSION_SECRET", "BRC_TOKEN",
    "BRC_DEVICE_ID", "GITHUB_TOKEN", "GH_TOKEN",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
})


class ForkImageDenied(ValueError):
    """No source, host path, secret, or environment values in refusal codes."""


def _deny(code: str) -> None:
    raise ForkImageDenied(code)


def verify_fork_image_metadata(image: dict, *, expected_image: str,
                               expected_source_commit: str) -> dict:
    """Fail-closed metadata precheck; independent digest evidence is required later."""
    if (not isinstance(expected_image, str) or not IMAGE_SHA.fullmatch(expected_image)
            or not isinstance(expected_source_commit, str)
            or not COMMIT_SHA.fullmatch(expected_source_commit)):
        _deny("UNTRUSTED_EXPECTED_IDENTITY")
    if (not isinstance(image, dict) or image.get("Id") != expected_image
            or image.get("Os") != "linux" or image.get("Architecture") != "amd64"):
        _deny("FORK_IMAGE_ID_OR_PLATFORM_MISMATCH")

    cfg = image.get("Config")
    if not isinstance(cfg, dict):
        _deny("FORK_CONFIG_MISSING")
    labels = cfg.get("Labels")
    if (not isinstance(labels, dict)
            or labels.get("org.opencontainers.image.source") != SOURCE
            or labels.get("org.opencontainers.image.revision") != expected_source_commit):
        _deny("FORK_SOURCE_LABEL_MISMATCH")
    if (cfg.get("User") != "rdp"
            or cfg.get("Cmd") != ["node", "dist/cli.js"]
            or cfg.get("WorkingDir") != "/app"):
        _deny("FORK_IMAGE_RUNTIME_MISMATCH")
    if cfg.get("Volumes") not in (None, {}):
        _deny("FORK_IMPLICIT_VOLUME_NOT_ALLOWED")
    exposed = cfg.get("ExposedPorts")
    if not isinstance(exposed, dict) or set(exposed) != {"3000/tcp"}:
        _deny("FORK_EXPOSED_PORT_MISMATCH")

    raw = cfg.get("Env")
    if not isinstance(raw, list):
        _deny("FORK_ENV_INVALID")
    env: dict[str, str] = {}
    for item in raw:
        if not isinstance(item, str) or "=" not in item:
            _deny("FORK_ENV_INVALID")
        name, value = item.split("=", 1)
        if not name or name.upper() in SECRET_ENV or name.upper() in env:
            _deny("FORK_ENV_FORBIDDEN_OR_DUPLICATED")
        env[name.upper()] = value
    if any(env.get(name) != val for name, val in REQUIRED_ENV.items()):
        _deny("FORK_ENV_RUNTIME_MISMATCH")

    return {
        "status": "OFFLINE_IMAGE_METADATA_MATCH_ONLY",
        "fork_source_commit": expected_source_commit,
        "candidate_image_id": expected_image,
        "legacy_hermes_operator_compatible": False,
        "sqlite_migration_verified": False,
        "owner_production_cutover_authorized": False,
    }
