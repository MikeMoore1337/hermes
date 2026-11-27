"""Compose the pinned private transport, durable journal and Linux worker.

Only a trusted local supervisor may select the device, project and bundle.
This module does not install a service, provision state or pair a device.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from device_fabric import linux_personal_status, linux_personal_worker
from device_fabric import native_private_tls as private
from device_fabric import windows_personal_commander_bundle as bundle_check
from device_fabric.linux_native_replay import LinuxReadReplay


class PersonalLinuxRuntimeDenied(ValueError):
    """Sanitized runtime failure without local state or credentials."""


def run_once(*, target: str, device_id: str, bearer: str, project: str, bundle: str,
             expected_manifest: bytes, bundle_sha256: str, trust_release_sha: str,
             journal: Path, websocket_connect: Callable[..., Any]) -> str:
    """Run one session using current-bearer status and a persistent call log.

    The caller must load these arguments from root-owned trusted local state,
    and ensure the service identity cannot modify the runtime bundle or trust.
    """
    replay = None
    try:
        if (target not in ('hermes-vps', 'yfc-vps') or type(project) is not str or
            type(bundle) is not str or not isinstance(journal, Path) or not journal.is_absolute() or
            not callable(websocket_connect) or not os.path.isabs(project) or not os.path.isabs(bundle) or
            os.path.commonpath((project, str(journal))) == project or
            os.path.commonpath((bundle, str(journal))) == bundle):
            raise ValueError()
        trust = private.load_private_relay(target, trust_release_sha)
        connector = private.private_websocket_connector(trust, websocket_connect)
        replay = LinuxReadReplay(journal)
        def active() -> bool:
            return linux_personal_status.bearer_state(trust, target=target, device_id=device_id,
                                                       bearer=bearer) is True
        def verified() -> bool:
            return bundle_check.verify(Path(bundle), expected_manifest, bundle_sha256) == bundle_sha256
        return linux_personal_worker.serve_once(target=target, device_id=device_id, bearer=bearer,
            project=project, bundle=bundle, connector=connector, is_active=active,
            claim_call=replay.claim, verify_bundle=verified)
    except Exception:
        raise PersonalLinuxRuntimeDenied('personal_linux_runtime_denied') from None
    finally:
        if replay is not None:
            replay.close()
