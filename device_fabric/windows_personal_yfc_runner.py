"""Compose the owner-selected YFC PSEC device without installing it.

The caller supplies owner identity, private TLS/status and a durable replay
journal. Project scans are point-in-time checks, not a lock against changes.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import time
from typing import Any, Callable

from device_fabric import windows_personal_commander_bundle as bundle
from device_fabric import windows_personal_commander_config as config
from device_fabric import windows_personal_commander_worker as worker
from device_fabric.windows_personal_appcontainer_pipe import PersonalAppContainerPipe
from device_fabric.windows_personal_project_scan import scan
from device_fabric.windows_personal_project_import import PublicProjectImport
from device_fabric.windows_personal_terminal_sessions import PersonalTerminalSessions
from device_fabric.windows_personal_yfc_psec import APP_NAME, GIT_ROOT, YFC_DEV, YfcDevPsecTerminal

SEARCH_MANAGER_SHA256 = "14bd3140d7e239d2e84f80d2dbe987cc86755243ca9f59590fb5dad816097f5f"


class YfcRunnerDenied(ValueError):
    """Constant refusal without local paths, credentials or process output."""


def _quote(path: Path) -> str:
    value = str(path)
    if (not path.is_absolute() or not value or len(value) > 2048
        or any(char in value for char in '\0\r\n"%!?&|<>^')):
        raise YfcRunnerDenied("yfc_runner_denied")
    return '"' + value + '"'


def run(raw_config: bytes, *, ca: bytes, expected_manifest: bytes,
        current_sid: Callable[[], str], connector: Callable[..., Any],
        status_factory: Callable[[str, str], Callable[[], bool | None]],
        claim_call: Callable[[str], bool], attach_job: Callable[[], None],
        pause: Callable[[float], Any] = time.sleep,
        decrypt: Callable[..., str] | None = None) -> str:
    """Run one bounded personal device worker in a dedicated process.

    The caller must initialize the durable journal and attach the dedicated
    worker to a kill-on-close job. This function never installs or pairs it.
    """
    probe = None
    try:
        if (not all(callable(item) for item in
                (current_sid, connector, status_factory, claim_call, attach_job, pause))
            or (decrypt is not None and not callable(decrypt))):
            raise ValueError()
        candidate = config.parse_config(raw_config)
        if candidate.profile != "yfc-dev":
            raise ValueError()
        app_data = os.environ.get("LOCALAPPDATA", "")
        if os.name != "nt" or not os.path.isabs(app_data):
            raise ValueError()
        base = Path(app_data) / APP_NAME
        release, state = base / "release", base / "adapter-state"
        node = release / "runner" / "node.exe"
        launcher = release / "runner" / "h454_windows_personal_adapter_launcher.mjs"
        dispatcher = release / "bundle" / "packages" / "agent" / "dist" / "dispatcher.js"
        if not all(path.is_file() for path in (node, launcher, dispatcher)):
            raise ValueError()
        command = (f"{_quote(node)} --preserve-symlinks-main --preserve-symlinks "
                   f"{_quote(launcher)} {_quote(dispatcher)} {_quote(state)}")
        def verify_bundle() -> str:
            return bundle.verify(release, expected_manifest, candidate.bundle_sha256)
        # Verify executable bytes before launching even the no-op probe.
        verify_bundle()
        search = release / "bundle" / "packages" / "agent" / "dist" / "core" / "search-manager.js"
        if (not search.is_file() or search.stat().st_size > 1024 * 1024
            or hashlib.sha256(search.read_bytes()).hexdigest() != SEARCH_MANAGER_SHA256):
            raise ValueError()
        def terminal(command_value: str | None):
            return YfcDevPsecTerminal(str(YFC_DEV), command=command_value,
                writable=(str(state),), readonly=(str(release), str(GIT_ROOT)))
        probe = terminal("exit /b 0")
        deadline = time.monotonic() + 10
        while probe.poll() is None and time.monotonic() < deadline:
            pause(0.02)
        if probe.poll() != 0:
            raise ValueError()
        probe.close()
        probe = None
        current = {"dispatcher": None}
        def start_dispatcher():
            process = terminal(command)
            current["dispatcher"] = process
            return process
        def isolation_verified() -> bool:
            try:
                scan(YFC_DEV)
                process = current["dispatcher"]
                return process is None or (not process._closed and process._environment is not None
                                            and process._job is not None and process.poll() is None)
            except Exception:
                return False
        broker = PersonalTerminalSessions(1, str(YFC_DEV),
            factory=lambda _sid, _root, command: terminal(command))
        importer = PublicProjectImport(release / 'code' / 'scripts' / 'h15_offline_project_import.py')
        options = {"decrypt": decrypt} if decrypt is not None else {}
        return worker.serve(raw_config, ca=ca, current_sid=current_sid,
            verify_bundle=verify_bundle, isolation_verified=isolation_verified,
            attach_job=attach_job, start_dispatcher=start_dispatcher,
            connector=connector, status_factory=status_factory, claim_call=claim_call,
            pause=pause, terminal_broker=broker, bridge_factory=PersonalAppContainerPipe, import_broker=importer,
            **options)
    except Exception:
        raise YfcRunnerDenied("yfc_runner_denied") from None
    finally:
        if probe is not None:
            probe.close()
