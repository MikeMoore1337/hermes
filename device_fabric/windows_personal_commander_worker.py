"""Supervise a separately enrolled personal Windows Commander session.

The caller supplies verified local state, pinned bundle/process startup,
private-TLS connector and durable replay journal. This module by itself does
not install or activate an agent and does not access any project files.
"""
from __future__ import annotations

import subprocess
import time
from typing import Any, Callable

from device_fabric import windows_personal_commander_config as config
from device_fabric.windows_personal_commander_pipe import PersonalCommanderPipe, PersonalPipeDenied
from device_fabric.windows_personal_commander_transport import PersonalTransportDenied, run_session

MAX_RECONNECTS = 5


class PersonalWorkerDenied(ValueError):
    """Constant denial without credentials, paths or process output."""


def serve(raw_config: bytes, *, current_sid: Callable[[], str], ca: bytes,
          verify_bundle: Callable[[], str], attach_job: Callable[[], None],
          start_dispatcher: Callable[[], subprocess.Popen],
          connector: Callable[..., Any], status_factory: Callable[[str, str], Callable[[], bool | None]],
          claim_call: Callable[[str], bool], pause: Callable[[float], Any] = time.sleep,
          decrypt: Callable[..., str] | None = None) -> str:
    """Run bounded sessions in a dedicated, job-owned worker process.

    Owner, CA and installed bundle are checked before unsealing. A local pipe
    failure ends this worker so closing its job reaps any remaining processes.
    """
    bridge = None
    process = None
    try:
        if (not all(callable(value) for value in (current_sid, verify_bundle, attach_job,
                start_dispatcher, connector, status_factory, claim_call, pause))
            or (decrypt is not None and not callable(decrypt))):
            raise ValueError()
        candidate = config.parse_config(raw_config)
        owner = current_sid()
        bundle = verify_bundle()
        options = {"decrypt": decrypt} if decrypt is not None else {}
        bearer = config.unseal(candidate, owner_sid=owner, ca=ca, bundle_sha256=bundle, **options)
        status = status_factory(candidate.device_id, bearer)
        if not callable(status) or status() is not True:
            raise ValueError()
        attach_job()
        process = start_dispatcher()
        bridge = PersonalCommanderPipe(process, list(config.PERSONAL_ROOTS.values()))
        failed = False
        def dispatch(name: str, args: dict) -> dict:
            nonlocal failed
            try:
                return bridge.dispatch(name, args)
            except PersonalPipeDenied:
                failed = True
                raise
        failures = 0
        while failures < MAX_RECONNECTS:
            if current_sid() != owner:
                return "owner_changed"
            try:
                outcome = run_session(device_id=candidate.device_id, bearer=bearer,
                    tools=bridge.tools, connector=connector, dispatch=dispatch,
                    is_active=lambda: status() is True, claim_call=claim_call)
                if outcome not in ("idle_timeout", "call_budget_exhausted"):
                    raise ValueError()
                failures = 0
                pause(1)
            except PersonalTransportDenied:
                if failed:
                    return "dispatcher_failed"
                state = status()
                if state is False:
                    return "grant_inactive"
                if state is not None and state is not True:
                    raise ValueError()
                failures += 1
                pause(min(2 ** failures, 30))
        return "reconnect_exhausted"
    except Exception:
        raise PersonalWorkerDenied("personal_worker_denied") from None
    finally:
        if bridge is not None:
            bridge.close()
        elif process is not None:
            try:
                process.kill()
                process.wait(timeout=5)
            except Exception:
                pass
