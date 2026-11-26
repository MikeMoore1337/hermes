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
from device_fabric.windows_personal_terminal_sessions import TOOLS as TERMINAL_TOOLS

MAX_RECONNECTS = 5


class PersonalWorkerDenied(ValueError):
    """Constant denial without credentials, paths or process output."""


def serve(raw_config: bytes, *, current_sid: Callable[[], str], ca: bytes,
          verify_bundle: Callable[[], str], isolation_verified: Callable[[], bool],
          attach_job: Callable[[], None],
          start_dispatcher: Callable[[], subprocess.Popen],
          connector: Callable[..., Any], status_factory: Callable[[str, str], Callable[[], bool | None]],
          claim_call: Callable[[str], bool], pause: Callable[[float], Any] = time.sleep,
          decrypt: Callable[..., str] | None = None, terminal_broker: Any | None = None,
          bridge_factory: Callable[..., Any] | None = None) -> str:
    """Run bounded sessions in a dedicated, job-owned worker process.

    Owner, CA, installed bundle and independently enforced OS confinement are
    checked before unsealing. The confinement callback must inspect the actual
    worker environment; a flag supplied by the relay or MCP caller is not proof.
    A local pipe failure ends this worker so its job reaps remaining processes.
    """
    bridge = None
    process = None
    try:
        if (not all(callable(value) for value in (current_sid, verify_bundle, isolation_verified, attach_job,
                start_dispatcher, connector, status_factory, claim_call, pause))
            or (decrypt is not None and not callable(decrypt))
            or (bridge_factory is not None and not callable(bridge_factory))):
            raise ValueError()
        if terminal_broker is not None and (not callable(getattr(terminal_broker, "dispatch", None))
                                            or not callable(getattr(terminal_broker, "close", None))):
            raise ValueError()
        candidate = config.parse_config(raw_config)
        owner = current_sid()
        if isolation_verified() is not True:
            raise ValueError()
        bundle = verify_bundle()
        options = {"decrypt": decrypt} if decrypt is not None else {}
        bearer = config.unseal(candidate, owner_sid=owner, ca=ca, bundle_sha256=bundle, **options)
        status = status_factory(candidate.device_id, bearer)
        if not callable(status) or status() is not True:
            raise ValueError()
        attach_job()
        process = start_dispatcher()
        bridge = (bridge_factory or PersonalCommanderPipe)(process, list(config.PERSONAL_ROOTS.values()))
        failed = False
        def dispatch(name: str, args: dict) -> dict:
            nonlocal failed
            try:
                if name in TERMINAL_TOOLS:
                    if terminal_broker is None:
                        return {"content": [{"type": "text", "text": "H454_PERSONAL_TERMINAL_UNAVAILABLE"}],
                                "isError": True}
                    return terminal_broker.dispatch(name, args)
                return bridge.dispatch(name, args)
            except Exception:
                failed = True
                raise PersonalPipeDenied("personal_pipe_denied") from None
        failures = 0
        while failures < MAX_RECONNECTS:
            if current_sid() != owner:
                return "owner_changed"
            try:
                outcome = run_session(device_id=candidate.device_id, bearer=bearer,
                    tools=bridge.tools, connector=connector, dispatch=dispatch,
                    is_active=lambda: isolation_verified() is True and status() is True,
                    claim_call=claim_call)
                if outcome not in ("idle_timeout", "call_budget_exhausted"):
                    raise ValueError()
                failures = 0
                pause(1)
            except PersonalTransportDenied:
                if failed:
                    return "dispatcher_failed"
                if isolation_verified() is not True:
                    return "isolation_lost"
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
        if terminal_broker is not None:
            try:
                terminal_broker.close()
            except Exception:
                pass
        if bridge is not None:
            bridge.close()
        elif process is not None:
            try:
                closer = getattr(process, "close", None)
                if callable(closer):
                    closer()
                else:
                    process.kill()
                    process.wait(timeout=5)
            except Exception:
                pass
