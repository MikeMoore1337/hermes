"""Connect one confined Linux personal Commander to its authenticated relay.

Provisioning, the grant-status check, TLS pinning, trusted bundle verification,
and the durable call journal are the responsibility of the parent supervisor.
No configuration or bearer is sent to the project-scoped dispatcher.
"""
from __future__ import annotations

from typing import Any, Callable

from device_fabric.linux_personal_sandbox import start
from device_fabric.windows_personal_commander_pipe import PersonalCommanderPipe
from device_fabric.windows_personal_commander_transport import run_session


class LinuxPersonalWorkerDenied(ValueError):
    """A sanitized failure without paths, credentials, or child output."""


def serve_once(*, target: str, device_id: str, bearer: str, project: str, bundle: str,
               connector: Callable[..., Any], is_active: Callable[[], bool],
               claim_call: Callable[[str], bool]) -> str:
    """Run one bounded session; an external supervisor may reconnect later.

    The supplied callbacks and arguments must come from protected local state,
    never a network request. A failed or revoked session closes the sandbox.
    """
    process = None
    bridge = None
    try:
        if (target not in ('hermes-vps', 'yfc-vps') or
                not all(callable(value) for value in (connector, is_active, claim_call)) or
                is_active() is not True):
            raise ValueError()
        process = start(project, bundle, ['/opt/commander/run'])
        bridge = PersonalCommanderPipe(process, ['/workspace'])
        return run_session(target=target, device_id=device_id, bearer=bearer,
                           tools=bridge.tools, connector=connector,
                           dispatch=bridge.dispatch, is_active=is_active,
                           claim_call=claim_call)
    except Exception:
        raise LinuxPersonalWorkerDenied('linux_personal_worker_denied') from None
    finally:
        if bridge is not None:
            bridge.close()
        elif process is not None:
            try:
                process.kill()
                process.wait(timeout=5)
            except Exception:
                pass
