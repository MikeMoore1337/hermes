"""Fix exit detection in the exact pinned personal Commander bundle."""
from __future__ import annotations

import hashlib

SOURCE_SHA256 = '7e35b46818937d323e69685e3a018d426061c8dc1d18af8900e46961b2e1ed50'
ANCHOR = b'                    attempts++;\n                    if (attempts >= maxAttempts) {'
INSERT = (
    b'                    // A closed process can finish without producing new output.\n'
    b'                    // An active session takes precedence over a stale reused PID.\n'
    b'                    if (!terminalManager.getSession(pid) && terminalManager.completedSessions.has(pid)) {\n'
    b'                        processState = { isFinished: true, isWaitingForInput: false };\n'
    b"                        exitReason = 'process_finished';\n"
    b'                        resolveOnce();\n'
    b'                        return;\n'
    b'                    }\n'
)


def patch(source: bytes) -> bytes:
    """Reject upstream drift before inserting a completion check exactly once."""
    if (type(source) is not bytes or hashlib.sha256(source).hexdigest() != SOURCE_SHA256
            or source.count(ANCHOR) != 1):
        raise ValueError('personal_interact_exit_patch_denied')
    return source.replace(ANCHOR, INSERT + ANCHOR, 1)
