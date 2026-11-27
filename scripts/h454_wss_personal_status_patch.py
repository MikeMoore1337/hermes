"""Prepare a personal-Windows status proxy from one pinned source blob.

No server files, containers, network endpoints, or credentials are changed.
"""
from __future__ import annotations

import hashlib

SOURCE_SHA256 = "8a4c70a9e29aba4262a8a9730043d40c34f040bc65edf7bbd6c2355f4c51db4b"
BEFORE = b"/^h454-(?:linux-hermes|linux-yfc|win-native)-[a-f0-9]{32}$/"
AFTER = b"/^h454-(?:linux-hermes|linux-yfc|linux-personal-hermes|linux-personal-yfc|win-native|win-personal)-[a-f0-9]{32}$/"


def patch(source: bytes) -> bytes:
    """Accept only the reviewed LF-encoded original and change one ID pattern."""
    if type(source) is not bytes:
        raise ValueError("personal_status_proxy_denied")
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256 or source.count(BEFORE) != 1 or AFTER in source:
        raise ValueError("personal_status_proxy_denied")
    return source.replace(BEFORE, AFTER, 1)
