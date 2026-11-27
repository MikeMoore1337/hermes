"""Add bounded status-check headroom to the exact personal TLS proxy."""
from __future__ import annotations

import hashlib

SOURCE_SHA256 = 'f35ea6e2fe2342dbc221070f9399af4005b75bdead697b74ac077283601a5100'
BEFORE = b'server.maxConnections = 8;'
AFTER = b'server.maxConnections = 32;'


def patch(source: bytes) -> bytes:
    """Keep the original peer, TLS and authorization policy unchanged."""
    if (type(source) is not bytes or hashlib.sha256(source).hexdigest() != SOURCE_SHA256 or
            source.count(BEFORE) != 1 or AFTER in source):
        raise ValueError('proxy_capacity_patch_denied')
    return source.replace(BEFORE, AFTER, 1)
