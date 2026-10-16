"""Native Hermes Web Dashboard plugin: only a whitelisted, pre-sanitized snapshot.

Install only after the resident-agent runtime admission gate is satisfied.
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Response

router = APIRouter()
SNAPSHOT = Path("/var/lib/hermes-control-center/overview.json")


@router.get("/overview")
def overview():
    try:
        raw = SNAPSHOT.read_bytes()
        data = json.loads(raw)
        if data.get("schema") != 1 or data.get("mode") != "read_only":
            raise ValueError("invalid snapshot")
    except (OSError, ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=503, detail="snapshot_unavailable")
    return Response(content=raw, media_type="application/json",
                    headers={"Cache-Control": "no-store"})
