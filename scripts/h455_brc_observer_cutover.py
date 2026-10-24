"""#455 owner BRC observer upgrade using existing audited transactional cutover.

Keeps the earlier h454 rollback/history checkpoint untouched. A second
checkpoint name is required because older historical rollback is retained.
All approval/image/SQLite/security checks remain those of the pinned #454
cutover; no production action happens without its exact owner JSON + --execute.
"""
from __future__ import annotations

from scripts import h15_brc_transactional_upgrade as gated

H455_CHECKPOINT = "hermes-brc-relay-h455-rollback"


def main(argv=None) -> int:
    if gated.CHECKPOINT != "hermes-brc-relay-h454-rollback":
        raise gated.CutoverDenied("UNEXPECTED_UPSTREAM_CHECKPOINT")
    gated.CHECKPOINT = H455_CHECKPOINT
    return gated.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
