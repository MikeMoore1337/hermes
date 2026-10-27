"""H454: guarded, owner-only native three-tool relay image cutover.

A fresh rollback checkpoint preserves all prior H454/H455 snapshots.
This wrapper performs NO activation unless the existing transactional
operator receives its already-required --execute and pinned approval file.
"""
from __future__ import annotations

from scripts import h15_brc_transactional_upgrade as gated

CHECKPOINT = "hermes-brc-relay-h454-native3-rollback"


def main(argv=None) -> int:
    if gated.CHECKPOINT != "hermes-brc-relay-h454-rollback":
        raise gated.CutoverDenied("UNEXPECTED_UPSTREAM_CHECKPOINT")
    gated.CHECKPOINT = CHECKPOINT
    return gated.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
