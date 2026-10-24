"""H455 observer refresh corrective cutover with a separate rollback checkpoint.

The previous H454 and H455 rollback containers MUST remain untouched. This
wrapper uses the original owner approval schema, signed OCI image pins,
immutable admission and transactional rollback already tested for H455.
Nothing is activated or restarted until explicit --execute.
"""
from __future__ import annotations

from scripts import h15_brc_transactional_upgrade as gated

CHECKPOINT = "hermes-brc-relay-h455-refresh-rollback"


def main(argv=None) -> int:
    if gated.CHECKPOINT != "hermes-brc-relay-h454-rollback":
        raise gated.CutoverDenied("UNEXPECTED_UPSTREAM_CHECKPOINT")
    gated.CHECKPOINT = CHECKPOINT
    return gated.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
