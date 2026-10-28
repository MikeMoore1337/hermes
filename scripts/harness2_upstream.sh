#!/usr/bin/env bash
# Read-only access to ORIGINAL google-research/harness2 CLI installed by Toolkit #421.
# This does not run optimizer, executor, judge, model provider or benchmark tasks.
set -Eeuo pipefail

readonly UPSTREAM_SHA="1cfe254e8d25b15f37048c3730134686abe60335"
readonly UPSTREAM_URL="https://github.com/google-research/harness2.git"

die() { printf 'harness2: %s\n' "$*" >&2; exit 2; }
help() {
  cat <<'EOF'
Usage: bash scripts/harness2_upstream.sh status
       bash scripts/harness2_upstream.sh check [original harness2-check flags]
       bash scripts/harness2_upstream.sh report [original harness2-report flags]
       bash scripts/harness2_upstream.sh setup-preview lab|jb|wb
       bash scripts/harness2_upstream.sh summary runs/.../summary.json

This only calls OFFICIAL upstream preflight and read-only report CLI.
It does not start models or install any software.
EOF
}
[[ $# -ge 1 ]] || { help; exit 2; }
if [[ "$1" == help || "$1" == --help ]]; then
  [[ $# -eq 1 ]] || die "unexpected arguments"
  help
  exit 0
fi
[[ -n "${HOME:-}" && -d "$HOME" && ! -L "$HOME" ]] || die "unsafe HOME"
readonly INSTALL="$HOME/.local/share/ai-development-toolkit/harness2-$UPSTREAM_SHA"
readonly SRC="$INSTALL/source"
readonly BIN="$INSTALL/.venv/bin"
[[ -d "$INSTALL" && ! -L "$INSTALL" && -d "$SRC" && ! -L "$SRC" ]] || die "pinned upstream not installed"
[[ -f "$INSTALL/.adt-original-harness2" && ! -L "$INSTALL/.adt-original-harness2" ]] || die "origin marker absent"
[[ "$(cat "$INSTALL/.adt-original-harness2")" == "$UPSTREAM_SHA" ]] || die "marker mismatch"
command -v git >/dev/null 2>&1 || die "git unavailable"
[[ "$(git -C "$SRC" rev-parse HEAD 2>/dev/null)" == "$UPSTREAM_SHA" ]] || die "upstream revision mismatch"
[[ "$(git -C "$SRC" remote get-url origin 2>/dev/null)" == "$UPSTREAM_URL" ]] || die "unexpected source origin"
[[ -x "$BIN/harness2-check" && -x "$BIN/harness2-report" && -x "$BIN/harness2-setup" ]] || die "upstream CLI not installed"
cd -- "$SRC"
case "$1" in
  status)
    [[ $# -eq 1 ]] || die "unexpected arguments"
    printf 'HARNESS2_UPSTREAM=PINNED\nUPSTREAM_SHA=%s\nMODEL_EXECUTION=NOT_REQUESTED\n' "$UPSTREAM_SHA"
    ;;
  check)
    shift
    exec "$BIN/harness2-check" "$@"
    ;;
  report)
    shift
    exec "$BIN/harness2-report" "$@"
    ;;
  summary)
    [[ $# -eq 2 ]] || die "provide a single original runs/.../summary.json path"
    exec python3 "$(dirname -- "${BASH_SOURCE[0]}")/harness2_upstream_manifest.py" "$2"
    ;;
  setup-preview)
    [[ $# -eq 2 ]] || die "specify exactly one supported benchmark"
    case "$2" in lab|jb|wb) exec "$BIN/harness2-setup" "$2" --dry-run ;; *) die "unsupported benchmark" ;; esac
    ;;
  *)
    die "unknown command - no benchmark execution permitted"
    ;;
esac
