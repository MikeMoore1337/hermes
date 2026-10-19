#!/usr/bin/env bash
# H-15 #371/#372: explicitly owner-approved, one-shot zero-device OAuth pilot.
# No persistent relay, no host mounts, no agent enrollment or /mcp exposure.
# Uses the vetted evaluation-only offline stage runner, then rolls back ONLY
# its labelled disposable container on every exit path.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
HERE="$(cd -- "$(dirname -- "$0")" && pwd -P)"
STAGE="$HERE/stage-relay.sh"
OAUTH_TEST="$HERE/../../scripts/h15_brc_zero_device_oauth_pilot.mjs"
NAME=hermes-brc-stage-h15
PUBLIC_MCP=https://mcp.mikemoore.top/mcp

fail() { echo "H15_OAUTH_PILOT_REFUSED=$1" >&2; exit 2; }
closed_public_mcp() {
  local result
  result="$(curl --noproxy '*' --silent --show-error --connect-timeout 5 \
    --max-time 15 --output /dev/null --write-out '%{http_code} %{ssl_verify_result}' \
    "$PUBLIC_MCP")" || fail PUBLIC_HTTPS_UNAVAILABLE
  [[ "$result" == "503 0" ]] || fail PUBLIC_MCP_NOT_CLOSED
  echo "H15_OAUTH_PILOT_PUBLIC_MCP=503"
}
owned_stage_absent() {
  # Never interfere with a pre-existing test or foreign Docker container.
  if docker inspect --type container "$NAME" >/dev/null 2>&1; then
    fail EXISTING_STAGE_CONTAINER_REFUSED
  fi
}
[[ "$#" == 2 ]] || fail EXPECT_MODE_AND_EXACT_IMAGE_ID
MODE="$1"
IMAGE_ID="$2"
[[ "$MODE" == preflight || "$MODE" == run ]] || fail UNKNOWN_MODE
[[ "$EUID" == 0 ]] || fail ROOT_REQUIRED
[[ "$IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] || fail IMMUTABLE_IMAGE_SHA_REQUIRED
[[ -f "$STAGE" && ! -L "$STAGE" && -f "$OAUTH_TEST" && ! -L "$OAUTH_TEST" ]] ||
  fail LOCAL_SCRIPT_MISSING
command -v timeout >/dev/null && command -v curl >/dev/null ||
  fail HOST_DEPENDENCY_MISSING
owned_stage_absent
bash "$STAGE" preflight "$IMAGE_ID"
closed_public_mcp
if [[ "$MODE" == preflight ]]; then
  echo "H15_OAUTH_PILOT_PREFLIGHT=PASS"
  echo "H15_OAUTH_PILOT_CHANGES=NONE"
  exit 0
fi

# Explicit user approval is limited to network-none, zero-device,
# no-host-mount local OAuth test, never production rollout.
echo "H15_OAUTH_PILOT_SCOPE=NO_DEVICES_NO_HOST_MOUNTS_NO_PUBLIC_MCP"
stage_started=no
cleanup() {
  local exit_code=$?
  trap - EXIT
  if [[ "$stage_started" == yes ]]; then
    if ! bash "$STAGE" rollback; then
      echo "H15_OAUTH_PILOT_CLEANUP=MANUAL_REVIEW_REQUIRED" >&2
      exit 2
    fi
    echo "H15_OAUTH_PILOT_CLEANUP=PASS"
  fi
  exit "$exit_code"
}
trap cleanup EXIT
stage_started=yes
bash "$STAGE" start "$IMAGE_ID"

# OAuth test runs inside the isolated BRC runtime itself; vetted JS is
# passed on stdin, with no mounted host source or enabled tool call.
timeout --kill-after=5s 120s \
  docker exec -i "$NAME" node --input-type=module - < "$OAUTH_TEST"
bash "$STAGE" smoke
closed_public_mcp
echo "H15_OAUTH_PILOT_OAUTH_TEST=PASS"
echo "H15_OAUTH_PILOT_RELEASE_APPROVED=NO"
echo "H15_OAUTH_PILOT_DEVICE_COMMANDS=NO"
