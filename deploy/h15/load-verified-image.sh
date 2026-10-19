#!/usr/bin/env bash
# H-15 #371. Verify a previously downloaded GitHub Actions image artifact.
# "load" is explicit, never downloads/pulls anything, never starts services.
# The three pins MUST be copied independently from the trusted CI run.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
fail() { echo "H15_BRC_IMAGE_LOAD_REFUSED=$1" >&2; exit 2; }
[[ $# == 5 ]] ||
  fail "USAGE_VERIFY_OR_LOAD_DIRECTORY_ARCHIVE_SHA256_IMAGE_ID_HERMES_SHA"
MODE="$1"; DIRECTORY="$2"; ARCHIVE_SHA="$3"; IMAGE_ID="$4"; HERMES_SHA="$5"
[[ "$MODE" == verify || "$MODE" == load ]] || fail INVALID_MODE
[[ "$ARCHIVE_SHA" =~ ^[a-f0-9]{64}$ ]] || fail INVALID_ARCHIVE_PIN
[[ "$IMAGE_ID" =~ ^sha256:[a-f0-9]{64}$ ]] || fail INVALID_IMAGE_PIN
[[ "$HERMES_SHA" =~ ^[a-f0-9]{40}$ ]] || fail INVALID_SOURCE_PIN
[[ -d "$DIRECTORY" && ! -L "$DIRECTORY" ]] || fail UNSAFE_ARTIFACT_DIRECTORY
command -v python3 >/dev/null || fail PYTHON3_UNAVAILABLE
command -v zstd >/dev/null || fail ZSTD_UNAVAILABLE
BASE="$(cd -- "$DIRECTORY" && pwd -P)"
[[ ! -L "$BASE/brc-relay.docker.tar.zst" && -f "$BASE/brc-relay.docker.tar.zst" ]] ||
  fail ARCHIVE_UNSAFE
python3 "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)/scripts/h15_brc_offline_image_bundle.py" \
  verify --directory "$BASE" \
  --expected-archive-sha "$ARCHIVE_SHA" \
  --expected-image-id "$IMAGE_ID" \
  --expected-hermes-sha "$HERMES_SHA" || fail INDEPENDENT_HASH_PROVENANCE_REJECTED
if [[ "$MODE" == verify ]]; then
  echo "H15_BRC_IMAGE_DOWNLOAD_VERIFIED=YES"
  echo "H15_BRC_IMAGE_LOADED=NO"
  exit 0
fi
[[ "$EUID" == 0 ]] || fail ROOT_REQUIRED_FOR_DOCKER_LOAD
command -v docker >/dev/null || fail DOCKER_UNAVAILABLE
docker info >/dev/null 2>&1 || fail DOCKER_DAEMON_UNAVAILABLE
[[ "$(uname -m)" == x86_64 ]] || fail TARGET_PLATFORM_NOT_AMD64
[[ "$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')" == linux/amd64 ]] ||
  fail TARGET_DOCKER_PLATFORM_MISMATCH
# Verify the compressed stream before giving ANY byte to the Docker daemon.
zstd -tq "$BASE/brc-relay.docker.tar.zst" || fail CORRUPT_ZSTD_STREAM
# Never run the daemon with the filename as an untrusted Docker image tag.
# Exact pin check happens again after load; "start" remains a separate step.
zstd -dc "$BASE/brc-relay.docker.tar.zst" | docker image load >/dev/null ||
  fail DOCKER_IMAGE_LOAD_FAILED
# Docker classic uses the config digest as the ID; Docker 29/containerd
# may use the OCI manifest digest. Validate the imported image against the
# pinned archive before reporting either runtime identity as safe.
TAG="hermes-brc-relay-eval:${HERMES_SHA:0:12}"
LOADED_ID="$(docker image inspect --format '{{.Id}}' "$TAG" 2>/dev/null)" ||
  fail EXPECTED_IMAGE_TAG_MISSING_AFTER_LOAD
docker image inspect "$TAG" |
  python3 "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)/scripts/h15_brc_loaded_identity.py" \
    --archive "$BASE/brc-relay.docker.tar.zst" \
    --expected-config-id "$IMAGE_ID" \
    --expected-tag "$TAG" || fail IMPORTED_IMAGE_IDENTITY_MISMATCH
echo "H15_BRC_IMAGE_OFFLINE_LOAD=PASS"
echo "H15_BRC_IMAGE_ID=$LOADED_ID"
echo "H15_BRC_CI_CONFIG_IMAGE_ID=$IMAGE_ID"
echo "H15_BRC_IMAGE_SERVICE_STARTED=NO"
echo "H15_BRC_OWNER_AGENTS_CHANGED=NO"
