#!/usr/bin/env bash
# A local SHA-addressed derivative with the reviewed v0.22.2 native-tool patch
# must be selected by the operator. Never silently fall back to stock Hermes.
require_patched_agent_image() {
  IMAGE="${HERMES_AGENT_RUNTIME_IMAGE:-}"
  if [[ ! "$IMAGE" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "HERMES_AGENT_RUNTIME_IMAGE must be a full local image ID (sha256:...)" >&2
    return 1
  fi
  local actual revision policy
  actual="$(docker image inspect "$IMAGE" --format '{{.Id}}')" || return 1
  if [[ "$actual" != "$IMAGE" ]]; then
    echo "Hermes image ID mismatch" >&2
    return 1
  fi
  revision="$(docker image inspect "$IMAGE" --format '{{index .Config.Labels "hermes.base.commit"}}')" || return 1
  policy="$(docker image inspect "$IMAGE" --format '{{index .Config.Labels "hermes.native.tool.policy"}}')" || return 1
  if [[ "$revision" != "d923a5eb487a17c0a68801bba9ef0f56c81040a8" ]] ||
     [[ "$policy" != "bounded-v0222" ]]; then
    echo "Unverified Hermes v0.22.2 native-tool policy image" >&2
    return 1
  fi
}
