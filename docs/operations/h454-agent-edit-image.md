# H454: minimal immutable agent image for edit-conflict errors

PR #677 fixed the pinned source, but the owner Windows DevTools agent still
uses image `8d28b0e`. Its compiled `edit.js` returns a successful MCP flag
when an edit is refused for multiple matches. Do not equate source deployment
with upgrading this separately managed image.

`scripts/h454_agent_edit_image.py` prepares one local derivative without
activating any device. It reuses the existing conflict-branch patch and
requires the exact immutable base and compiled-module SHA256. No dependencies
are downloaded or installed. The Dockerfile only copies the changed module
and adds three provenance labels. Full image Config must otherwise match,
including User/Env/Entrypoint/Cmd/workdir; existing filesystem layers must be
unchanged with exactly one added layer.

Default is read-only PLAN; it uses an isolated reader container, without
host mounts, network, credentials or the agent entrypoint:

    python -B -m scripts.h454_agent_edit_image

Preparation uses only the existing local Docker Desktop pipe:

    python -B -m scripts.h454_agent_edit_image --build

The builder refuses remote contexts, an occupied candidate tag, existing
output, symlinks/junctions and paths outside this checkout's `.artifacts`.
It never stops/restarts an agent, modifies DPAPI/state, publishes an image,
or changes SSH, Task Scheduler or native permissions. The local manifest
records measured source-file/module hashes and `activation_performed=false`.
Its hashes describe the actual owner build; do not infer registry provenance
or cross-host reproducibility from them.

## Owner-host preparation evidence, 2026-10-30

- Base: `sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3`.
- Module: `/app/dist/core/tools/edit.js`, mode 0644, UID/GID 65534.
- Before SHA256: `45e3aaf22d1d06e657903cd0da90c9c350277e4a0be0dc610b7074a6287a50e7`.
- After SHA256: `7baa7ed315d3c187791280317e4607c9006e9916e0492dc69b833cdffa77661d`.
- Built candidate: `sha256:ac9f8ce0c2fa54c687747384e8416b687decb6e46eb5954536cae43ee0f55bb5`.
- Actual old-base dispatcher smoke fails specifically on the conflict-error
  oracle. Actual new-image smoke passes error + unchanged bytes for ambiguity,
  a successful unique edit, cleanup and all six existing tool denials.
- Smoke runs non-root/read-only/network-none, with bounded RAM/CPU/PIDs and
  synthetic tmpfs workspace only. No paired device runs in these fixtures.

This is **isolated image evidence**, not a new live client E2E. The running
Windows agent remains the earlier image with the separately delivered init
configuration. See [current parity evidence](h15-brc-parity-acceptance.md).

## Separate activation approval

Before a rollout, require green exact-source CI, verify the local manifest
and immutable image again, prepare a stopped candidate with exact current
container security/mount parity and a fresh protected rollback snapshot.
Preserve the current working init container and the older retained original.
Use existing DPAPI staging after every start; never run two agents with the
same device identity. Only after live MCP acceptance may an atomic update
of the existing state `imageId` pin make the new image persistent. That
production change requires its own concrete owner approval and rollback.

Env change required: no; an approved activation would change the state image
pin. Login/reboot and independent ChatGPT acceptance remain unverified.
Keep [#454](https://github.com/MikeMoore1337/hermes/issues/454) OPEN.
