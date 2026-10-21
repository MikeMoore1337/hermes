# H-15 / #445 - pinned development toolchain candidate (source only)

This is a **NO-RUNTIME-ACTIVATION** recipe for the existing BRC Docker sandbox.
It only prepares an alternative developer image with Git and Python 3.
It is not device enrolment, an OAuth gateway, a persistent agent installer,
or a permission grant. The existing BRC image, ENTRYPOINT and CMD are inherited.

## Scope and boundaries

- Build only from an existing owner-approved **64-character sha256:** Docker
  image ID of the H-15 sandbox agent. No floating base tag or auto-pull.
- Debian 12 Bookworm only. Git, Python 3, pip, venv and CA certificates come
  from Debian repository snapshots dated 2026-10-20 at **build time**.
  The running agent gets no new network permissions. Snapshot availability,
  image build and runtime execution are NOT_RUN as of this source-only PR.
- No automatic `npm install` or `pip install`, no additional credentials,
  and no change to container mounts, production services or Codex config.
- Work only in an owner-approved sandbox copy under `/workspace/projects`.
  No production checkout, YFC database, Second Brain vault or host home access.

## Preparation (read-only)

On the owner's Windows host, during an approved maintenance slot, obtain the
existing sandbox image ID from the live container. Use the actual container name:

```powershell
$containerName = '<actual-h15-sandbox-container>'
$baseId = docker inspect --format '{{.Image}}' $containerName
if ($LASTEXITCODE -ne 0 -or $baseId -notmatch '^sha256:[a-f0-9]{64}$') { throw 'INVALID_PINNED_BASE' }
docker image inspect $baseId | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'BASE_IMAGE_NOT_AVAILABLE' }
```

Verify the image ID against the existing owner-approved H-15 release record,
check user, mounts, resources, network, immutable source and rollback image.
Do not print image or container environment variables, tokens or other secrets.

## Optional manual candidate build - never run by CI or deployment

With separate operator approval, from the repository root:

```powershell
docker build --pull=false --network=default `
  --build-arg "BRC_BASE_IMAGE=$baseId" `
  -f deploy/h15/devtools/Dockerfile `
  -t h15-brc-devtools:candidate deploy/h15/devtools
if ($LASTEXITCODE -ne 0) { throw 'CANDIDATE_BUILD_FAILED' }
```

The Docker build context is deliberately limited to `deploy/h15/devtools`,
not the project root. The source recipe does not independently enforce
the approval of the local base image. Snapshot download requires external
network during the **image build only**, not during agent execution.

## Acceptance before any agent switch

1. Inspect final image ID, installed versions, inherited ENTRYPOINT/CMD,
   effective UID 65534, mount policy and vulnerability/provenance evidence.
2. Run a disposable container with no network, read-only root filesystem,
   dropped capabilities, `no-new-privileges`, CPU/RAM/PID limits, only one
   synthetic writable `/workspace` mount. Check Git/Python tools.
3. Test `git status` on the isolated Hermes clone, then a bounded Python
   smoke. Repo-specific dependency resolution is a separate decision.
4. Independently verify file AND shell denials against synthetic canaries,
   tool authorization, reconnect/replay, output bounds, ChatGPT and Codex.
5. Record the exact original container/image settings and a separately
   approved staged rollback to that same image; do not silently mutate a
   persistent device or production environment. If any check fails, **roll back**
   to the approved original image and verify existing H-15 connectivity.

**No production** services, Hermes H-01, YFC apps or Second Brain systems
are modified by this source-only candidate.

## Evidence and gates

| Criterion | Status |
| --- | --- |
| Offline source-contract checks | Tested locally; required in repository CI |
| Actual pinned Docker image build | NOT_RUN |
| Windows Docker / PowerShell operator test | NOT_RUN |
| Disposable toolchain/sandbox negative E2E | NOT_RUN |
| Live migration, reconnect, rollback | NOT_RUN |

Do not equate merged source code with an active upgraded agent.
