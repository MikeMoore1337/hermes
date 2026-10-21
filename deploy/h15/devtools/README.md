# H-15 / #445 - pinned development toolchain candidate (source only)

This is a **NO-RUNTIME-ACTIVATION** recipe for the existing BRC Docker sandbox.
It only prepares an alternative developer image with Git and Python 3.
It is not device enrolment, an OAuth gateway, a persistent agent installer,
or a permission grant. The existing BRC image, ENTRYPOINT and CMD are inherited.

## Scope and boundaries

- Build only from an existing owner-approved **64-character sha256:** Docker
  image ID of the H-15 sandbox agent. No floating base tag or auto-pull.
- Debian 12 Bookworm only. Git, Python 3, pip, venv and CA certificates come
  from Debian repository snapshots dated 2026-10-20 at **build time**. An installed Debian archive keyring authenticates the initial HTTP APT CA-certificate bootstrap; strict signed index checks remain enabled. Subsequent package installation uses HTTPS after the CA bundle is available.
  The running agent gets no new network permissions. This **revised repository
  Dockerfile** has not been rebuilt; a separate, owner-built image is documented
  below. Live runtime activation remains NOT_RUN.
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

## Existing Windows clone: non-destructive Git interoperability

PR #447 configures **new** shared clones for LF via repository-local
`core.autocrlf=false`. An **existing** Windows-created staging clone with
CRLF files is not rewritten by that PR. Owner's disposable Docker probe
confirmed Windows Git tracked status = 0, raw Linux diff = 839 and Linux
diff/status with `-c core.autocrlf=true` = 0.

For that specific **existing staging clone only**, back up its `.git/config`
outside the repository, then use native Windows Git
`git -C <staging-repo> config --local core.autocrlf true`. This changes
Git metadata only, not tracked file contents. Verify both Windows and
Linux Git tracked status = 0 without a per-process autocrlf override.
If either verification fails, restore only the backed-up config and stop.
Do not run `git reset --hard`, `git checkout .`, `git clean`,
or globally set `core.autocrlf` / `safe.directory=*`.
Linux Git may need only a **per-command exact-path** `safe.directory`
exception because the bind-mounted owner differs from UID 65534.
This CRLF exception for the existing clone does **not** change the
LF policy for newly cloned projects.

## Observed owner candidate evidence (2026-10-21)

- Owner-built v3 DevTools candidate: Git 2.39.5, Python 3.11.2,
  Node 24.22.0; pinned OCI image index
  `sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3`.
- Disposable `--network none`, read-only, UID 65534 Docker smoke:
  **PASS** with exact repository `safe.directory` exception.
- Separate Windows/Linux CRLF differential probe: **PASS** (0
  normalized tracked modifications).
- This repository Dockerfile has been adjusted to reflect the signed
  CA bootstrap observed in the operator build, but **this exact
  source-file build has not been repeated**. Runtime swap and
  reboot/rollback checks remain **NOT_RUN**.

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
| Offline source-contract checks | Previous source CI PASS; this revision must pass exact-head CI |
| Actual pinned Docker image build | Owner v3 operator build PASS; this revised Dockerfile build NOT_RUN |
| Windows Docker / PowerShell operator test | Owner v5 staged Check/disposable smoke PASS |
| Disposable toolchain/sandbox negative E2E | Partial (isolated toolchain and Git PASS; full connected MCP tests pending) |
| Live migration, reconnect, rollback | NOT_RUN |

Do not equate merged source code with an active upgraded agent.
