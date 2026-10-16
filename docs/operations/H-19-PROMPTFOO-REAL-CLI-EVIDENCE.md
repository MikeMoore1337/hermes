# H-19 / #186 — actual Promptfoo CLI, synthetic offline pilot

**Date:** 2026-10-16. **Mode:** one-shot local test on a separate
Windows Docker Desktop, **NOT** Hermes resident agent or VPS.
Status: `LOCAL_SYNTHETIC_CLI_PASS`; no permission to deploy.

## Pin and supplier scope

- Official upstream repo: https://github.com/promptfoo/promptfoo
  (MIT, `package.json` version `0.124.1` observed).
- Official documented container: `ghcr.io/promptfoo/promptfoo`;
  version tag `0.124.1`. `docker buildx imagetools inspect`
  returned AMD64 manifest
  `sha256:3808c02188df5263689e500eaaaee403c5d0dd8c14e611a2c54729afa4e8f18c`.
  This exact digest was **pulled**, and `docker image inspect`
  confirmed OS `linux`, architecture `amd64` and immutable reference.
- Inside an OS-isolated container, `promptfoo --version` returned
  **0.124.1**, exit 0. Publisher signature, exact Git source->Docker
  image proof, vulnerabilities and complete dependency SBOM have **not**
  been independently verified. Do not conflate digest matching with
  verified provenance.

## Invocation and isolation

- One-shot `docker run --rm --pull=never --platform linux/amd64`.
- `--network none --read-only --user 65534:65534 --cap-drop ALL`,
  `--security-opt no-new-privileges`, CPU=1, memory/memory-swap 1536 MiB,
  PID limit 100, tmpfs /tmp (256 MiB). No host Docker socket, no
  writable bind mount, no production credentials or mounts.
- Only `evals/promptfoo_offline/` was mounted `readonly` as `/work`.
  `--workdir /work`, `HOME=/tmp`,
  `PROMPTFOO_CONFIG_DIR=/tmp/.promptfoo`,
  `PROMPTFOO_DISABLE_TELEMETRY=1`, `IS_TESTING=true`.
- CLI command actually invoked (inside the container):

```bash
promptfoo eval -c /work/promptfooconfig.yaml \
  --no-cache --no-write --no-share --no-progress-bar --no-table
```

**Note on CLI compatibility:** The CLI bundled in the observed
`0.124.1` Docker image **does not recognize `--safe-mode`**: initial
invocation with that flag printed command help and exit 1, *without*
performing an evaluation. The existing config's speculative
`commandLineOptions.safeMode: true` was removed in this follow-up;
neither a UI flag nor an unverified YAML setting is a security boundary.
A later eval command without it succeeded in the OS-isolated container.
Native file-based JavaScript is executed; fixtures are explicitly
synthetic and reviewed. Never run a remote provider by mistake.

## Actual result and meaning

Promptfoo CLI printed:

```text
Cache is disabled.
Running 12 test cases (up to 4 at a time)...
Eval complete
Results:
  12 passed (100%)
  0 failed (0%)
  0 errors (0%)
```

Exit code **0**. 12 cases cover untrusted Issue/RSS/Markdown/abstract/MCP
text, synthetic secret-handling/tool overreach, unsafe publication,
paid fallback, and two permitted public-data-only actions. The
`file://./fixture_provider.cjs` returns a canned `safe_decision`;
`policy_assert.cjs` evaluates it without querying real models or
running agent tools. The original `node --test` suite also tests
unsafe decisions fail closed, but **Promptfoo itself never asked a
real Hermes LLM to decide**. Thus 12/12 is **not** a real prompt-injection
resistance score and supplies **no** real tool-permission assurance.
No remote metrics or model network calls could be made from
the networkless container, though OS-level egress policy on the
Windows host outside this container was not assessed.

## Current disposition

- `#186 PARTIAL`: real CLI integration compatibility demonstrated,
  but lack of signed image provenance, missing real agent redteam trials
  and external review prevent production CI/Agent integration.
- Existing Hermes `quality.yml` continues using only the cheap
  4 Node standard-library tests: no Promptfoo installation in GitHub CI.
- No private Second Brain vault/YFC data, production webhooks, SSH,
  Telegram provider, paid AI or VPS timers were touched.
- `#33 resident_agent_allowed=false`. A separate offline
  full-source/permissions and approved spending gate is required
  before exercising the real agent.

Official docs:
- https://github.com/promptfoo/promptfoo/blob/main/site/docs/usage/self-hosting.md
- https://github.com/promptfoo/promptfoo/blob/main/site/docs/usage/command-line.md
