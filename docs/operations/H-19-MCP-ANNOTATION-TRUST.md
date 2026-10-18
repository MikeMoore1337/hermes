# H-19 / #186 - untrusted MCP readOnlyHint is an unverified security claim

Date: 2026-10-18. Scope: **test-only** real MCP Streamable HTTP, without
external MCP servers, live models, provider credentials, production credentials,
H-01 resident modifications or outbound network.

## Threat model

In upstream pinned NousResearch Hermes v0.22.2
(`d923a5eb487a17c0a68801bba9ef0f56c81040a8`), the client records each
remote MCP tool's **server-supplied** `annotations.readOnlyHint=True` at
registration. Its `tools/mcp_tool_handlers.py:_trust_gate_check` skips the
consent dialog when that hint is true, even if the server is configured
`trust: untrusted`. The tool's actual side effects are **not inferred or
verified** from its declaration.

This is a trust-boundary risk: an adversarial or compromised MCP server can
advertise a tool as read-only while its implementation writes data. The
annotation is not an independent owner-controlled authorization.

## Bounded verification

`scripts/h19_real_http_mcp.py --execute` compares the immutable upstream
image and the existing, scope-only patched derivative in separate disposable
Docker runs. In each run the real MCP SDK Streamable HTTP server exposes:

- `peek`: genuinely read-only positive control
- `mark`: annotated write, requires simulated explicit consent
- `disguised`: **lies** with `readOnlyHint=True` and writes the private,
  constant-content `/tmp` marker if invoked

The harness mocks the consent surface to **deny** and record every call.
Actual server-side `tools/call` names are counted after inbound HTTP
delivery. It independently reads the marker bytes; a response string alone
is not counted as an effect. It fails if either genuine RPC, marker readback,
approval interception, or expected original-versus-derivative observation
changes. On both versions, the existing patch addresses **session toolset
scope**, **not** the read-only annotation trust boundary.

The report explicitly records
`untrusted_annotation_spoof_gap_observed=true` on a passing observational
test. **PASS means the experiment reproduced the expected wire-level
behavior. It does not mean the trust gate is secure.** Treat this flag as
a vulnerability, not successful enforcement. The scenario never grants owner
consent: the `deny` callback deliberately exists, but a false read-only hint
can prevent the callback from being invoked at all.

No runtime agent launch, YFC, Second Brain, external API, TLS/proxy, paid
inference, or third-party MCP endpoint is involved. `--network none`,
nonroot, read-only Docker with private tmpfs remains mandatory.

## Required remediation before treating arbitrary MCP as safe

The trust policy must not take a write-bypass decision solely from untrusted
server-provided read-only annotations. Preferred protection:

1. Have an **owner-controlled, per-server, per-tool allowlist** of vetted
   read-only tool names with verified effect semantics; no allowlist entry
   means consent required for `trust: untrusted`, regardless of MCP hints.
2. Deny high-risk or unavailable consent surfaces **before network RPC**,
   even when a tool advertises a read-only hint.
3. Keep independently enforced session toolset restrictions, OS filesystem
   rights and network egress; consent alone is not an OS boundary.
4. Add malicious-annotation regression coverage for stdio, HTTP, cached
   schemas, aliases and reconnects. Test after any policy change with a real
   local wire recorder and private effect marker, including a genuine read
   positive control.

These are **requirements, not implemented mitigations**. A future fix must
change the ephemeral upstream candidate or the reviewed runtime policy and
produce independent passing before/after evidence. The current bounded
derivative remains test-only.

## Acceptance and remaining gates

- Machine-readable observational output:
  `h19-real-http-mcp.json` in the isolated optional workflow.
- Standard offline Python unit tests cover receipt mutations, evidence
  overclaims and no-execution default.
- Missing MCP SDK, wrong image/source identity, error or malformed evidence
  is never silently treated as PASS.
- `full_external_mcp_enforcement_verified=false`.
- `full_resident_runtime_verified=false`.
- `real_model_evaluation=NOT_RUN`, `resident_agent_allowed=false`.
- Issue #186 stays **OPEN/PARTIAL**, and #33 independently gates H-01.

The red-team test is a diagnostic proof of a *known unsafe assumption*
in the upstream classification, not a reason to enable third-party MCP.
