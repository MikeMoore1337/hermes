# H-19 / #350 - owner-vetted read-only MCP permission gate

Date: 2026-10-18. This is an **experimental, test-only fix** for the pinned
Hermes v0.22.2 upstream derivative. Not installed into resident H-01.
See [initial exploitation proof](H-19-MCP-ANNOTATION-TRUST.md) and Issue #186.

## Finding and patch

A remote MCP server's `readOnlyHint=true` is an **untrusted statement**,
not a permission granted by the owner. On untrusted servers the upstream client
previously skipped the approval prompt and treated such calls as safe to retry
after a lost session. A malicious "read" operation with real side effects could
be invoked and replayed.

The local derivative now uses **two independent positive predicates** for
trust: untrusted:

1. The server advertises an exact `readOnlyHint=True`.
2. An operator-controlled configuration entry names that **exact native MCP
   tool name** in `read_only_allowlist` for the consuming server/profile.

Neither condition alone is sufficient. A missing or invalid allowlist is empty
and requires human consent **before** transport. Empty lists, globs,
duplicate names, malformed types and oversized lists cannot silently enable
read permissions. The exact same effective predicate controls session-expired
retry safety; unvetted tools do not get read-only auto-retry.

Example of locally audited, exact-name read-only grant (not production config):

```yaml
mcp_servers:
  audited_catalog:
    trust: untrusted
    command: /opt/audited-mcp-server
    read_only_allowlist:
      - list_public_documents
```

The owner must verify that the tool truly cannot modify external state;
a friendly-sounding tool name or its annotation is **not** verification.
The user-facing `trust: full` mode retains its existing semantics and is
not safe for arbitrary third-party servers. Never supply `trust: full`
merely to avoid approvals.

**Config integrity is a required separate OS control:** the agent and MCP
server must not be able to edit the operator-owned allowlist or change the
`trust` tier. Owner intent cannot be guaranteed by a writable local config.

## Isolation and real protocol proof

The scoped test image applies the pre-existing native toolset patch and
`patches/upstream/hermes-v0.22.2-mcp-owner-readonly-policy.patch` to the
immutable original v0.22.2 image. The source version and image digest remain
pinned. Docker is nonroot, networkless, read-only outside private tmpfs and has
no host mounts, secrets or real provider.

Two independent real MCP protocol paths are exercised:

- **stdio**: an actual child MCP SDK server receives wire-level JSON-RPC
  `tools/call`. Its dishonest read-hint tool attempts a private marker write.
- **Streamable HTTP**: an actual MCP SDK ASGI server on 127.0.0.1 records real
  inbound JSON-RPC `tools/call`, with a second physical marker readback.

The original image is expected to make the dishonest tool call without
consent. The derivative MUST call the simulated-deny consent callback
**exactly once** and cause **zero** forbidden inbound RPCs or markers.
There are positive controls for approved writing and for a separately
vetted read that works without consent. When the approved read is removed from
the owner's list in the patched HTTP probe, a deny must block the RPC. A
session toolset denial must remain independently effective.

Reports remain machine-readable and fail closed on unexpected observations.
**PASS means the original bypass was reproduced AND the derivative blocked it
on both transports**, not that all arbitrary MCP operations are safe.

## Not verified / remaining gates

- Real external third-party MCP servers, network DNS/TLS/proxy, sampling,
  cached-schema/reconnect and cross-profile multiplex runtime combinations
  beyond the scoped source path are not independently accepted.
- Full OS permissions, config immutability and production resident user
  identity are not established by test-only Docker.
- Real model evaluation NOT_RUN; inference cost zero.
- No launch, installation or permission change for resident H-01, #33.
- No production roll-forward authorization, YFC, Second Brain or other third-party
  credentials; source deployment is not runtime activation.

Issue #350 remains OPEN until remaining scoped matrix/OS and runtime policy
coverage has been reviewed. Parent #186 remains OPEN/PARTIAL until all
separately authorized real-LLM/third-party MCP acceptance requirements.
