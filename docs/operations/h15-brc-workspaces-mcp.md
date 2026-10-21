Hermes #454: Source-only relay MCP workspace tools.

- list_workspaces: authenticated user-scoped discovery of the four approved sandbox projects.
- resolve_workspace: accepts one project alias, returns actual paired online device ID and approved sandbox root; returns git_verified:false; clients must verify actual Git origin/branch before modification.
- Requires pinned shahidx0x/better-remote-commander upstream cbe511702dd0147650353c29ac6ab1decd8afda1, already patched with Hermes dispatcher and gateway policies.
- In a disposable checkout, run: python3 -m scripts.h15_brc_workspace_gateway --source-dir /path/to/pinned/hardened/brc --registry deploy/h15/workspace-registry.json
- Patch is NOT a running deployment. No native Windows host access, new credentials, provider/model calls, Docker changes or permissions.
- Run: python3 -m unittest discover -s tests -p test_h15_brc_workspace_gateway.py -v. Then verify actual pinned source build and live OAuth MCP tool discovery/negative tests prior to deployment. See Issue #454.
