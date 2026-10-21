# Hermes Commander: workspace routing foundation (#454)

This is the **first implementation slice**, not an activated replacement for Desktop Commander. The deployed Hermes BRC MCP still exposes the existing 21 file/search/terminal tools. `list_workspaces` and `resolve_workspace` are **not** yet remotely advertised MCP tools.

The allowlisted manifest `deploy/h15/workspace-registry.json` holds four public sandbox repository aliases. The read-only `scripts/h15_workspace_router.py` resolves "yfc", "toolkit", "adt", "second brain", "hermes" to pinned roots. It validates actual Git origin/branch and denies unexpected, missing, symlinked or replaced paths. No root outside `/workspace/projects` can be selected. It does not access Windows native host files, production VPS or private Second Brain vault.

`--devices-stdin` accepts the genuine `list_devices` JSON envelope for a unique online/non-paused Windows device. The returned device ID comes from the live list, not a committed static ID. Without live discovery, the resolver reports `device_status=not_checked`; it **never** claims Online from a manifest.

After this PR is merged **and the staging Hermes workspace is safely updated**, agents may invoke, inside the Windows BRC:
```sh
python3 -B /workspace/projects/hermes/scripts/h15_workspace_router.py --list
python3 -B /workspace/projects/hermes/scripts/h15_workspace_router.py --resolve yfc
```

Pending stages before frictionless client UX:
1. Integrate a read-only catalog into the real BRC relay's MCP tool advertisement and **server-side** authenticated invocation; real ChatGPT+Codex tool E2E. A CLI script alone is not auto-routing.
2. Add approved project onboarding, device diagnostics and recoverability to Control Center (#455) after visual approval.
3. Grant any native Windows filesystem/process paths only after explicit owner scope; no whole-drive mount or auto-vault bridge.
4. Verify Windows reboot/login recovery later (#445).

Run `python3 -m unittest discover -s tests -p test_h15_workspace_router.py`. Pure resolver metadata is **not an access-control boundary**. Keep existing Docker UID, mounted roots and relay policy gates. No runtime/image/credentials/deployment changes are introduced by this patch.
