# Hermes #454 - fresh Windows identity WSS hello compatibility

The previous `h15_native_windows_outbound.hello()` advertises
`H15 Windows native read-only`, tied to the revoked
`h454-win-01335a1f6e6705b4` device. The new BRC owner-bound
native route from #876 requires an exact different name,
`H454 Windows native read-only`, and a fresh
`h454-win-native-<32 lowercase hex>` ID.

Without this new HELLO profile, a new bearer can pair correctly but its
MCP READ route rejects the live agent (name mismatch).

The new `fresh_native_hello` pins the new device, bearer format and
`wss://hermes.mikemoore.top/ws`. `windows_native_reenrollment.run_once`
opts into it explicitly. Neither `parse_settings()` nor the old
legacy `hello()` changes identity, and generic callers cannot select
an arbitrary name or tool catalog.

The exact new HELLO advertises only the three native Win32 READ tools.
It cannot expose `write_file` or `start_process`. CI tests an actual
in-memory WSS session, matching payload and fails for a revoked ID,
wrong bearer, unapproved URL, and a missing explicit new-profile gate.

This is a **wire-protocol correctness fix**, NOT a signed Windows
service, installed native host agent, owner approval or real WSS release.
Before original-host acceptance, the service still requires fixed
service SID/NTFS ACL, DPAPI CurrentUser under that SID, owner-paired
device, current BRC bearer revocation and a working outbound relay.

No owner OS/production changes. Issue #454 OPEN, RUNTIME_NO_GO.
