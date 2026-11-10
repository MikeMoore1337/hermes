# Hermes #454 / Stage 2A - fresh Windows native read identity (source only)

**Status: source candidate. No enrollment, signed installer, live service or host read.**

The original Win32 native device `h454-win-01335a1f6e6705b4` is
**PAUSED/OFFLINE** and its old bearer was revoked. Neither that token nor that
device record can be silently reused to make the native service appear online.
The new identity contract in `device_fabric/windows_native_reenrollment.py`
requires a distinct `h454-win-native-<32 lowercase hex>` owner-paired ID.

## Exact boundaries

- Parse a separately trusted **local** native Windows installation manifest
  with pinned release SHA, SHA-256, disabled service, read-only mode and the five
  owner-approved original Windows roots.
- Parse only canonical, duplicate-free private device state with an exact
  manifest digest, pinned relay `wss://hermes.mikemoore.top/ws`, separate
  device ID, bounded expiry and an opaque sealed bearer blob. The plaintext
  bearer never appears in repository files, tool arguments or diagnostic output.
- The **future** service and owner-pairing operator must independently confirm
  Windows service SID/NTFS ACL, confidential DPAPI unseal, release provenance,
  authenticated owner enrollment and live revocation. These controls are
  represented by trusted injectable callbacks for offline contract tests.
  They are **not implemented by this change**. A lambda returning True is
  not a security boundary and must never be exposed as an MCP argument.
- Only after the callbacks pass, the source candidate composes the **existing**
  Win32 native reader and read-only BRC outbound transport in **one** bounded
  session. A guarded socket checks service/owner/revocation/expiry on each wire
  I/O and closes a partially entered connection if authorization changes.
  Even a hand-crafted in-memory candidate cannot reuse the revoked identity.
  It has no queue, reconnect loop, shell, write, delete, process tool,
  startup registration or remote root selection.
- The existing `scripts/h15_native_windows_outbound.py` legacy CLI still
  requires its earlier ID; this source does **not** change that legacy
  registration or unpause it. The new handler is not exposed via any CLI,
  installer, system service, WebSocket endpoint or ChatGPT native tool.

## Security acceptance in disposable CI

```sh
python -B -m unittest -v tests.test_h454_windows_native_reenrollment
```

Both standard repository Python CI and actual GitHub Windows runner execute
this contract. Negative fixtures include previously revoked/other sandbox ID,
malformed JSON and duplicate keys, altered root/service scope, forged
`owner_approved`, spoofed relay, invalid sealed token, expired session,
missing local OS/pair gates, mid-session revocation and sanitized exceptions.
The existing Windows runner separately exercises genuine Win32 kernel
CreateFile/handle tests on disposable files and LocalService ACL isolation.

**Passing synthetic tests is NOT original owner-host E2E.** The currently
deployed BRC/WSS route does not automatically accept the new identity or
serve this code. The existing public `/ws` was previously reported CLOSED;
do not open it or bypass the joint relay/WSS rollback gate for a smoke test.

## Remaining Stage 2A work

1. Real owner-authenticated new-device enrollment and secure non-exporting
   Windows protected state (DPAPI + service SID ACL), including live revocation.
2. Signed graphical installer with disabled/reversible Windows service and
   protected installation and rollback receipts, with owner's exact approval.
3. Existing Hermes MCP / BRC relay strict native tool catalog and approved
   device ID routing, while preserving Docker devices and paired security pins.
4. OS-enforced read-only service isolation and real negative/positive
   original-Windows file tests in ChatGPT and Codex. Linux host installation
   and acceptance are separate approvals.

No production, BRC/WSS, credentials, Windows ACL, UAC, service, startup task
or original owner files were changed by this source candidate. Keep #454 OPEN.
