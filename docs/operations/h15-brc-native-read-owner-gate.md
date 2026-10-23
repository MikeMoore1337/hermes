# H-15 #454: disabled-by-default BRC relay policy for original Windows reads

Source-only candidate. NOT applied to the running production relay.

The native Windows read-only agent source is in
scripts/h15_native_windows_outbound.py. It announces ONLY
native_file_stat and native_file_read on an outbound owner-paired BRC
WebSocket connection. The BRC relay in production has a static allowlist
and currently refuses these two tools. Merely advertising them from a
self-reported agent name cannot grant capability.

The operator-gated source patcher
scripts/h15_brc_native_read_gate_patch.py patches ONLY a disposable,
verified pinned upstream checkout AFTER the existing two Hermes
gateway and workspace hardening steps. It adds the template
deploy/h15/hermes-native-read-gate.template.ts plus two guarded
changes to relay source. It does not install or restart any relay.

## Trust boundary

- The new tools are absent from catalog unless
  HERMES_NATIVE_READ_DEVICE_ID is explicitly set for the relay.
- Invocation requires explicit deviceId matching that configured ID.
  The device must already be authenticated to the same owner by the
  relay pairing-token machinery. A paused/offline device is denied.
- Independently require a live device with exactly TWO capabilities,
  platform win32, name H15 Windows original read-only and the paired
  device ID. This is defense in depth: hello metadata can be spoofed
  by a holder of a stolen token and is not an independent credential.
- Device selection of that ID always denies other generic BRC
  tools, even if compromised agent code attempts to advertise them.
- Arguments limited to exact project and relative path; rejects
  traversal, secrets, vault and executable file requests.
- All other currently supported BRC devices/tools retain their
  existing behavior. An unset native ID does not enable native reads.

## Tests and future owner approval

The patcher refuses wrong source SHA, symlinked files, edited marker
patterns, and double patching before writing new output. Offline tests
exercise the exact source edits and attempt Node/TypeScript contract
tests if the compiler is available.

Do NOT apply this patch to production without fresh verification of
the real pinned BRC source, a successful TypeScript compilation and
real relay/disconnect/pairing/negative call E2E in a disposable clone.
New native Windows resident execution, pairing token creation,
changes to ACLs, deploying a relay policy and enabling a background
service require a new owner approval with precise commands and scope.

Issue links:
https://github.com/MikeMoore1337/hermes/issues/454
https://github.com/MikeMoore1337/hermes/issues/455
