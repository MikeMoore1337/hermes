# Hermes #454 Stage 2A - offline Windows GUI scope preview

**Status: SOURCE CANDIDATE ONLY. NOT AN INSTALLER.**

This bounded increment provides a standalone Windows graphical scope
preview for future native Windows installation review. It is explicitly
not an agent, signed installer, enrollment client, Windows service, UAC
workflow, or runtime. It does not read original project files or configure
any OS permissions. An unsigned EXE cannot substitute for a reviewed
publisher/signature and is not approved for owner-PC execution.

Source:
- deploy/h454/native-windows-preview/HermesCommanderNativePreview.csproj
- deploy/h454/native-windows-preview/Program.cs
- .github/workflows/h454-native-windows-preview.yml

The dialog names the proposed disabled service
HermesCommanderNative, NT SERVICE\HermesCommanderNative, read-only
mode, exact source revision, missing publisher signature, and the five
original Windows project READ roots already authorized in
[h15-native-windows-approval.md](h15-native-windows-approval.md).
It has **no Install/Activate/Connect button**. Private Second Brain vault
and parent workspaces remain prohibited. No new Windows command/write
approval or native process launch is implied.

## Isolated Windows CI

The PR job builds with Microsoft's free .NET 10 SDK on a disposable
GitHub-hosted windows-2025 runner, checks the source for prohibited
effect APIs, and starts only the compiled preview's noninteractive
self-test with the exact github.sha. Positive and wrong-SHA cases
are required; the binary's Authenticode status must be NotSigned.
The GUI itself is **not** visually or physically accepted by these tests.

Manual artifact production requires workflow dispatch on the exact live
main SHA and successful same-SHA repository/UI push checks. It only
uploads the unsigned EXE and a plain SHA-256 checksum receipt for
short-lived review. A checksum is **not a signature, provenance
attestation, consent, or install permit**. No SSH/deploy, secrets,
native original-host access, OS mutations or resident service startup.

## PNG preview for owner visual review (PR only)

The pull-request Windows CI also builds a *separate test-only executable*
from the same WinForms source and renders the actual window to an 800x590
PNG on a disposable GitHub-hosted Windows runner. Its exclusive-new file
output is limited to `RUNNER_TEMP/h454-native-win32-preview.png`.
The screenshot harness lives only under `tests/` and is **not**
compiled into the distributed unsigned preview EXE.

When the PR run passes, open that Actions run and its
`h454-native-win32-gui-review-png` artifact (retained for 3 days).
The artifact contains **only a PNG** - no runnable installer or binary.
This is a way to inspect the proposed UI without executing unsigned
software on the owner's Windows computer. CI rendering is still **not**
owner visual acceptance, security review or real-host acceptance. No
owner UAC dialog, credential pairing, service, ACL or filesystem access
is exercised.

## Still needed before Stage 2A Windows install

1. Replace this preview with a reviewed, reproducible, actually
   installable package including the constrained read-only native worker,
   protected state, disabled service, rollback/uninstall and OS ACL tests.
2. Independently validate Authenticode publisher/code-signing requirements
   and artifact provenance. Never ask the owner to bypass SmartScreen.
3. Present the **exact installer hash and OS change proposal** to the
   owner and obtain separate approval before running UAC or altering
   accounts, NTFS, registry, services or original project paths.
4. Re-enroll the existing revoked/paused Win32 device only after an
   explicit owner-approved credential workflow. Do not copy old tokens.
5. Prove original-host READ restrictions, negative vault/secret tests
   and both ChatGPT/Codex live usage; continue with one-use
   write/process approval and OS-isolated workers separately.

See [Stage 2A owner-approved installation gates](h454-native-host-install-approval-plan.md).
Until all required real-host checks pass:
WINDOWS_NATIVE_SERVICE=NOT_INSTALLED,
WINDOWS_NATIVE_CONNECTED=NO, NATIVE_HOST_PASS=NOT_RUN.
Keep [Issue #454](https://github.com/MikeMoore1337/hermes/issues/454) OPEN.
