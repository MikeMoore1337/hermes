# Hermes #454 Stage 2A - Windows CurrentUser DPAPI bearer primitive

**Candidate only. Not an installer, native service, credential issuer or owner-host acceptance.**

New `device_fabric/windows_native_dpapi.py` implements genuine Windows
`CryptProtectData` / `CryptUnprotectData` in **CurrentUser** scope
(NO `CRYPTPROTECT_LOCAL_MACHINE`). Cryptography is bound by extra
entropy to both the immutable owner-reviewed install manifest SHA-256
and a **new** `h454-win-native-<32 lowercase hex>` identity; the
revoked Win32 identity and sandbox IDs are rejected.

The module performs no file or registry writes, networking, process launch,
service installation, device pairing, or token generation. Results and
exceptions never print the bearer or Win32 error text. Plaintext from
`CryptUnprotectData` is zeroed in the unmanaged DPAPI output buffer
before `LocalFree`; Python's returned immutable string cannot be
guaranteed securely wiped, so avoid logging and retain it only for the
bounded session. The Windows caller must explicitly zero any other mutable
plaintext buffers it owns. No files are placed under GitHub source control.

## OS prerequisites (future owner-approved install)

- The installer must provision an isolated non-admin service identity
  `NT SERVICE\\HermesCommanderNative`; load its DPAPI user context
  and protect the bearer *as that same identity*. A bearer protected by
  the owner's interactive identity must not be copied to the service.
- Protect the state directory and encrypted file with a verified DACL
  restricted to that service SID, Administrators and SYSTEM. Refuse
  inheritance from Users/Everyone, file junctions, reparse points,
  owner mismatch or broadly writable ancestors.
- The owner must enroll a **fresh** native identity through the existing
  authenticated Hermes MCP relay, with actual server-side revocation
  and no reuse of the paused/revoked device. Only a trusted local
  service/relay/owner gate may unseal and consume the bearer.
- DPAPI alone does not authenticate owner consent or grant filesystem
  access. The companion `windows_native_reenrollment.run_once` still
  requires trusted OS identity, pairing, expiry and revocation checks.
  Neither module is a service or installation entrypoint.
- Do not bypass Windows SmartScreen, request plaintext credentials
  in ChatGPT, create an unsigned "trusted" publisher, or claim that
  CI CurrentUser matches the actual future service SID.

## Evidence

Windows GitHub Actions job `H-15 native Windows read handle CI`
executes `tests.test_h454_windows_native_dpapi` using the Windows
CryptProtectData API with disposable synthetic credentials. Positive
roundtrip, wrong device/manifest, ciphertext tampering, expired/invalid
formats and sanitized error cases are covered. Main Linux CI verifies
fail-closed non-Windows behavior.

**Success on a disposable runner is not evidence of production Windows
service enrollment, NTFS ACL confinement, live credentials, WSS routing
or original project access.** Keep #454 OPEN, RUNTIME_NO_GO.
