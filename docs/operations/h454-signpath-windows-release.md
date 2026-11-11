# Hermes #454 - SignPath Foundation signed Windows release (prepared)

Status: release workflow SOURCE-ONLY, signing NOT_RUN. No SignPath account,
code signature, certificate, installer on owner Windows, native runtime or
owner relay activation has been created by this PR. Do not claim that an
actual verified signed binary exists without a successful hosted workflow.

## Why it cannot sign automatically now

Hermes currently has no declared OSI-approved LICENSE in GitHub metadata.
SignPath Foundation requires an OSI-approved license without proprietary
code, a maintained and already released project, and separate publisher
approval. Eligibility requires the owner's legal review, not merely that
a GitHub repository is public. Do not relicense the repository unilaterally.

Official references:
- https://signpath.org/
- https://github.com/SignPath/fdn-website/blob/main/docs/terms.md
- https://docs.signpath.io/trusted-build-systems/github
- https://docs.signpath.io/projects

## Prepared workflow

File: .github/workflows/h454-native-win32-signpath-release.yml

This is a manually dispatched, exact-current-main-SHA signing pipeline.
The protected GitHub Environment h454-signpath-release must require the
owner's reviewer approval. Its private configuration is NOT provisioned
by the source code and must be supplied ONLY via GitHub Settings.

- Environment variable H454_SIGNPATH_OSS_APPROVED=true only after legal
  licensing, provenance and SignPath eligibility have been reviewed.
- Environment variables H454_SIGNPATH_ORGANIZATION_ID,
  H454_SIGNPATH_PROJECT_SLUG, H454_SIGNPATH_POLICY_SLUG and
  H454_SIGNPATH_ARTIFACT_CONFIG. The last MUST refer to an approved
  SignPath configuration that signs BOTH the MSI AND its embedded EXE.
- GitHub Environment secret H454_SIGNPATH_API_TOKEN. This must never
  appear in chat, logs, repository files or owner-machine scripts.
- SignPath Foundation / SignPath.io project, trusted GitHub build policy
  and manual signing approver must be configured separately. SignPath
  approval and its certificate cannot be created by a repository commit.

The workflow refuses without ALL conditions: exact current main SHA,
approved owner-protected environment, explicitly confirmed OSS eligibility,
LICENSE file, SignPath configuration, and successful same-SHA repository
and Control Center UI push CI. It builds the previously reviewed disabled
native Windows MSI in a GitHub-hosted Windows runner and submits the
short-lived unsigned CI artifact only to the verified SignPath origin
workflow. The unsigned action artifact expires in one day.

The verification helper scripts/h454_verify_signed_windows_msi.ps1
requires VALID Authenticode on BOTH the MSI and administratively extracted
HermesCommanderNativeService.exe, the expected SignPath Foundation
publisher and trusted timestamp, matching signer certificate fingerprints
and exact source SHA self-test for the executable. It does not install
or start any service. Only after all checks pass, a verified MSI and
SHA-256 receipt become a seven-day signed CI artifact.

## Actions required from the owner later

1. Review the licenses of all original source/dependencies. Decide
   whether an OSI-approved release of Hermes is legally appropriate.
   SignPath's free OSS eligibility is not guaranteed.
2. After acceptance by SignPath Foundation, configure the project,
   nested MSI/EXE signing, GitHub integration, signing policy and protected
   h454-signpath-release Environment in GitHub, without sharing secrets.
3. Review the exact SHA and manually dispatch the main workflow, then
   independently verify the signed receipt and binaries.
4. Separately approve Windows UAC / virtual service SID / NTFS ACL /
   DPAPI state. Even signed, the current MSI installs a deliberately
   inert NOT_PROVISIONED Windows service.
5. Complete real new-device pairing and actual original-host READ
   acceptance via ChatGPT and Codex before any process/write operations.

No unsigned distribution, self-signed fake trusted publisher, payment
or production BRC/WSS cutover by this PR. RUNTIME_NO_GO; Issue #454 OPEN.


## Required signature chain now includes the native read worker

The MSI contains `HermesCommanderNativeService.exe` and
`HermesCommanderNativeWorker.exe` built at the same source SHA.
The signing configuration must deep-sign both embedded executables and
the MSI. The SignPath release verifier now requires VALID Authenticode
and matching publisher certificate thumbprints on ALL THREE binaries,
checks the service source SHA and verifies that the worker rejects
execution under the non-service CI account. The receipt includes the
worker's SHA-256 and `worker_valid=true`. Missing/unsigned worker
prevents a release.

PyInstaller 6.22.3 and websockets 17.2 are exact build version pins, NOT
full wheel hash/provenance locks. A real signed release still requires
an approved dependency provenance review, eligible OSS license and
SignPath Foundation project, protected owner Environment and explicit
distributable provenance/host installation approvals.
