# H-15 #454: source-only native Windows read transport (WSS or opt-in SSH loopback)

**State: NOT DEPLOYED. Not paired with relay, not installed on the owner's PC.**
**Public `/ws` is intentionally closed** in the existing H15 ingress (Hermes #372 deployment acceptance). An unauthenticated WebSocket Upgrade to `https://hermes.mikemoore.top/ws` returned HTTP 404 from Cloudflare on 2026-10-23; this does not establish a usable private BRC endpoint. Do NOT open public `/ws` merely to activate native reads.
Linked: Hermes #454 and #455; owner read/execute policy in
docs/operations/h15-native-windows-approval.md.

The owner previously proved a single original-Windows Win32 read of
D:\Pet-projects\hermes\README.md: 8403 bytes and SHA-256 verified, outside
root denied; this proof does not include remote MCP transport.

## Bounded protocol
- New separate Python Windows agent: scripts/h15_native_windows_outbound.py.
  Default is outbound WSS to pinned host `hermes.mikemoore.top`, path `/ws`, port 443. No plaintext or domain fallback. **This is NOT a verified working production WebSocket route.**
- A separate explicit `--tunneled-loopback` mode accepts only `HERMES_NATIVE_BRC_LOOPBACK=ws://127.0.0.1:<approved-port>/ws` with an unprivileged port in 1024-65535. No hostname, non-loopback interface, query, userinfo, fragment, proxy, redirect or fallback.
- For this mode `ws://` covers **only the local TCP hop**. The remote confidentiality and peer authenticity must be provided by a separately owner-approved authenticated SSH local forward, with a verified SSH host key and approved target inside the existing BRC private network. The mode flag and a bound local port do not prove an authentic SSH tunnel.
- A malicious local process binding the port first could capture the device bearer token. Before any live use, verify local port/process ownership, use a restricted Windows OS identity and a short-lived/revocable owner-bound token, stop if the SSH forward is interrupted, and independently enforce approved path/ACL policies. Do not activate unattended/background reconnect.
- Device identity must exactly match the isolated #528 relay route: `H15 Windows native read-only`. The older #526 source-only gate is not a second independently deployable route.
- Uses upstream BRC wire version 1, owner-paired device bearer token in
  Authorization header and X-BRC-Protocol: 1. Hello announces unique native
  device name and ONLY two tools: native_file_stat and native_file_read.
  No generic file tools, shell or process actions.
- Calls are forwarded in-process to the previously verified MCP stdio
  adapter and Win32 CreateFileW handle-bound reader, **without spawning any
  subprocess per read**. Four exact roots; no parent Second Brain vault,
  secrets, write, directory listing or arbitrary command execution.
- 8 KiB maximum inbound frames; 64 distinct call IDs and 16 native operations
  per session; 256 KiB source-file ceiling, verified SHA-256 and byte count.
  Duplicate IDs, duplicate JSON keys, foreign tools, malformed fields, wrong
  relay welcome and rejected paths never reach a permitted native file read.
- Explicit single-session process only; no auto-reconnect, no service,
  scheduled task, public listener or new credential store.
- Python 3.14 free optional dependency: websockets==17.2 (sync client,
  additional_headers, TLS). This source change does **NOT install** it.

## Outstanding gates before actual use
1. Separate owner approval for the precise Windows-native process launch
   and any dependency install, ACL changes, pairing or resident operation.
   Owner's standing permission covers data reads, NOT new commands.
2. Dedicated restricted OS identity, known ACL/reparse protections, secure
   device token delivery and storage. Do not disclose token in CLI arguments,
   ChatGPT messages, CI outputs or GitHub comments.
3. **Relay policy not yet changed**: current fixed policy does not advertise
   or dispatch the two new names. The next relay change must check the actual
   owner-bound paired device ID/capability profile, not self-reported
   hostname/platform alone, and must not expose generic shell tools to the
   new native device. Review/test it before any runtime activation.
4. Run two genuinely independent ChatGPT and Codex client E2E checks and
   negative path/vault/timeout/revocation tests before calling it ready.
   Existing Windows test covers only owner-run one-file local proof.

## Evidence
- Targeted Python tests in the existing BRC Docker sandbox emulate the
  WebSocket without connecting to any Internet host or reading original D:.
- GitHub isolated Windows runner has an additional synthetic end-to-end test
  of fake-socket BRC call -> local MCP -> real Win32 handle-bound read on
  temporary CI files. It is not proof of the owner's live BRC pairing.

No Codex CLI, paid AI, other service activation or live host effects.
