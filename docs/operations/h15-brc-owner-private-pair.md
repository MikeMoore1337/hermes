# Hermes #454 — one-time private Windows pairing, no public ingress

Status: source-only until explicitly approved VPS operator execution; no service
or public endpoint is activated by this file.

## Reason

The owner-configured https://mcp.mikemoore.top/device/verify is intentionally
unavailable to browser traffic (public HTTP 503). The private BRC relay at
http://127.0.0.1:38183 is reached over the existing pinned Windows SSH
forward. Browser-assisted pairing on this HTTP loopback would fail the exact
HTTPS Origin and Secure-cookie gates. Do not spoof Origin or open public /ws.

## Procedure

Only after a reviewed PR is merged, verified CI and exact source release
have reached the owner VPS, and the real service identity, SQLite backup
and relay health have been checked:

1. Keep the verified SSH loopback alive; Windows native agent must run under
   the dedicated nonadministrator hermes-brc-readonly identity with the four
   project paths protected by independently checked OS read-only rights.
2. Start a fresh one-shot Windows pairing script calling POST /device/start
   with exactly H15 Windows native read-only. Use a NEW code, not any code
   previously pasted into a chat or ticket. It has a 15-minute lifetime.
   Keep the Windows process waiting for the private /device/poll response.
3. On the authorized Hermes VPS vps1777112993, in an interactive root shell
   and from the verified successful deployed release:

       cd "/opt/hermes-agent-owner/releases/main-$(cat /var/lib/hermes-main-deploy/last-success.sha)"
       python3 -B -m scripts.h15_brc_owner_private_pair

   Do not run via stdin/heredoc or through an MCP sandbox.
4. Type the short Windows code into the interactive VPS prompt (not the
   long device_code and not any token). The script checks the pending row,
   unique admin owner, name, expiry, WAL, and no previous native device.
   The operator then types the exact displayed phrase APPROVE H454 followed
   by that newly displayed code.
5. After the conditional single-row transaction commits, the VPS prints:

       H454_PRIVATE_PAIRING_APPROVAL=PASS
       DEVICE_TOKEN=NOT_ISSUED_ON_VPS
       WINDOWS_PRIVATE_POLL=READY

   Original BRC /device/poll is then responsible for issuing the bearer
   privately to the waiting Windows process. No bearer is printed, stored
   by this helper, passed as an argv argument, or sent to GitHub/ChatGPT.
   Python opens SQLite only after dropping to the unprivileged relay OS UID.
6. Verify one new owner-bound win32 device with exactly native_file_stat and
   native_file_read, check the actual original Windows file and denied paths
   from ChatGPT and Codex, then revoke the token using a separately
   approved owner management procedure. No background daemon or shell tool.

## Failure rules

A REFUSED result makes no approval change; do not retry automatically, change
owner settings or manually update SQLite. Existing user devices must remain
untouched. Windows pairing codes expire; if expired, start a new one-shot
session and pass the new short code privately to the VPS. Stop if the owner
is ambiguous, native device name already paired, the DB owner/mode differs
from the pinned production state, the row changed or was previously approved.

## Scope of verification

Offline regressions: python3 -m unittest -v tests.test_h15_brc_owner_private_pair
on a temporary SQLite fixture. A green CI gate or successful approval is
not a pass for live Windows original-file ChatGPT or Codex E2E.
