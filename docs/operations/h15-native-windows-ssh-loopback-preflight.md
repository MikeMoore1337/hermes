# Hermes #454 / #455 - original Windows read-only SSH loopback handoff

**Status: SOURCE ONLY / NOT_CONNECTED. No owner Windows or live relay changes.**

## Why another connection mode exists

The live H15 public ingress was deliberately installed with public `/ws` closed
(Hermes #372: `H15_PUBLIC_WS_CLOSED=PASS`). On 2026-10-23 an **anonymous**
HTTPS GET and a WebSocket Upgrade without a device token to
`https://hermes.mikemoore.top/ws` both returned HTTP 404 from Cloudflare.
That does not prove a working endpoint or authorize opening a public WebSocket.

The existing BRC Windows Docker sandbox reaches the private relay over a
restricted SSH local forward. This proposal preserves that no-public-WSS
boundary for a *separate native Windows read-only device*. It does not
reuse generic-agent credentials, root mounts or shell tooling.

## Source-only transport contract

`scripts/h15_native_windows_outbound.py` still defaults to a pinned WSS
origin. An opt-in `--tunneled-loopback` mode instead reads **only**
`HERMES_NATIVE_BRC_LOOPBACK`, which must be
`ws://127.0.0.1:<port>/ws` for decimal port 1024-65535. Never redirect
or fall back to a public domain or unapproved host; no proxy; no automatic
reconnection, service, scheduled task, user-home shell or installer.
`HERMES_NATIVE_BRC_WSS` alongside this option fails closed.

In this mode the local WebSocket leg is not TLS. Security relies on the
**separately verified** SSH server identity and encryption of the *remote*
leg. The agent alone cannot prove that a local port belongs to that tunnel.
A different local process can impersonate the listening port and receive
the bearer token; therefore use short-lived credentials, independently
check local listener ownership, and do not start the bridge before those
proofs. Prefer authenticated TLS end-to-end in a later iteration where
operationally feasible. This is a design tradeoff, not a proof of production
readiness.

## Pre-activation checks (all NOT_RUN)

1. **Read-only owner VPS network inspection:** verify actual private relay
   network address/port, current image/patch, reachable `/ws` from the
   intended restricted SSH identity, and rollback readiness. Do not infer
   these details from sample CI addresses or public DNS.
2. **Tunnel agreement:** propose exact SSH identity, verified host key,
   loopback bind `127.0.0.1:<selected-port>` and private destination,
   no shell, no remote dynamic forward, `ExitOnForwardFailure`, finite
   lifetime; confirm the local listening process belongs to the approved
   SSH client. Do not open public `/ws` or any inbound Windows port.
3. **Native Windows identity:** a separate non-administrator OS user,
   explicit four approved project roots, OS ACL/reparse-negative proof and
   no original-file modifications. Exclude the parent
   `second-brain-workspace`, private vault, tokens and user home.
4. **Owner credentials:** create and pair a new owner-bound `win32` device
   with exact `H15 Windows native read-only` name and exactly
   `native_file_stat`/`native_file_read`. Deliver the token to the
   restricted process out of band without command-line/log/GitHub/chat
   disclosure; pre-agree revocation. Never reuse generic BRC agent token.
5. **Relay activation:** present separately approved pinned image,
   source/CI receipt, transactional production cutover, SQLite backup,
   rollback and verification. Green GitHub CI or a normal Hermes
   application deploy **does not switch** the active BRC relay image.
6. **Host start:** obtain explicit *per-command* owner approval before
   local source staging, package installation, SSH forward, ACL mutation,
   or `py -3.14 -B -m scripts.h15_native_windows_outbound
   --single-session --tunneled-loopback`. The Python import/runtime
   dependency is optional `websockets==17.2` and is **not installed**
   by this PR. Keep source outside the original project trees.
7. **Real client E2E:** `native_file_stat` and `native_file_read` on only
   `hermes/README.md` from separately refreshed ChatGPT and Codex,
   integrity proof, vault/escape/other-owner/paused/replay/foreign-command
   denies, connector re-pair/reconnect behavior. Then revoke token and
   close the approved tunnel, verifying offline state. No native write,
   rename, delete or process execution tools are allowed in this device.

**Approval is needed for EACH concrete Windows-host command/mutation and for
production relay modification.** The standing original-file read grant is
not authorization to launch Windows commands, change ACL, install packages,
issue credentials or enable a service. This document is preparation only;
all seven gates remain open and require real traces, not fixture PASS.

Linked issues: https://github.com/MikeMoore1337/hermes/issues/454
and https://github.com/MikeMoore1337/hermes/issues/455.
