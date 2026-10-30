# H454: authenticated BRC transport and interrupted-update recovery

**Source and synthetic tests only. No new listener, certificate, Windows
launcher, container or service is installed by this change.** The live
cutover remains HOLD until its exact artifacts, certificate custody, network
and recovery procedure are verified and the owner approves a concrete window.

## Connection boundary

The existing Windows agent sends its bearer to a plaintext local SSH forward.
Checking the SSH PID before connecting does not authenticate the process that
accepts that particular connection. The pinned-agent source patch requires
only `wss://host.docker.internal:38184/ws`, explicitly supplies the CA from
`/opt/hermes-brc/relay-ca.pem`, verifies `brc-agent.internal`, and rejects all
other targets before opening a socket. The CA must be a verified immutable
part of the read-only agent image, not a writable runtime mount or an ambient
Node trust-store change. The existing container profile must also prohibit
mounts over the agent code and CA. The old encrypted credentials stay intact;
`Convert-H454SecureCredential` produces an in-memory copy with the WSS URL
and `pairedAt=manual`, rejecting unexpected fields or identity.

`h454_windows_wss_launcher.py` prepares a Run-only launcher from an exact,
independently pinned guarded launcher and public CA hash; the caller must not
trust a hash calculated from unreviewed input. It switches the forward and
temporary credential copy to WSS and checks local TLS readiness without
sending a bearer. Other launcher modes require a separate owner operator.
The Windows curl readiness probe allows an unavailable revocation endpoint
(`--ssl-revoke-best-effort`); the Node agent independently validates the
configured CA and server name, but neither check establishes certificate
revocation status. CA/key custody, renewal and compromise recovery remain
prerequisites. Readiness is not a substitute for authenticated MCP smoke.

`deploy/h15/Dockerfile.brc-agent-pinned-wss` is a recipe, not an image or a
deployment. Its build context must contain only the verified compiled module,
map and public CA. Resolve the supplied local base tag to its approved image ID
before and after the build, prohibit pulls, compare inherited layers/config,
and verify as UID 65534 that the root-owned 0755 trust directory and 0444 CA
and module are readable but immutable under the actual read-only runtime.

The private `h454_wss_relay_proxy.mjs` accepts only an agent WebSocket upgrade
at `/ws` with a well-formed bearer, limits handshakes and connections, and
forwards only to `127.0.0.1:3000` in its network namespace. The existing relay
authenticates the bearer. A proposed SSH forward
would target its private port `3001`. No public `/ws`, host port publication,
new mount, process identity or network change is authorized by this document.
The actual namespace, relay address, SSH `PermitOpen`, port availability,
key ownership, certificate name, validity, rotation and bounded rollback
must be checked before any activation. The TLS private key must remain on the
relay side and must never enter the Windows agent image or test artifacts.
This design assumes the relay namespace and its host are trusted; it does not
protect an already compromised agent process or Docker administrator.

## Interruption and rollback boundary

The rollout must acquire the exclusive runtime lock, persist verified snapshots
and a flushed, no-overwrite pending marker, then install the guarded **old**
launcher before stopping either container. A guarded candidate launcher must
also contain the same marker check. Under the lock, the guard refuses normal
start whenever the marker name exists, including an unexpected directory or
reparse entry; unknown or oversized state directories fail closed.

`h454_windows_offline_recovery.ps1` supplies exclusive-lock, marker and
offline control-file recovery primitives for an owner-approved operator. It
accepts only exact pinned marker, snapshot, image, container and file hashes;
both known containers must be stopped. It atomically restores the old state
and guarded old launcher, retains the marker and **does not start or rename a
container**. Repeating the recovery is safe for the tested file states. The
preflight rejects drift, missing snapshots, unknown markers, shared locks and
running containers before writing; later drift causes HOLD with the marker
retained. These primitives are not yet wired into
the existing rollout operator and do not automatically restore availability.

The former image still uses plaintext transport. Automatically restarting it
after a failed TLS migration would reintroduce the bearer exposure. Until a
separately verified secure rollback image exists, recovery leaves the agent
offline with its marker and guard in place. A production-ready operator must
also reconcile container names, the SSH forward and a secure fallback image,
then repeat a real MCP smoke before clearing the marker. Removing the marker
or using the previous plaintext rollback is not an automatic recovery step.

One candidate sequence is to build two separately pinned images with the same
verified WSS module and public CA: a transport-secured version of the current
image, and a transport-secured version of the no-auto-pair image. First verify
the transport-secured baseline with a real MCP smoke; only then can it be a
rollback target for the second image. The baseline's temporary credentials
must use `manual` to avoid the older CLI's re-pair path. If the first migration
fails, the plaintext predecessor remains stopped; this is a safe outage, not
an automatically successful rollback. Neither image currently has an
approved real CA or a production-ready rollout operator.
The secured baseline would be a different image and container; it does not
fulfil the owner's separate requirement to restage credentials and restore
the original container. A safe and tested way to do that without exposing the
original plaintext bearer remains open.

`h454_isolated_rollback_proxy.mjs` is a source-only experiment for that gap.
It listens on one detected private IPv4 address and forwards no agent bytes
until a separate TLS connection authenticates the pinned CA and server name.
Its image recipe places the CA and code in a root-owned, read-only directory.
The proxy cannot itself establish that Docker's network is internal, that its
DNS alias resolves uniquely to this proxy, or that no other container can join
the network. A future owner-gated operator must verify those facts, exact image
and network identities, the old container's existing host overrides, and the
complete process and rollback sequence before staging real credentials. The
isolation may remove normal project egress. The experiment is not an operator
and must not be deployed as a standalone recovery procedure.

## Evidence and limits

- A real pinned BRC agent transport and relay were exercised together in an
  isolated container with synthetic certificates and token: tool call and
  reconnect passed; fake globally trusted and wrong-name certificates did not
  receive the token. Invalid HTTP routes and unauthorized tokens were refused.
- The image recipe was exercised on the locally prepared no-auto-pair base
  with a synthetic CA. Its inherited layers and runtime configuration matched;
  the non-root process could read but could not overwrite the CA or module.
  The disposable test image was removed.
- Windows PowerShell 5.1 fixtures exercised exclusive locking, known and
  unknown states, idempotent offline recovery, and termination of an owned
  test process between two real `File.Replace` operations.
- A Windows PowerShell 5.1 and Schannel fixture verified the generated
  launcher's TLS probe against a synthetic trusted certificate; untrusted,
  wrong-name, missing-CA and changed-CA cases failed closed.
- A disposable container from the pinned baseline image passed two offline
  start/stage cycles with synthetic credentials; its tmpfs was empty after
  restart and an extra stage refused overwrite. This does not test the actual
  original container or its return to the network. The candidate CI includes
  a separate synthetic Docker network-order test and an exploratory isolated
  network-alias check that reports HOLD if the alias cannot be established.
  The candidate workflow also exercises a synthetic original-like restart and
  stage through the isolated proxy to a synthetic TLS relay; it checks that the
  proxy does not listen on its upstream interface. These fixtures do not prove
  Docker Desktop behavior or verify a Windows rollout.
- Local network-isolated tests of the proxy used synthetic certificates and
  token: the trusted peer received the token; an untrusted or wrong-name peer
  did not, even with a globally trusted fake CA. The proxy rejected a missing
  interface and a changed CA hash. A deliberately slow TLS handshake was bounded.
- These tests do not establish certificate deployment, host ACLs, actual SSH
  forwarding, complete process-tree cleanup, login/reboot recovery, a real
  power-loss guarantee, live MCP recovery or production activation.
