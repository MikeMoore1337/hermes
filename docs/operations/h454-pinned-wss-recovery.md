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
Before stopping an existing container, the launcher checks its profile and
identity and retries the SSH tunnel until the process and TLS endpoint pass
readiness. It refuses the stop if the container was replaced during that wait.
After successful credential staging and state commit, its monitor also retries
a lost SSH process with a bounded readiness attempt and a five-second retry delay.
It checks the new process and TLS endpoint, atomically records the new process
identity, and leaves the already running container in place without restaging.
Unexpected state drift stops the monitor instead of overwriting the state.
Retry requires the launcher process to remain running; task termination,
login and reboot recovery are not established by it.
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
The sidecar requires `H454_SSH_SOURCE_IPV4` to be one private IPv4 address;
it immediately closes connections from other addresses. The operator must pin
the freshly inspected internal network gateway and confirm the SSH forwarding
source before starting it. One separate, credential-free SSH test on the
current host observed the gateway as its source at port 3000; that observation
does not prove the future port 3001 path or survive network changes. Source
filtering limits exposure to neighboring containers but is not authentication;
the Docker host and its network administrator remain trusted.
This design assumes the relay namespace and its host are trusted; it does not
protect an already compromised agent process or Docker administrator.
When run as a namespace-sharing sidecar, the proxy checks the relay's loopback
health every five seconds and exits after three consecutive failures. The
operator must configure and verify Docker's `unless-stopped` restart policy;
the agent can then reconnect after the proxy rejoins the restarted relay.
Replacing the relay with a different container ID requires explicit sidecar
reconciliation and remains outside this restart check.

`h454_relay_authorized_keys.py` prepares bytes for the one pinned Ed25519 key
only when the entire input hash, private relay address and exact existing
`nologin,restrict,port-forwarding` policy match. It adds port 3001 alongside
the existing port 3000 and preserves all other bytes; OpenSSH supports
[multiple `permitopen` options](https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT).
It writes nothing and does not supply locking, an atomic install or rollback;
those remain operator
requirements. A read-only preview matched the current key without changing it.

An alternative `h454_relay_second_authorized_key.py` primitive publishes a
distinct key restricted to port 3001 through an exclusively created hard link;
it never replaces the first authorized-keys file. It requires a root-owned
private registry, a pinned service-user SSH directory on the same filesystem,
an exact digest for the first file, and an unoccupied second filename. Its
receipt pins the new inode for idempotent revocation without deleting or
truncating a concurrently replaced SSH filename. If installation cannot confirm
revocation after a failure, it reports `KEY_INSTALL_UNSETTLED`. Emptying the
pinned inode prevents future logins through that inode; the caller must also
check other authorized-key paths and stop existing SSH connections by their
verified owners. A revoked slot cannot yet be reused automatically.

The production caller must open and recheck the real directory paths, verify
effective sshd configuration and permissions, securely provision and pin the
new identity, use a dedicated root-only registry for this key and account,
manage interruption recovery and validate the real connection.
The current server's effective configuration lists the second key file and that
filename was absent at inspection. A separate synthetic sshd bound only to the
VPS loopback accepted both restricted fixture keys, denied their opposite ports,
and rejected the second after inode-pinned revocation while the first still
worked. A second loopback fixture exercised the actual install and revoke
functions with synthetic keys and the service UID; old and new authentication,
refusal of the old port for the new key, and new-key revocation passed. Temporary
fixtures were removed and the real second filename remained absent. Neither
fixture installed a real key or tested the production adapter.
[OpenSSH supports selecting an agent identity using its public key](https://man.openbsd.org/ssh_config#IdentityFile),
and [Windows can store a key in its SSH agent](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement),
but enrollment, restart behavior and identity availability have not been
verified for this BRC.

## Interruption and rollback boundary

The rollout must acquire the exclusive runtime lock, persist verified snapshots,
install the guarded **old** launcher, then persist a flushed, no-overwrite
pending marker before stopping either container. A guarded candidate launcher must
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

`h454_windows_cutover_engine.ps1` provides the ordering core for a trusted
local operator adapter: it checks the held recovery lock at each step, installs
the guard and marker before attempting the stop, requires each action to
confirm its postconditions, and requires candidate MCP before changing control
files. It requires explicit UTC start and end times for the owner's maintenance
window, checks the window before quiescing the launcher and again before the
original stop, and holds without stopping if the window expires. Recovery after
a stop remains possible after the window ends; this check does not guarantee
that the outage finishes before the window ends. The trusted adapter must quiesce
the legacy scheduled launcher before installing the guard and verify that no
old launcher or owned child can start or continue unguarded; disabling a task
alone does not prove that an already running process has exited. If the old
launcher holds `runtime.lock`, the adapter must first validate the agreed window
and quiesce it before acquiring the lock; the callback rechecks quiescence under
the lock. These callbacks and the agreed window are not supplied by the
ordering core. Only an adapter-confirmed, settled failure enters rollback automatically;
an exception, timeout or other ambiguous outcome retains the marker and stops
without further mutation because a Docker operation might still be in flight.
The adapter must not report `FAILED_SETTLED` or resume recovery unless it can
establish that no earlier daemon operation can still mutate state. A successful
rollback stops the candidate and restores known control files before starting
and, if needed, restaging the original. It then verifies original MCP while
retaining the marker. The offline control-file primitive requires both known
containers stopped; if the original is already running, an adapter may skip
file writes only after verifying that the old control hashes already match.
Otherwise it must HOLD. If marker
removal has an ambiguous result after a verified commit, it reports HOLD without
starting a second rollback. The same ordered recovery entry can be called after
an interruption, with fresh inspected state and the lock reacquired; repeated
recovery skips staging if the adapter verifies the original is already ready.
The engine accepts only local trusted callbacks;
it neither validates Docker or credentials itself nor is a standalone operator.
The production adapter, its exact artifacts and an approved cutover are still
missing. `h454_windows_network_guard.ps1` verifies a fresh Docker network
snapshot's immutable identity, internal bridge mode, label and exact two-member
set. Its rollback route check also requires the original agent on only that
network, the proxy on that and one pinned upstream network, the intended alias,
no host override, and a fresh DNS observation resolving only to the proxy.
These checks consume observations supplied by the caller; they do not prove
the proxy's upstream interface is closed or prevent a Docker administrator
changing the network later.

The former image still uses plaintext transport. Automatically restarting it
after a failed TLS migration would reintroduce the bearer exposure. Until a
separately verified route restores the exact original container securely,
recovery leaves the agent offline with its marker and guard in place. A
production-ready operator must reconcile the original container, launcher,
SSH forward, isolated proxy and future starts, then repeat a real MCP smoke
before clearing the marker. Removing the marker or using the previous
plaintext rollback is not an automatic recovery step.

A transport-secured baseline would be a different image and container; it does
not fulfil the owner's requirement to restage credentials and restore the
original container. A safe and tested way to do that without exposing the
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
- An isolated listener outage produced a refused connection; an untrusted TLS
  listener then received no application bytes, and the agent reconnected and
  completed another tool call after the trusted listener returned. A local
  synthetic client mutation disabling certificate verification was correctly
  rejected by that test. This does not test automatic restart of the Windows
  SSH process or the live agent.
- The image recipe was exercised on the locally prepared no-auto-pair base
  with a synthetic CA. Its inherited layers and runtime configuration matched;
  the non-root process could read but could not overwrite the CA or module.
  The disposable test image was removed.
- Windows PowerShell 5.1 fixtures exercised exclusive locking, known and
  unknown states, idempotent offline recovery, and termination of an owned
  test process between two real `File.Replace` operations.
- The recovery engine was exercised with the actual offline file-replacement
  primitive and synthetic container callbacks: controls were restored before
  original startup, the marker remained, and repeated recovery skipped staging.
  This does not exercise a production Docker adapter or real credentials.
- A PowerShell 5.1 fixture exercised startup retry before container claim,
  substitution of that container during the wait, failed and successful
  reconnects, an unexpected listener identity, a readiness timeout,
  state-hash drift and startup versus monitor cleanup. It also terminated and
  replaced an owned Windows test process; the actual SSH process and
  production relay were not used. The previous private launcher was composed
  with synthetic image, profile and CA pins and passed the same extracted
  fixture; the launcher was not installed or executed.
- The rollback route guard passed PowerShell 5.1 negative fixtures for extra
  network members, changed identities, host overrides, alias and DNS drift.
  It also accepted fresh Docker Desktop metadata from disposable containers
  and isolated networks; those resources were removed. This did not stage
  credentials or alter the original container.
- A Docker Desktop fixture restarted a disposable relay while a TLS proxy
  shared its network namespace. The proxy detected the lost loopback relay,
  Docker restarted it into the relay's new namespace, and a pinned TLS probe
  passed. The fixture used synthetic certificates, did not call real MCP,
  and removed its containers, network and image. Equivalent CI coverage uses
  isolated disposable containers.
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
- A local Docker Desktop fixture exercised the ordering engine with real
  disposable original-image and WSS-candidate containers, synthetic OAuth/MCP,
  lock and marker. After candidate MCP and a synthetic failure between control
  file replacements, it restored the same disposable original container,
  restaged credentials, passed MCP and retained the marker. A third container
  on the private network was refused before staging. Test adapters and state
  were synthetic; this does not verify the production operator or actual
  original-container rollback. A PowerShell 5.1 run also injected an ambiguous
  error, reacquired the fixture lock and recovered through the same synthetic
  route. This models an interruption; it did not terminate the operator process.
- These tests do not establish certificate deployment, host ACLs, actual SSH
  forwarding, complete process-tree cleanup, login/reboot recovery, a real
  power-loss guarantee, live MCP recovery or production activation.
