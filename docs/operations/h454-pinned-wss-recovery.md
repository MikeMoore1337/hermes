# H454: authenticated BRC transport and interrupted-update recovery

**The Windows WSS tunnel is active; the BRC cutover remains HOLD.** A private
TLS proxy and a separately restricted SSH key are installed on the relay. The
permanent Windows supervisor connected with pinned TLS and recovered its SSH
child after a controlled termination while the original container was stopped.
After the supervisor itself was terminated, its owned SSH child exited and
the periodic task started a new supervisor with pinned TLS.
The original container is still stopped. Its raw profile differs from the old
launcher pin only in the representation of an unspecified DNS list; the
normalized comparison matches. Secure restaging, the production update
operator and live MCP remain unverified. A concrete maintenance window is
required before stopping BRC for a later cutover.

While the original was already stopped, its legacy scheduled task was disabled
after checking the exclusive runtime lock, original container identity and
closed local listeners. Its previous task XML was saved in the protected state
directory. The independently pinned old launcher is now guarded, its original
bytes are backed up and a pending transition marker is present. The guard
refuses the launcher's run path while the marker remains. The backup is a
control snapshot, not a verified secure rollback procedure.

The isolated recovery network and credential broker are now prepared on the
Windows Docker host. Only the broker is attached; the earlier proxy is stopped
and disconnected from that network. The original container is still stopped
on its old bridge and no real credential was staged. These resources alone do
not restore the device.

## Connection boundary

The original image's terminal dispatcher and agent run as the same UID. A
disposable copy using a synthetic credential confirmed that `start_process`
can read `/run/brc/device.json`; mode 0600 does not separate those processes.
The prepared direct-WSS candidate would also expose a bearer staged there.
Neither should be started with a real bearer until that exposure is addressed.

The experimental `h454_credential_broker.mjs` keeps the real bearer in a
separate container's memory. The original agent receives a local surrogate;
the broker accepts only the agent WebSocket upgrade, substitutes the real
bearer after pinned TLS verification, and accepts staging only on its own
loopback interface. The agent and its terminal can still use or impersonate
the local surrogate within their shared sandbox; it is not a per-command
authorization boundary. A disposable test using the original image, synthetic
credentials and a synthetic relay confirmed terminal access only to the
surrogate, refusal of the broker's staging port from both networks, and
restaging plus reconnection after broker restart. The test removed its own
resources. The real broker is running without a staged credential. The restore
operator has passed a disposable original-image staging and repeat-run test,
and a read-only preflight against the real stopped container, but has not yet
restored it. Its restage-only mode is not yet scheduled or verified against a
real broker restart. Use by the direct-WSS candidate is not implemented.

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
independently pinned guarded launcher, public CA hash and second SSH public-key
hash; the caller must not trust hashes calculated from unreviewed input. Its
`prepare_from_installed` entry also accepts the specifically identified legacy
preserving launcher: it checks the full input digest and the exact historical
helper body before adding the current identity checks and pending-marker guard.
It requires a different candidate image ID and a candidate profile hash, which
the operator must independently verify against the built WSS image and container.
The current installed launcher was composed this way in memory and parsed by
PowerShell 5.1 with synthetic CA and public-key pins. That structural check
does not independently approve its calculated input digest or install it. It
uses only that public key with the default Windows SSH agent, ignores external
SSH configuration, and refuses an overridden agent socket or changed key.
It switches the forward and temporary credential copy to WSS and checks local
TLS readiness without sending a bearer. Other launcher modes require a separate
owner operator.
The launcher checks the container profile and identity and retries the SSH
tunnel until the process and TLS endpoint pass readiness. If the verified
container is already running, it compares staged credentials with the
DPAPI-derived expected values inside the container and adopts it without
stopping or restaging it. Changed identity, file permissions, symlinks or a
credential mismatch cause a hold. A stopped container may be started and
staged; an unexpectedly running container cannot be claimed for a stop.
Its monitor retries
a lost SSH process with a bounded readiness attempt and a five-second retry delay.
It checks the new process and TLS endpoint, atomically records the new process
identity, and leaves the already running container in place without restaging.
Unexpected state drift stops the monitor instead of overwriting the state.
Before touching a tunnel, the launcher requires a dedicated `powershell.exe -File`
process and assigns it to a Windows job whose non-inherited handle stays open
until that process exits. Windows then terminates its SSH child even if the
launcher dies before recording the child's identity; a job assignment failure
holds before the tunnel is changed. This also covers the launcher's other child
processes, not unrelated processes or the Docker containers themselves.
Retry requires the launcher process to remain running; task termination,
login and reboot recovery are not established by it.
The Windows curl readiness probe allows an unavailable revocation endpoint
(`--ssl-revoke-best-effort`); the Node agent independently validates the
configured CA and server name, but neither check establishes certificate
revocation status. CA/key custody, renewal and compromise recovery remain
prerequisites. Readiness is not a substitute for authenticated MCP smoke.

`deploy/h15/Dockerfile.brc-agent-pinned-wss` is a recipe, not an image or a
deployment. Its build context must contain only the verified compiled module,
its map, the verified no-auto-pair CLI and its map, and the public CA. The
current original image contains the unmodified CLI, so the WSS transport alone
does not disable automatic pairing if credentials are missing. Both compiled
variants must come from the same reviewed upstream and Hermes CI revision.
The recipe rejects a no-auto-pair CLI or map whose digest differs from the
currently pinned build; the caller must separately verify the transport and CA.
Resolve the supplied local base tag to its approved image ID
before and after the build, prohibit pulls, compare inherited layers/config,
and verify as UID 65534 that the root-owned 0755 trust directory and 0444 CA
and all four compiled files are readable but immutable under the actual
read-only runtime.
An image was built locally from the running original image and the verified
compiled artifacts at Hermes revision `e06253609002e37c79dcd4c08bd4c1b60950bd0b`,
with the real public CA and no device credentials. Its inherited image layers
and runtime configuration matched the original; a disposable, network-isolated
container verified the installed file hashes and refused to pair when credentials
were missing. The original container remained running. This is an image check,
not a deployed candidate or an MCP smoke.

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
operator must configure and verify Docker's `unless-stopped` restart policy.
That policy is insufficient after a prolonged relay outage: a disposable
fixture on the relay host showed the proxy left stopped even after the relay
returned. `h454_wss_relay_reconcile.py` can restart a pinned stopped sidecar
after checking the relay and network identities, static private address,
sidecar profile, read-only mounts, file hashes and process limits. It verifies
the shared namespace and a pinned TLS probe before clearing a flushed pending
marker; an uncertain start retains that marker and prevents another attempt.
Docker may return the same mounts in a different order, so the profile sorts
them by unique destination before hashing while still checking every mount.
At first start Docker also changes the hostname from the sidecar ID to the
relay ID and normalizes the OOM-killer setting; only those exact safe defaults
are treated as equivalent. Unexpected names and disabled OOM killing fail.
The reconciler itself does not install its root-only pin file or a scheduler. The
operator must disable the scheduler before an intentional sidecar stop, and
must investigate a pending marker before resuming. Replacing the relay with a
different container ID requires explicit sidecar reconciliation.

`h454_wss_relay_prepare.py` prepares that pin file and creates one stopped
sidecar from the pinned relay image. It checks the existing authorization
request, TLS identity, private static network, free port and exact code hashes;
all new files use no-overwrite creation. A pending marker blocks activation if
preparation is interrupted or Docker's result is uncertain. Preparation does
not start the sidecar, install the SSH key or schedule reconciliation.

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
`h454_relay_authorization_operator.py` now supplies the server-side part of
that workflow: it records a no-overwrite request, rechecks the relay and
effective sshd policy against its digest before and after installation, and
stores an inode-pinned receipt. An interrupted request-link or installation
before receipt can be reconciled; revocation can also empty the pinned slot
without a receipt. A failure that cannot confirm revocation reports unsettled.
Revoking the slot does not terminate existing SSH sessions or verify other
key sources. The exact source and request still need a verified delivery and
owner-controlled caller; this is not the Windows cutover operator.
The current server's effective configuration lists the second key file and that
filename was absent at inspection. A separate synthetic sshd bound only to the
VPS loopback accepted both restricted fixture keys, denied their opposite ports,
and rejected the second after inode-pinned revocation while the first still
worked. A second loopback fixture exercised the actual install and revoke
functions with synthetic keys and the service UID; old and new authentication,
refusal of the old port for the new key, and new-key revocation passed. Temporary
fixtures were removed and the real second filename remained absent. Neither
fixture installed a real key or tested the production adapter.
The server-side operator's snapshot passed a read-only check against the relay
and the newly prepared public key. A root-only request was prepared and checked
against that snapshot. The restricted key was subsequently installed through
the operator; a separate inode and receipt check confirmed the original key
file remained unchanged. Revocation has not been exercised on this real key.

`h454_relay_tls_identity.py` prepares a separate root-only CA and an RSA-3072
server certificate with a fixed name, no-overwrite atomic publication and
verified private-file permissions. The CA key is not needed by the sidecar;
only the server key and public certificate are intended for a read-only mount.
An unfinished staging directory blocks another creation and is retained for
inspection; it is not silently deleted or treated as a complete identity.
The verifier rejects an unexpected name, key mismatch, unsafe files and a leaf
with less than 30 days remaining. The CA and leaf are issued for 730 and 180
days respectively; renewal and deployment are not automated. Disposable Linux
fixtures exercised the operator, and a synthetic RSA-3072 certificate passed
Windows Schannel with the correct CA and name while a wrong name was rejected.
The real relay identity was prepared separately and its file permissions,
certificate chain, key match and wrong-name refusal were verified there.
Only its public CA certificate was copied to Windows; the private keys remain
on the relay. The private proxy now serves TLS, and a temporary Windows SSH
tunnel passed the pinned-CA probe while a wrong name was refused. The probe
sent no bearer and the temporary tunnel was closed.
[OpenSSH supports selecting an agent identity using its public key](https://man.openbsd.org/ssh_config#IdentityFile),
and [Windows can store a key in its SSH agent](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement),
and a synthetic Windows-to-loopback-sshd test authenticated using a temporary
agent-loaded key with only its public file present. The synthetic agent entry
was removed afterward.

The source-only `h454_windows_wss_identity.ps1` prepares a separate Ed25519
identity under the existing protected Windows state directory. It refuses to
replace an existing backup or public key, protects the private record for the
current Windows user with DPAPI and loads it into the Windows SSH agent through
an anonymous pipe. `Restore` validates the protected record and public key
before loading the same identity again. Its executable and existing launcher
hashes must be independently reviewed and pinned by the caller. An interrupted
or timed-out load requires inspection before retry; it is not proof that the
agent was unchanged. A disposable Windows fixture checked DPAPI recovery,
repeat restore, mismatch refusal and corrupt-backup refusal with a random key,
then removed only that key. A read-only preflight accepted the current task and
protected state directory. A separate real identity was then created there;
its agent entry was removed and restored from the DPAPI backup while other
agent entries were preserved. The real server now authorizes that key only for
the private WSS port. Automatic identity recovery, agent-service restart and
reboot remain unverified.

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
set. Its rollback route check also requires the exact private IPv4 CIDR and
gateway from Docker IPAM, matching member addresses, an upstream outside that
subnet, the original agent on only the isolated network, the proxy on that and
one pinned upstream network, the intended alias, no host override, and a fresh
DNS observation resolving only to the proxy.
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
original container. The secure route has been exercised with a disposable
container, but restoring and restaging the actual original remains unverified.

`h454_isolated_rollback_proxy.mjs` is a source-only experiment for that gap.
It selects one private IPv4 interface using the operator-pinned isolated
network CIDR, rejects ambiguous interfaces and an upstream in that CIDR, and
forwards no agent bytes until a separate TLS connection authenticates the pinned
CA and server name. With two disposable Docker networks, a local restart test
retained the isolated listener and pinned TLS route while the upstream interface
refused the plaintext port. The operator must verify the CIDR against the exact
inspected Docker network and configure the intended restart policy.
Its image recipe places the CA and code in a root-owned, read-only directory.
The proxy cannot itself establish that Docker's network is internal, that its
DNS alias resolves uniquely to this proxy, or that no other container can join
the network. A future owner-gated operator must verify those facts, exact image
and network identities, the old container's existing host overrides, and the
complete process and rollback sequence before staging real credentials. The
isolation may remove normal project egress. The experiment is not an operator
and must not be deployed as a standalone recovery procedure.

`h454_windows_wss_tunnel.ps1` is the canonical SSH-only supervisor. It revalidates
its protected configuration and identity on each attempt, retries after failures,
and places its child processes in an owned Windows job. Its real scheduled task
is now running; the tunnel alone does not restore the device.

`New-H454WssTaskDefinition` constructs the tested periodic task definition
in memory with one-minute repetition, no execution time limit, no overlapping
instances and registration disabled by default. `Register-H454WssTaskDisabled`
also checks the held recovery lock, disabled legacy task, protected snapshots,
canonical marker, exact guard insertion and supervisor preflight before
registering that task disabled. It can adopt an exactly matching disabled task
after interruption, but refuses an unknown or enabled task. It does not create
the marker, install files, enable the task or operate the container; those
remain the operator's responsibility. Synthetic registration tests exercise refusals with a mocked
scheduler. A separate local test registered and removed a uniquely named,
disabled task using the real scheduler. `Start-H454WssTask` separately checks
the exact disabled task and requests its activation under the lock. If a start
fails after activation, it disables and stops only the matching task. A start
request does not prove TLS or MCP readiness.
`h454_windows_wss_config.py` builds the supervisor configuration in memory
only after verifying that the guarded launcher is the exact transformation of
the pinned original and that its relay address is RFC 1918. Synthetic settings
were accepted by the PowerShell validator; settings were also built in memory
from the real launcher and public files without printing addresses or secrets.
`h454_windows_wss_files.ps1` prepares the five fixed supervisor files using
Windows PowerShell. It checks the original-to-guarded launcher relation, the
marker, pinned inputs, node signature, state ACL and stopped container under
the recovery lock. It refuses existing conflicts and reparse points; an
identical partial installation can be resumed. Windows fixtures exercise
preflight, collision, junction, installation and resume without BRC secrets.

`h454_windows_guard_operator.ps1` is a bounded preparation operator for the
already-stopped original. It verifies supplied source and task-backup pins,
the disabled legacy task, the exclusive lock, container identity and closed
listeners before preparing the guarded launcher, its backup and the pending
marker. Its default is a read-only preflight; applying it requires the owner
switch. Its separate WSS preparation mode checks pinned source bytes and can
install the supervisor files and register its task disabled. An explicit
`StartWss` request can then activate that matching task; it does not start or
stop a container, stage credentials or perform MCP. Supplied hashes must be
established independently.
On the real stopped container, the operator installed the guarded launcher,
an original-byte backup and a pending marker. Independent checks confirmed the
three hashes, the disabled old task and closed listeners; the container
remained stopped. Synthetic checks retained the marker and
original-byte backup when a failure was injected before or after atomic
replacement, then resumed under a reacquired lock. The five pinned WSS files
are installed in the real state directory and the new task is running.
Independent checks verified its identity, the file hashes, pinned TLS, refusal
of a wrong TLS name and a closed plaintext listener. The owned SSH process was
terminated while the original was stopped; the same supervisor established a
new pinned connection. Real encrypted credentials were decrypted only in
memory and validated against the expected device and old relay; they were not
sent. The original's raw Docker profile hash differs from the historical pin:
the current `HostConfig.Dns` is an empty array where the pin used `null`. A
read-only comparison matches the historical pin after this single normalization;
synthetic nonempty DNS and privilege changes still fail. Docker Engine 29.9.2
applies a DNS override only for a nonempty list in its
[DNS implementation](https://github.com/moby/moby/blob/docker-v29.9.2/daemon/libnetwork/sandbox_dns_unix.go).
The normalizer is prepared in generated launchers, not installed in the old
launcher. The eventual recovery operator must still verify actual DNS and the
isolated route before sending credentials.

`h454_windows_original_profile.ps1` checks the original identity and reuses
the hasher and profile pin from its separately pinned launcher. It normalizes
only an absent DNS override and, for a separately verified recovery network,
the network name before comparing the remaining profile. The guard operator's
read-only `CheckOriginal` mode passed against the actual stopped original; it
does not create a route, start the container or stage credentials.
That preflight uses `h454_windows_recovery_docker.ps1`, which pins the signed
Docker executable and local engine socket, rejects host overrides and treats a
timeout as ambiguous. A disposable, network-isolated container confirmed exact
stdin bytes using synthetic data; the fixture was removed.

`PrepareRecoveryRoute` can separately prepare the isolated network and pinned
proxy while the original remains stopped. Before each mutation it rechecks
the lock, guarded launcher, original profile and running pinned WSS tunnel. It
checks all Docker container network associations, including stopped containers,
and refuses foreign members. It probes the proxy with a synthetic rejected
bearer and checks that its upstream interface refuses plaintext. A real
disposable fixture prepared and resumed this route, refused both stopped and
running foreign containers, resumed after injected interruptions and an owned
leftover probe, and preserved a foreign probe until the fixture removed it.
The fixture removed its own resources. This mode does not attach or start the
original or stage credentials.
An initial foreign-probe fixture had a variable-name collision and left its
own stopped test container; it was identified by ID, image, command and label
and removed. The corrected fixture completed and cleaned up.

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
- A cross-host synthetic test combined the Windows SSH agent, a public-only
  identity file, an isolated loopback sshd using the second-key primitive,
  and the WSS proxy in a disposable VPS Docker network. A synthetic WebSocket
  upgrade succeeded through pinned TLS; an untrusted CA sent no application
  bytes to the synthetic relay, and revoking the test key refused a new SSH
  login without changing the first fixture key. The temporary agent identity,
  files, containers and network were removed. No real BRC bearer or MCP call
  was used, and the live relay and original container were not changed.
- The image recipe was exercised on the locally prepared no-auto-pair base
  with a synthetic CA. Its inherited layers and runtime configuration matched;
  the non-root process could read but could not overwrite the CA or module.
  The disposable test image was removed.
- A later Docker Desktop fixture built the combined WSS and no-auto-pair image
  from the same immutable image ID as the running original. Its base layers and
  runtime configuration matched except for the fixture label. With synthetic
  credentials and TLS, missing credentials did not start pairing and a denied
  credential remained intact. The same test rejected a disposable image that
  retained the original auto-pair CLI, and a changed CLI failed the recipe's
  digest check. The real container was not restarted and no real credentials
  were staged.
- At the 2026-10-31 inspection, the original container had no Docker `ExtraHosts` entries and no
  `host.docker.internal` entry in its hosts file. A read-only check decrypted
  the existing Windows credential in memory, validated its device identity,
  and matched it against the credential already staged in that same running
  container. No token was printed, no restaging was performed, and neither
  check establishes a working rollback or an MCP connection.
- A disposable container using the original image connected through
  `host.docker.internal` to a temporary Windows loopback listener on port
  38184 and exchanged only a synthetic marker. This verifies local TCP
  reachability, not SSH authentication, TLS or the real relay.
- On 2026-11-02, the actual original Windows container was found stopped with
  `H15_CREDENTIAL_STAGE_TIMEOUT` from its last start; both legacy and WSS
  local ports were unlistened. Its Windows MCP device remained offline. This
  observation is not a rollback or a successful credential restaging.
- A disposable original-image container was attached to an isolated internal
  network and disconnected from the default bridge while stopped. It started
  and restarted with only the isolated network; the fixture removed its own
  container and network. The actual original was not changed by this test.
- A temporary Windows SSH forward and the actual relay TLS sidecar carried a
  deliberately invalid synthetic bearer through a disposable isolated proxy;
  the relay refused it. The proxy's upstream interface refused plaintext and
  the disposable agent had no direct upstream route. The same test later passed
  through the permanent WSS supervisor. This verifies the test route, not real
  credential restaging or a successful MCP call.
- Windows PowerShell 5.1 fixtures exercised exclusive locking, known and
  unknown states, idempotent offline recovery, and termination of an owned
  test process between two real `File.Replace` operations.
- The recovery engine was exercised with the actual offline file-replacement
  primitive and synthetic container callbacks: controls were restored before
  original startup, the marker remained, and repeated recovery skipped staging.
  This does not exercise a production Docker adapter or real credentials.
- A PowerShell 5.1 fixture exercised startup retry before container claim,
  adoption of a matching running container, refusal of staged credential or
  container drift, failed and successful reconnects, an unexpected listener
  identity, a readiness timeout, state-hash drift and startup versus monitor
  cleanup. A disposable Docker container also passed the actual staged
  credential verifier with synthetic data and refused a changed token, unsafe
  file mode and symlink. The fixture also terminated and
  replaced an owned Windows test process; the actual SSH process and
  production relay were not used. The previous private launcher was composed
  with synthetic image, profile and CA pins and passed the same extracted
  fixture; the launcher was not installed or executed.
- A separate Windows PowerShell 5.1 fixture abruptly terminated a synthetic
  launcher after it started a child in the Windows job; the child exited and an
  unrelated sibling survived. A separate local run used the real Windows SSH
  executable with a temporary test forward and observed that both the SSH
  process and its listener exited with the synthetic launcher. No BRC bearer,
  scheduled task or actual container was changed. This does not prove that the
  real scheduled task restarts the launcher or that reboot recovery works.
- On the owner Windows host, a manually started temporary task with a
  restart-on-failure setting did not restart within 125 seconds after its test
  action returned exit code 1. A separate temporary task using a one-minute
  periodic trigger did start the test action again and its owned child exited
  when the task was stopped. Both tasks were removed; neither used the real
  supervisor or tested logon or reboot recovery.
- A temporary copy of the generated supervisor established pinned TLS to the
  real relay using the restricted Windows key. After its owned SSH process was
  terminated, a new owned SSH process restored the pinned connection and a
  wrong TLS name was refused. No BRC credential was sent; the temporary process
  and protected files were removed. This does not test a scheduled installation.
- A combined temporary scheduled test initially failed because the scheduled
  process could not see a separately created protected test directory. With
  no-overwrite temporary files in the existing protected BRC state directory,
  the scheduled supervisor reached the real relay, reconnected after its SSH
  child was terminated, and was started again by the periodic trigger after
  its own process was terminated. A wrong TLS name was refused. The temporary
  task and files were removed; no BRC credential was sent. Login and reboot
  recovery and a permanent installation remain unverified.
- An early registration fixture accidentally created a disabled task when
  Windows auto-import replaced its mock. Its fixture-only action was verified
  and the task was removed. The fixture now preloads the module, verifies its
  mocks and checks for accidental real registration; any leak is a test failure.
- The rollback route guard passed PowerShell 5.1 negative fixtures for extra
  network members, changed identities, host overrides, alias and DNS drift,
  CIDR and gateway mismatch, overlapping upstream addresses and bad prefixes.
  It also accepted fresh Docker Desktop metadata from disposable containers
  and isolated networks with the pinned CIDR; those resources were removed.
  This did not stage credentials or alter the original container.
- A Docker Desktop fixture restarted a disposable relay while a TLS proxy
  shared its network namespace. The proxy detected the lost loopback relay,
  Docker restarted it into the relay's new namespace, and a pinned TLS probe
  passed. The fixture used synthetic certificates, did not call real MCP,
  and removed its containers, network and image. Equivalent CI coverage uses
  isolated disposable containers. A later fixture on the actual relay host
  kept its disposable relay stopped until the watchdog exited; its proxy did
  not automatically recover within 25 seconds after the relay returned. An
  explicit restart then restored synthetic TLS. A separate fixture exercised
  the reconciler through the prolonged outage and refused a pending marker.
  Its CI version stops the disposable sidecar after the watchdog fires, so it
  exercises the stopped case even on Docker versions that keep retrying. The
  live relay remained running and the fixture resources were removed.
- A disposable relay fixture also prepared a stopped sidecar, started it with
  the reconciler and refused a second listener on the same port. Its SSH
  request and TLS manifest were synthetic stubs; it did not authorize a real
  key, use real credentials or prove the Windows cutover.
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
- Taken together, the fixtures do not establish a production update operator,
  original-container recovery, complete process-tree cleanup, login/reboot
  recovery, a real power-loss guarantee or live MCP recovery.
