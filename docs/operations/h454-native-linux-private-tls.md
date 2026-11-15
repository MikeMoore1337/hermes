# H454 native Linux READ via existing private TLS sidecar (SOURCE ONLY)

## Original-host evidence and destination

On 2026-11-14 the original Hermes VPS root console verified:
`H454_PRIVATE_ROOT_HTTP=404`,
`H454_PRIVATE_NATIVE_STATUS_HTTP=404`,
`H454_PRIVATE_TLS_ORIGINAL_VPS=PASS`,
`H454_BRC_WSS_CHANGED=NO`. These probes used the protected WSS
sidecar pin file, exact private relay IPv4 on port 3001, the pinned
root CA file and certificate hostname `brc-agent.internal`. HTTP 404
is the expected pre-deploy status of the old sidecar, not TLS failure.

The accepted original Hermes VPS disabled native installation remains
`e8887bfb7a04aaff9cbb91a1c46003fcd8d5347a`, inactive and
unpaired. Current BRC/WSS production containers and their rollback
identity snapshots remain unchanged. Neither this source nor PR #896
has been deployed into the existing WSS proxy.

## Trust and host ownership contract

The new `device_fabric.native_private_tls` module implements a single
pinned `wss://brc-agent.internal:3001/ws` session and bounded HTTPS
`GET /device/native-status`, reusing the same BRC owner device bearer
and exact existing one-MCP wire format. The native public pairing
`ws_url` is still required to equal the original relay's canonical
`wss://hermes.mikemoore.top/ws` - the **connection** is explicitly
remapped inside the trusted local adapter, never through an HTTP
redirect, untrusted DNS or system proxy.

The future approved owner-host installer must independently inspect
the original root-only
`/var/lib/hermes-h454-wss-sidecar/pins.json`, original TLS identity
and native release SHA, then write this **new** root-owned, group/world
non-writable, service-readable directory, without exposing a private key:

- `/opt/hermes-commander-native/trust/` - `root:root` mode `0755`
- `ca.crt` - exact SHA256 of the existing pinned **public CA cert**,
  `root:root` mode `0444` or `0644`
- `private-relay.json` - canonical, exactly seven fields below,
  `root:root` mode `0444` or `0644`; bind `release_sha` to the
  *new* reviewed native source release, never the older e888 release

Example **template only**, never guess the actual original owner bridge
IP or the CA SHA256:

```json
{"ca_sha256":"<exact approved hex SHA256>","port":3001,"relay_ipv4":"<exact original host private relay IPv4>","release_sha":"<exact approved new main release SHA>","schema":"h454-private-relay-v1","server_name":"brc-agent.internal","target":"hermes-vps"}
```

The values must be JSON canonical ASCII with sorted keys and no
trailing newline. Symlinks, hardlinks, owner/permission drift, duplicate
keys, unknown fields, public/loopback/foreign IP, incorrect CA digest or
wrong release/target refuse all network calls. The service cannot read
the original private TLS **key**, which is never copied.

## Future systemd unit

Render the unit from the approved future native release only:

```python
render_active_unit(
    manifest, target="hermes-vps",
    release_sha=approved_release_sha,
    manifest_sha256=approved_manifest_sha256,
    relay_ipv4=approved_pinned_private_ipv4,
    dns_ipv4="",
    private_relay=True,
)
```

Expected unit attributes include the existing dedicated
`hermes-commander-native` non-root identity, strict read-only
`ReadOnlyPaths`, zero capabilities, no broad mounts, verified
`NoNewPrivileges=yes` and `RestrictSUIDSGID=no` (required for
`openat2` compatibility), and **exactly one**
`IPAddressAllow=<approved private relay IP>/32` with
`IPAddressDeny=any`. No public Cloudflare IP, DNS stub or other
network destination may appear.

The production CLI calls the private status provider on every READ
request and at startup. Any missing/rotated/revoked native token,
bad TLS CA/SNI, missing trust, wrong OS cgroup identity, or source
hash drift denies the session. Only a pinned `websockets==17.2`
wheel can be used. The adapter constructs its own pre-connected
socket and verifies the private peer before sending a bearer. There
is no fallback to public WSS or public native-status.

## Pending release gate, NOT approved by this source PR

The separate exact-SHA source bundle workflow must produce a **14-file**
read-only native Linux package including
`device_fabric/native_private_tls.py`. The old e888 native package
remains immutable, its two original units and archived rollback bytes
remain untouched. Existing one-time migration operator from e888 must
NOT be used to upgrade itself or be pointed at a changed archive.

Before host installation/start: review the new exact-SHA package,
prepare a new versioned, rollback-safe original-host upgrade for the
trust, code and two systemd units, and independently verify an
`openat2` canary with the fixed unprivileged service identity.
Only a *separate explicit owner approval* may authorize that upgrade,
a joint pinned BRC/WSS sidecar rollout, device pairing or service
start. A source build or CI result is not a host acceptance receipt.

Synthetic tests use disposable CA/key pairs, real TLS sockets and fake
bearers; they do not send credentials or original files to an external
service. Native Hermes/YFC real READ E2E and ChatGPT/Codex original
host acceptance remain NOT_RUN. Hermes #454 remains OPEN.
