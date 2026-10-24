# Hermes #454 — preserve registered original-Windows device during one-use rekey

**Status: source-only proposal. NO owner-host rekey is approved or executed by this PR.**

The real Hermes BRC installation has one registered device
`h454-win-01335a1f6e6705b4` named `H15 Windows native read-only`,
platform `win32`, currently offline. Owner VPS read-only SQLite inspection
confirmed `NATIVE_REGISTRATION_COUNT=1` and `NATIVE_DEVICE_ID_MATCH=PASS`.
The previous original-Windows bridge was intentionally single-session with a
memory-only bearer; its process has exited. Reusing its token is not assumed.

## Minimal existing-ID flow

Pinned upstream BRC `cbe511702dd0147650353c29ac6ab1decd8afda1`:

- `POST /device/start` creates a random, short-lived, unapproved code.
- `POST /device/poll` authorizes after owner approval. Its `device_id`
  request parameter **takes precedence** over `device_codes.device_id`.
  The Windows client **MUST omit** `device_id` in its polling request or
  pass **exactly** `h454-win-01335a1f6e6705b4`; a different value could
  insert a second device. It must supply name
  `H15 Windows native read-only` and platform `win32`.
- `store.issueDeviceToken(existingId, ownerId, name, platform)` replaces
  that ONE existing `devices.token_hash` with a freshly generated token and
  privately returns raw bearer only to that waiting Windows process. Before
  the poll succeeds, the old hash remains as-is. This is the intended rekey
  path, **not** deletion, general revocation, or an SQL token update.
- The operator `scripts/h15_brc_owner_native_rekey.py` only approves
  ONE fresh `device_codes` row and assigns its existing exact device ID.
  It does not read or modify a device token or any `devices` row.

## Owner and security gates (NOT EXECUTED)

1. Independently confirm the running relay image, four paired identities
   (three online sandboxes and the exact native ID offline), private SSH
   listener identity and `/health`, and trusted Windows non-admin OS identity
   `hermes-brc-readonly` with all four owner-approved project roots
   effectively read-only. Public `/ws` must stay closed.
2. Receive **new specific owner approval** to launch one bounded Windows
   agent-pair-and-read process and to approve one code against the existing
   device registration on the real Hermes VPS. No automatic re-pairing.
3. On original Windows, run the already source-pinned restricted process
   under `hermes-brc-readonly`: generate a fresh request over the verified
   loopback forward `http://127.0.0.1:38183/device/start`, retain the long
   `device_code` only in that process memory; print the *short* `user_code`
   only to the Windows operator. Poll with the exact device ID (or omit it),
   name and platform as specified above. Never post device_code or bearer to
   GitHub/ChatGPT, process args, PowerShell history, logs or a file.
4. On `vps1777112993`, from the exact tested deployed release in a **real
   interactive root TTY**, invoke
   `python3 -B -m scripts.h15_brc_owner_native_rekey`. It rejects wrong
   host, non-TTY, unsafe SQLite ownership, non-WAL, wrong unique owner,
   different/paused/wrong-platform device, missing/expired/nonfresh request
   and replay. It drops to the relay OS UID/GID before opening SQLite and
   changes exactly one conditional `device_codes` row. Type the fresh
   short code in private and confirm precisely `REKEY H454 <fresh-code>`.
   Requires fresh CI/production source verification before use.
5. Only after the private Windows poll succeeds does upstream BRC mint the
   new credential and supersede the previous hash. The agent then connects
   to `ws://127.0.0.1:38183/ws` **over the verified SSH forward** using
   `--single-session --tunneled-loopback` under the non-admin token.
   Require live exact name, ID, `win32`, exactly native_file_read/stat;
   no generic Windows shell/write tools, no other original paths.
6. Independently perform real ChatGPT and Codex `native_file_stat` and
   `native_file_read` positive/negative probes (including outside-root,
   private vault, path traversal), integrity/size check and agent offline
   behavior. Then explicitly revoke the temporary bearer through an
   independently reviewed owner operation and verify the native device
   remains offline, the three sandbox devices still online, and historical
   Docker rollback checkpoints intact. **Do not claim #454 completed
   before both-client E2E and revocation evidence.**

## Known limits

The upstream `/device/poll` chooses the caller-supplied `device_id`
before the approved database `device_id`. Consequently the Windows
pairing code and its exact parameters must be reviewed and pinned *before*
operator approval. This script alone does not enforce the remote caller's
ID. There is no usable public browser pairing URI; never fake HTTPS Origin,
relax CSRF, expose /ws publicly, copy bearer from SQLite, reuse an unrelated
Windows agent, or run `h15_brc_owner_private_pair.py` (it correctly rejects
an already registered native device).

Offline test:
`python3 -m unittest -v tests.test_h15_brc_owner_native_rekey`.

See [Issue #454](https://github.com/MikeMoore1337/hermes/issues/454).
