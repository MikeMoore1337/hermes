# H-15 #349: verified, private Skill Evals evidence index

`eval_lane/evidence_manifest.py` is a **read-only local guard**, not an
upload API, artifact publisher or evidence reviewer. It consumes results
created by the pinned ADT `agent_eval_runner.py` in a dedicated 0700-owned
directory. The operator must provide both the exact approved typed job and
the `observations.json` SHA256 already sealed in Hermes's one-shot receipt.

The verifier fails closed if any of these assertions are false:

- Private directory (0700) owned by the current OS identity; no symlinks
  in the evidence root, report, per-trial directory or referenced artifacts.
- `observations.json` digest matches the sealed receipt, size stays within
  2 MB, context includes the expected provider, model and executed dataset.
- Exactly `2 * trials * number of cases` unique baseline/candidate records,
  with each scenario/trial/variant from the signed, approved job.
- Exact six-file evidence inventory per attempt: `prompt.txt`,
  `source.diff`, `agent.stdout.txt`, `agent.stderr.txt`,
  `oracle.stdout.txt`, `oracle.stderr.txt`.
- Each evidence file exists, is a non-linked regular file with private
  permissions, is at most 2 MB, and its byte-level SHA256 matches the digest
  recorded immediately after the model attempt.
- Fixture SHA is well-formed; no malformed CLI/oracle return value can be
  silently turned into a success.

Output is a **hash-only** in-memory Python dictionary:

- Exact approved job ID, toolkit SHA, provider, model, sealed report digest;
- Per-trial synthetic case ID, trial index, baseline/candidate flag, pinned
  fixture SHA, boolean CLI/oracle exit outcomes and six SHA256 hashes;
- `safe_to_publish=false`, `provider_cost_verified=false` and
  `independent_review=NOT_PERFORMED` by construction.

Raw prompts, diffs, agent stdout/stderr, paths, arbitrary observation fields,
provider credentials, environment variables, API tokens and home-directory
data are **not copied**. This is deliberate: untrusted agent logs can
contain secrets, and a fixed regex list is not sufficient redaction.
Any further evidence transfer must be a **separately reviewed, owner-approved**
step; even this hash-only index should remain private until inspected.

## Offline synthetic test

```bash
python3 -m unittest tests.test_h15_private_evidence_manifest -v
```

Tests inject synthetic secret strings into both raw agent output and
untrusted observation JSON, then assert that nothing secret reaches the
returned hash-only index. They also simulate tampering, symlinks, incomplete
pairs, duplicate attempts and unexpected paths.

No real agent work has been run by this implementation. This module is
*not* connected to the H-15 WSS transport or H-01 service. See
[the dormant executor architecture](../architecture/H-15-SCOPED-SKILL-EVALS-EXECUTOR.md)
and the [offline OS isolation plan](H-15-SKILL-EVALS-OFFLINE-ISOLATION.md).

The independent human reviewer still needs to inspect the **private original**
evidence and attest to correctness, actual skill activation, regressions and
unsafe actions. This hash-only index is insufficient to score ADT #11.
