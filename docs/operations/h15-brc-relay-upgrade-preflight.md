# H15 #454 - read-only admission for a BRC relay image upgrade

This is an infrastructure preflight, NOT a live deployment tool.

The actual Hermes BRC VPS agent runs inside a nonroot sandbox. It has no
Docker CLI or host Docker socket and must not be given either simply to
perform a relay upgrade.

The owner-side command scripts/h15_brc_upgrade_preflight.py verifies
a sealed offline OCI bundle against independently verified archive SHA256,
OCI image ID and Hermes exact-main commit. It checks the installed candidate
image provenance and the currently running dedicated container:
- owner label, running state and distinct old OCI image;
- exact isolated network and fixed address;
- only the existing persistent /state bind, no host filesystem extension;
- nonroot identity, read-only root filesystem, no privileges or added caps;
- no published ports, bounded memory and process count.

Docker inspect may contain production credentials. This code examines that
JSON internally and never prints environment data, passwords or OAuth tokens.
It fails closed if an invariant differs from the reviewed runtime contract.

Exact-main candidate from Actions run 39674608327:
Hermes commit: 64e940bb5e4a2cd25019a760908d38c3cf4083e0
Image ID: sha256:a6265cc7c73779efbd3782fef892a6ac9cb6aea6583998549904abbf271248a7
Archive SHA256: 878319d6463c0830ed0c23a28635dc7ef9b6f0d58e5a150a09edbeb4c4a6677c

The image must already have been securely downloaded and loaded by an
authorized host operator using existing offline bundle verification gates.
The preflight never downloads, loads, starts, stops, swaps or rolls back
containers. A PASS explicitly reports changes_performed=false and
deployment_approved=false.

Next: add a dedicated operator with backup and rollback, verify host
preflight using exact secure source/manifest; perform an owner-authorized
native Docker-host cutover, then actual ChatGPT and Codex MCP E2E.
No Codex CLI or paid API is needed.
