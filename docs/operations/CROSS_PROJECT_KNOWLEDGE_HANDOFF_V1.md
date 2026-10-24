# Integration I2: reviewed knowledge handoff without vault access

Status: **offline candidate only**, owner-required review. Issue #557 and roadmap #555.

## What it does

Formats short, deliberately user-reviewed engineering facts from an I1 task packet into a Markdown **draft**. It does not retrieve GitHub, inspect Second Brain, certify privacy, save notes, or send data to an AI model. All facts and cited links must be checked by the owner using their canonical sources.

This is *not* Hermes-to-Second-Brain service integration. Existing local Second Brain GUI already offers the appropriate capture → NoteDraft → review/diff → Safe Write path. Do not build a competing vault writer or make a new external API.

## Run offline

From the Hermes checkout, create a temporary local JSON input **without private data or credentials**:

~~~json
{
  "handoff": {
    "schema_version": 1,
    "task": {"repository": "MikeMoore1337/hermes", "issue": 556},
    "workspace": {"alias": "hermes", "scope": "sandbox", "git_verified": false},
    "toolkit": {"profile": null, "selection": "NOT_VERIFIED"},
    "evidence": {
      "pr": null,
      "tests": {"state": "NOT_RUN", "ref": null},
      "ci": {"state": "NOT_VERIFIED", "ref": null, "sha": null},
      "production": {"state": "NOT_VERIFIED", "ref": null, "sha": null},
      "owner_acceptance": "PENDING"
    }
  },
  "facts": {
    "problem": "При передаче инженерной задачи терялся подтверждённый контекст.",
    "decision": "Применён ограниченный формат передачи задачи без прав исполнения.",
    "rationale": "GitHub остаётся источником фактов о тестах и релизе.",
    "reviewed_on": "2026-10-24"
  }
}
~~~

~~~bash
python3 scripts/prepare_knowledge_handoff.py < input.json
python3 -m unittest tests.test_integration_knowledge_handoff -v
~~~

The CLI outputs a JSON object with Markdown under the markdown key; DRAFT_REVIEW_REQUIRED, canonical_vault_written=false, remote_api_called=false, source_claims_verified=false and privacy_review_complete=false are mandatory. To use the draft, first check Issue/PR/CI against GitHub and edit the explanatory text. Then, **only after conscious human review**, paste the note in the *existing* local Second Brain GUI and follow its own diff/confirmation flow.

The formatter limits input prose fields to short, single-line text and refuses many obvious secrets, paths and Markdown injection. This is **not a guaranteed privacy filter**: do not submit sensitive values or raw logs.

## Constraints

- Input facts are *supplied descriptions*, not verified truth. Evidence links remain merely proposed references.
- No automatic memory mutation, Second Brain service identity, private vault mounting, OAuth, provider call, daemon, scheduler, host permissions or production activation.
- I1 remains the only shared task packet. This formatter does not store a second state machine or index.
- The future external metadata-only Hermes/Second Brain bridge is still **BLOCKED** by Second Brain #386/#400, Hermes #6/#2/#33 and separate personal-data approval. Do not mark live bridging completed because this CLI passes tests.
